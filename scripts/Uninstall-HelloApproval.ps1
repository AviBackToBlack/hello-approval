#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$RemoveRuntime,
    [switch]$RemoveLauncherCache
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'hello-approval Git Signing Agent'
$TaskPath = '\'
$TaskMarker = 'hello-approval/ha-1.3/v1'
$SigningSchema = 'hello-approval/ha-1.4/v1'
$VerificationSchema = 'hello-approval/ha-1.5/v1'
$TrustMarker = "# $VerificationSchema"

function Test-WindowsPathEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $leftNormalized = $Left -replace '\\','/'
    $rightNormalized = $Right -replace '\\','/'
    return [string]::Equals($leftNormalized, $rightNormalized, [StringComparison]::OrdinalIgnoreCase)
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Assert-RealDirectory {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Purpose)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Purpose is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Purpose must be a real non-reparse directory: $Path"
    }
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Purpose)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Purpose is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Purpose must be a real non-reparse file: $Path"
    }
    return [IO.Path]::GetFullPath($Path)
}

function Invoke-Git {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowNonZero
    )

    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Git @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }

    if ($rc -eq 0 -or $AllowNonZero) {
        return [pscustomobject]@{ ExitCode = $rc; Output = $output }
    }

    $detail = if ($output.Count -gt 0) { ' ' + ($output -join ' | ') } else { '' }
    throw "$Context failed with exit $rc.$detail"
}

function Get-GitDirectValues {
    param([Parameter(Mandatory = $true)][string]$Git, [Parameter(Mandatory = $true)][string]$Key)

    $result = Invoke-Git -Git $Git -Arguments @('config','--global','--get-all',$Key) -Context "Read direct global $Key" -AllowNonZero
    if ($result.ExitCode -eq 1) { return @() }
    if ($result.ExitCode -ne 0) { throw "Read direct global $Key failed with exit $($result.ExitCode)." }
    return @($result.Output)
}

function Get-GitFileOne {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $result = Invoke-Git -Git $Git -Arguments @('config','--file',$File,'--get-all',$Key) -Context "Read $Key from $File" -AllowNonZero
    if ($result.ExitCode -eq 1) { return @() }
    if ($result.ExitCode -ne 0) { throw "Read $Key from $File failed with exit $($result.ExitCode)." }
    return @($result.Output)
}

function Get-GlobalWritePath {
    param([Parameter(Mandatory = $true)][string]$Git)

    $result = Invoke-Git -Git $Git -Arguments @('var','GIT_CONFIG_GLOBAL') -Context 'Resolve Git global configuration candidates'
    $candidates = @($result.Output | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
    if ($candidates.Count -lt 1) { throw 'Git did not report a global configuration path.' }
    return [IO.Path]::GetFullPath(($candidates[$candidates.Count - 1] -replace '/', '\'))
}

function Get-FileSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Path = $Path; Existed = $false; Bytes = $null; Attributes = $null }
    }

    $item = Get-Item -LiteralPath $Path -Force
    return [pscustomobject]@{
        Path = $Path
        Existed = $true
        Bytes = [IO.File]::ReadAllBytes($Path)
        Attributes = $item.Attributes
    }
}

function Restore-FileSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)

    if ($Snapshot.Existed) {
        $parent = Split-Path -Parent $Snapshot.Path
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            [void][IO.Directory]::CreateDirectory($parent)
        }
        if (Test-Path -LiteralPath $Snapshot.Path) {
            try { [IO.File]::SetAttributes($Snapshot.Path, [IO.FileAttributes]::Normal) } catch {}
        }
        [IO.File]::WriteAllBytes($Snapshot.Path, [byte[]]$Snapshot.Bytes)
        [IO.File]::SetAttributes($Snapshot.Path, [IO.FileAttributes]$Snapshot.Attributes)
    } elseif (Test-Path -LiteralPath $Snapshot.Path) {
        try { [IO.File]::SetAttributes($Snapshot.Path, [IO.FileAttributes]::Normal) } catch {}
        Remove-Item -LiteralPath $Snapshot.Path -Force
    }
}

function Assert-OwnedGitFile {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSchema,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = Assert-RegularFile -Path $Path -Purpose $Purpose
    $schema = @(Get-GitFileOne -Git $Git -File $resolved -Key 'hello-approval.schema')
    if ($schema.Count -ne 1 -or $schema[0] -cne $ExpectedSchema) {
        throw "Refusing to remove unowned $Purpose; schema is '$($schema -join '; ')': $resolved"
    }
}

function Assert-OwnedTrustFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = Assert-RegularFile -Path $Path -Purpose 'hello-approval allowed_signers'
    $lines = @(Get-Content -LiteralPath $resolved)
    if ($lines.Count -lt 1 -or $lines[0] -cne $TrustMarker) {
        throw "Refusing to remove unowned allowed_signers file: $resolved"
    }
}

function Assert-PinnedRuntimeSurface {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][object]$Pin
    )

    Assert-RealDirectory -Path $RuntimeRoot -Purpose 'Pinned runtime root'
    $rootItems = @(Get-ChildItem -LiteralPath $RuntimeRoot -Force)
    if ($rootItems.Count -ne 1 -or $rootItems[0].Name -cne 'bin' -or -not $rootItems[0].PSIsContainer -or ($rootItems[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing runtime removal: pinned runtime root surface is not exact: $RuntimeRoot"
    }

    $bin = Join-Path $RuntimeRoot 'bin'
    $required = @($Pin.installation_policy.installed_files)
    $items = @(Get-ChildItem -LiteralPath $bin -Force)
    $names = @($items | ForEach-Object { $_.Name })
    if ($names.Count -ne $required.Count) {
        throw "Refusing runtime removal: runtime bin file count does not match pin: $bin"
    }

    foreach ($name in $required) {
        if (-not ($names -ccontains $name)) {
            throw "Refusing runtime removal: required file '$name' is missing: $bin"
        }
        $pinFile = $Pin.files | Where-Object { $_.name -ceq $name -and $_.policy.disposition -eq 'required' } | Select-Object -First 1
        if ($null -eq $pinFile) { throw "Refusing runtime removal: no required provenance record for $name." }

        $path = Assert-RegularFile -Path (Join-Path $bin $name) -Purpose "Pinned $name"
        $item = Get-Item -LiteralPath $path -Force
        $hash = Get-FileSha256 -Path $path
        if ($item.Length -ne [int64]$pinFile.size_bytes -or $hash -cne ([string]$pinFile.sha256).ToLowerInvariant()) {
            throw "Refusing runtime removal: pinned runtime file differs from provenance: $path"
        }
    }
}

function Assert-LauncherCacheSurface {
    param([Parameter(Mandatory = $true)][string]$LauncherRoot)

    if (-not (Test-Path -LiteralPath $LauncherRoot)) { return }
    Assert-RealDirectory -Path $LauncherRoot -Purpose 'hello-approval launcher cache'

    foreach ($entry in @(Get-ChildItem -LiteralPath $LauncherRoot -Force)) {
        if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $entry.Name -notmatch '\A[a-f0-9]{64}\z') {
            throw "Refusing launcher-cache removal: unexpected cache entry: $($entry.FullName)"
        }

        $children = @(Get-ChildItem -LiteralPath $entry.FullName -Force)
        if ($children.Count -ne 1 -or $children[0].PSIsContainer -or $children[0].Name -cne 'Start-HelloApprovalAgent.ps1' -or ($children[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refusing launcher-cache removal: digest directory surface is not exact: $($entry.FullName)"
        }

        $hash = Get-FileSha256 -Path $children[0].FullName
        if ($hash -cne $entry.Name) {
            throw "Refusing launcher-cache removal: launcher bytes do not match digest directory: $($entry.FullName)"
        }
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'Uninstall-HelloApproval.ps1 supports Windows only.' }
foreach ($required in @('LOCALAPPDATA','USERPROFILE','SystemRoot')) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($required, 'Process'))) {
        throw "Required environment path is unavailable: $required"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = Join-Path $env:LOCALAPPDATA 'hello-approval'
$gitRoot = Join-Path $projectRoot 'git'
$signingConfig = Join-Path $gitRoot 'signing.gitconfig'
$verificationConfig = Join-Path $gitRoot 'verification.gitconfig'
$trustFile = Join-Path $gitRoot 'allowed_signers'
$launcherRoot = Join-Path $projectRoot 'app\launcher'

$pinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'
$pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
if ($pin.schema -ne 'hello-approval/upstream-pin/v1') { throw "Unsupported provenance pin schema: $($pin.schema)" }
$releaseTag = [string]$pin.upstream.release_tag
$runtimeRoot = Join-Path $projectRoot ("runtime\sshenc\{0}" -f $releaseTag)

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'Git executable is required for conservative Git cleanup.' }
$git = $gitCommand.Source

$signingConfigGit = $signingConfig -replace '\\','/'
$verificationConfigGit = $verificationConfig -replace '\\','/'

# Ownership/shape validation happens before any mutation.
Assert-OwnedGitFile -Git $git -Path $signingConfig -ExpectedSchema $SigningSchema -Purpose 'hello-approval signing Git fragment'
Assert-OwnedGitFile -Git $git -Path $verificationConfig -ExpectedSchema $VerificationSchema -Purpose 'hello-approval verification Git fragment'
Assert-OwnedTrustFile -Path $trustFile

$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
$taskXmlText = $null
$taskWasRunning = $false
if ($null -ne $task) {
    $taskXml = [xml](Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath)
    $taskXmlText = $taskXml.OuterXml
    $taskWasRunning = $task.State -eq 'Running'
    $ns = New-Object Xml.XmlNamespaceManager($taskXml.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $descriptionNode = $taskXml.SelectSingleNode('/t:Task/t:RegistrationInfo/t:Description', $ns)
    $description = if ($null -eq $descriptionNode) { $null } else { [string]$descriptionNode.InnerText }
    if ($description -ne $TaskMarker) {
        throw "Refusing full cleanup because same-name Scheduled Task is foreign; ownership marker is '$description'."
    }
}

if ($RemoveRuntime -and (Test-Path -LiteralPath $runtimeRoot)) {
    Assert-PinnedRuntimeSurface -RuntimeRoot $runtimeRoot -Pin $pin
}
if ($RemoveLauncherCache -and (Test-Path -LiteralPath $launcherRoot)) {
    Assert-LauncherCacheSurface -LauncherRoot $launcherRoot
}

$globalWritePath = Get-GlobalWritePath -Git $git
$globalSnapshot = Get-FileSnapshot -Path $globalWritePath
$signingSnapshot = Get-FileSnapshot -Path $signingConfig
$verificationSnapshot = Get-FileSnapshot -Path $verificationConfig
$trustSnapshot = Get-FileSnapshot -Path $trustFile

$directIncludes = @(Get-GitDirectValues -Git $git -Key 'include.path')
$ownedIncludeValues = @($directIncludes | Where-Object {
    (Test-WindowsPathEqual -Left ([string]$_) -Right $signingConfigGit) -or
    (Test-WindowsPathEqual -Left ([string]$_) -Right $verificationConfigGit)
})

$gitMutationStarted = $false
$taskRemoved = $false
$runtimeQuarantine = $null
$launcherQuarantine = $null
try {
    if ($PSCmdlet.ShouldProcess("$TaskPath$TaskName", 'Stop and remove owned hello-approval Scheduled Task')) {
        if ($null -ne $task) {
            & (Join-Path $PSScriptRoot 'Uninstall-HelloApprovalScheduledTask.ps1') -Confirm:$false
            $taskRemoved = $true
        } else {
            Write-Host 'Owned Scheduled Task is already absent.'
        }
    }

    if ($PSCmdlet.ShouldProcess($globalWritePath, 'Remove hello-approval Git includes and owned Git/trust files')) {
        $gitMutationStarted = $true

        foreach ($includeValue in $ownedIncludeValues) {
            $removeResult = Invoke-Git -Git $git -Arguments @('config','--global','--fixed-value','--unset-all','include.path',[string]$includeValue) -Context "Remove owned include.path $includeValue" -AllowNonZero
            if ($removeResult.ExitCode -ne 0 -and $removeResult.ExitCode -ne 5) {
                throw "Could not remove owned include.path '$includeValue'; git exit=$($removeResult.ExitCode)."
            }
        }

        $remainingIncludes = @(Get-GitDirectValues -Git $git -Key 'include.path')
        $remainingOwned = @($remainingIncludes | Where-Object {
            (Test-WindowsPathEqual -Left ([string]$_) -Right $signingConfigGit) -or
            (Test-WindowsPathEqual -Left ([string]$_) -Right $verificationConfigGit)
        })
        if ($remainingOwned.Count -ne 0) {
            throw "Owned hello-approval include.path entries remain after cleanup: $($remainingOwned -join '; ')"
        }

        foreach ($path in @($signingConfig,$verificationConfig,$trustFile)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force
            }
        }

        if (Test-Path -LiteralPath $gitRoot -PathType Container) {
            $remaining = @(Get-ChildItem -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) {
                Remove-Item -LiteralPath $gitRoot -Force
            }
        }

        Write-Host 'Owned Git signing/verification includes and project trust files removed.'
    }

    if ($RemoveRuntime -and $PSCmdlet.ShouldProcess($runtimeRoot, 'Remove exact pinned hello-approval runtime')) {
        if (Test-Path -LiteralPath $runtimeRoot) {
            $runtimeParent = Split-Path -Parent $runtimeRoot
            $runtimeQuarantine = Join-Path $runtimeParent ('.{0}.removing.{1}' -f (Split-Path -Leaf $runtimeRoot), [Guid]::NewGuid().ToString('N'))
            [IO.Directory]::Move($runtimeRoot, $runtimeQuarantine)
            Write-Host "Exact pinned runtime staged for removal: $runtimeRoot"
        } else {
            Write-Host 'Pinned runtime is already absent.'
        }
    }

    if ($RemoveLauncherCache -and $PSCmdlet.ShouldProcess($launcherRoot, 'Remove verified hello-approval content-addressed launcher cache')) {
        if (Test-Path -LiteralPath $launcherRoot) {
            $appRoot = Split-Path -Parent $launcherRoot
            $launcherQuarantine = Join-Path $appRoot ('.launcher.removing.{0}' -f [Guid]::NewGuid().ToString('N'))
            [IO.Directory]::Move($launcherRoot, $launcherQuarantine)
            Write-Host "Verified launcher cache staged for removal: $launcherRoot"
        } else {
            Write-Host 'Launcher cache is already absent.'
        }
    }
} catch {
    $original = $_
    if ($gitMutationStarted) {
        try { Restore-FileSnapshot -Snapshot $globalSnapshot } catch { Write-Warning "Failed to restore global Git config snapshot: $($_.Exception.Message)" }
        try { Restore-FileSnapshot -Snapshot $signingSnapshot } catch { Write-Warning "Failed to restore signing fragment snapshot: $($_.Exception.Message)" }
        try { Restore-FileSnapshot -Snapshot $verificationSnapshot } catch { Write-Warning "Failed to restore verification fragment snapshot: $($_.Exception.Message)" }
        try { Restore-FileSnapshot -Snapshot $trustSnapshot } catch { Write-Warning "Failed to restore allowed_signers snapshot: $($_.Exception.Message)" }
    }
    if ($null -ne $runtimeQuarantine -and (Test-Path -LiteralPath $runtimeQuarantine) -and -not (Test-Path -LiteralPath $runtimeRoot)) {
        try { [IO.Directory]::Move($runtimeQuarantine, $runtimeRoot) } catch { Write-Warning "Failed to restore runtime quarantine after cleanup failure: $($_.Exception.Message)" }
    }
    if ($null -ne $launcherQuarantine -and (Test-Path -LiteralPath $launcherQuarantine) -and -not (Test-Path -LiteralPath $launcherRoot)) {
        try { [IO.Directory]::Move($launcherQuarantine, $launcherRoot) } catch { Write-Warning "Failed to restore launcher-cache quarantine after cleanup failure: $($_.Exception.Message)" }
    }
    if ($taskRemoved -and $null -ne $taskXmlText) {
        try {
            Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $taskXmlText -Force | Out-Null
            if ($taskWasRunning) {
                Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
            }
        } catch {
            Write-Warning "Failed to restore Scheduled Task snapshot after cleanup failure: $($_.Exception.Message)"
        }
    }
    throw $original
}

# Destructive directory bytes are deleted only after all rollback-capable steps
# have succeeded. A failure to reclaim quarantine storage is reported as a
# warning; the active integration path is already removed as requested.
foreach ($quarantine in @($runtimeQuarantine, $launcherQuarantine)) {
    if ($null -ne $quarantine -and (Test-Path -LiteralPath $quarantine)) {
        try {
            Remove-Item -LiteralPath $quarantine -Recurse -Force
        } catch {
            Write-Warning "Cleanup completed but quarantine storage could not be fully removed: $quarantine | $($_.Exception.Message)"
        }
    }
}
if ($RemoveRuntime) {
    $runtimeParent = Split-Path -Parent $runtimeRoot
    if (Test-Path -LiteralPath $runtimeParent -PathType Container) {
        $remaining = @(Get-ChildItem -LiteralPath $runtimeParent -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $runtimeParent -Force -ErrorAction SilentlyContinue }
    }
}
if ($RemoveLauncherCache) {
    $appRoot = Split-Path -Parent $launcherRoot
    if (Test-Path -LiteralPath $appRoot -PathType Container) {
        $remaining = @(Get-ChildItem -LiteralPath $appRoot -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $appRoot -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host ''
Write-Host 'Conservative cleanup boundary:' -ForegroundColor Cyan
Write-Host '- sshenc config: PRESERVED'
Write-Host '- canonical public key: PRESERVED'
Write-Host '- hardware-backed/platform credential: PRESERVED; destructive credential deletion is manual/confirmation-gated'
Write-Host '- GitHub Signing Key registration: PRESERVED; account-key removal is manual'
Write-Host '- user SSH config and unrelated environment/Git settings: PRESERVED'
Write-Host '- stock Windows ssh-agent service: PRESERVED'
Write-Host '- logs/state outside selected cleanup switches: PRESERVED'
if (-not $RemoveRuntime) { Write-Host '- pinned runtime: PRESERVED (use -RemoveRuntime explicitly after ownership validation)' }
if (-not $RemoveLauncherCache) { Write-Host '- content-addressed launcher cache: PRESERVED (use -RemoveLauncherCache explicitly after ownership validation)' }
