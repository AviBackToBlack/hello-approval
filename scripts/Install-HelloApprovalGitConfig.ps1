#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$EnableCommitSigning,
    [switch]$EnableTagSigning,
    [switch]$OverrideExistingSigningConfig
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Schema = 'hello-approval/ha-1.4/v1'
$PublicKeyLeaf = 'github-signing.pub'
$ExpectedKeyType = 'sk-ecdsa-sha2-nistp256@openssh.com'
$OwnedKeys = @('gpg.format', 'gpg.ssh.program', 'user.signingkey')

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Assert-RegularFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Purpose)
    if (-not [IO.Path]::IsPathRooted($Path)) { throw "$Purpose path must be absolute: $Path" }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$Purpose is missing: $full" }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Purpose must be a real non-reparse file: $full"
    }
    return $full
}

function Assert-RealDirectory {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Purpose)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "$Purpose is missing: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Purpose must be a real non-reparse directory: $Path"
    }
}

function Ensure-RealDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Assert-RealDirectory -Path $Path -Purpose 'hello-approval Git configuration directory'
        return
    }
    [void][IO.Directory]::CreateDirectory($Path)
    Assert-RealDirectory -Path $Path -Purpose 'hello-approval Git configuration directory'
}

function Assert-PinnedRuntimeSurface {
    param([Parameter(Mandatory = $true)][string]$RuntimeRoot, [Parameter(Mandatory = $true)][object]$Pin)
    Assert-RealDirectory -Path $RuntimeRoot -Purpose 'Pinned runtime root'
    $rootItems = @(Get-ChildItem -LiteralPath $RuntimeRoot -Force)
    if ($rootItems.Count -ne 1 -or $rootItems[0].Name -cne 'bin' -or -not $rootItems[0].PSIsContainer -or ($rootItems[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Pinned runtime root surface must contain exactly one real bin directory: $RuntimeRoot"
    }
    $bin = Join-Path $RuntimeRoot 'bin'
    $required = @($Pin.installation_policy.installed_files)
    $items = @(Get-ChildItem -LiteralPath $bin -Force)
    $names = @($items | ForEach-Object { $_.Name })
    if ($names.Count -ne $required.Count) { throw "Pinned runtime bin surface differs from installed_files: $bin" }
    foreach ($name in $required) {
        if (-not ($names -ccontains $name)) { throw "Pinned runtime bin surface is missing exact file '$name': $bin" }
        $pinFile = $Pin.files | Where-Object { $_.name -ceq $name -and $_.policy.disposition -eq 'required' } | Select-Object -First 1
        if ($null -eq $pinFile) { throw "Required runtime file '$name' has no required provenance record." }
        $path = Assert-RegularFile -Path (Join-Path $bin $name) -Purpose "Pinned $name"
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Length -ne [int64]$pinFile.size_bytes -or (Get-FileSha256 -Path $path) -ne ([string]$pinFile.sha256).ToLowerInvariant()) {
            throw "Pinned runtime file does not match provenance: $path"
        }
    }
}

function Get-GitValues {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][ValidateSet('global','system','file')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Key,
        [string]$File
    )
    if ($Scope -eq 'file') { $output = @(& $Git config --file $File --get-all $Key 2>$null) }
    elseif ($Scope -eq 'global') { $output = @(& $Git config --global --includes --get-all $Key 2>$null) }
    else { $output = @(& $Git config --system --get-all $Key 2>$null) }
    $rc = $LASTEXITCODE
    if ($rc -eq 1) { return @() }
    if ($rc -ne 0) { throw "git config --$Scope --get-all $Key failed with exit $rc." }
    return @($output | ForEach-Object { [string]$_ })
}

function Get-DirectGlobalValues {
    param([Parameter(Mandatory = $true)][string]$Git, [Parameter(Mandatory = $true)][string]$Key)
    $output = @(& $Git config --global --get-all $Key 2>$null)
    $rc = $LASTEXITCODE
    if ($rc -eq 1) { return @() }
    if ($rc -ne 0) { throw "git config --global --get-all $Key failed with exit $rc." }
    return @($output | ForEach-Object { [string]$_ })
}

function Set-ConfigValue {
    param([string]$Git, [string]$File, [string]$Key, [string]$Value)
    & $Git config --file $File --replace-all $Key $Value
    if ($LASTEXITCODE -ne 0) { throw "Failed to write $Key to staged hello-approval Git config." }
}

function Get-GlobalWritePath {
    param([string]$Git)
    $paths = @(& $Git var GIT_CONFIG_GLOBAL 2>$null | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
    if ($LASTEXITCODE -ne 0 -or $paths.Count -lt 1) { throw 'Git did not report a global configuration path.' }
    $path = $paths[$paths.Count - 1] -replace '/', '\'
    if (-not [IO.Path]::IsPathRooted($path)) { throw "Git global write path is not absolute: $path" }
    return [IO.Path]::GetFullPath($path)
}

function Restore-FileSnapshot {
    param([string]$Path, [bool]$Existed, [byte[]]$Bytes)
    if ($Existed) {
        $parent = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { [void][IO.Directory]::CreateDirectory($parent) }
        [IO.File]::WriteAllBytes($Path, $Bytes)
    } elseif (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'Install-HelloApprovalGitConfig.ps1 supports Windows only.' }
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is not available.' }
if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) { throw 'USERPROFILE is not available.' }

$gitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'Git was not found in PATH.' }
$git = $gitCommand.Source
& $git --version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Git executable failed its version probe.' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$pin = Get-Content -LiteralPath (Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json') -Raw | ConvertFrom-Json
if ($pin.schema -ne 'hello-approval/upstream-pin/v1') { throw "Unsupported provenance pin schema: $($pin.schema)" }
if ($pin.installation_policy.allowed_distribution -ne 'zip-manual-placement') { throw 'Pinned distribution policy is not zip-manual-placement.' }
$requiredByPolicy = @($pin.files | Where-Object { $_.policy.disposition -eq 'required' } | ForEach-Object { $_.name } | Sort-Object)
$installedByPolicy = @($pin.installation_policy.installed_files | Sort-Object)
if (@(Compare-Object -ReferenceObject $requiredByPolicy -DifferenceObject $installedByPolicy -CaseSensitive).Count -ne 0) {
    throw 'Pin inconsistency: installed_files must exactly match files with policy.disposition=required.'
}

$runtimeRoot = Join-Path $env:LOCALAPPDATA ("hello-approval\runtime\sshenc\{0}" -f [string]$pin.upstream.release_tag)
Assert-PinnedRuntimeSurface -RuntimeRoot $runtimeRoot -Pin $pin
$sshencPath = [IO.Path]::GetFullPath((Join-Path $runtimeRoot 'bin\sshenc.exe'))
$publicKeyPath = Assert-RegularFile -Path (Join-Path $env:USERPROFILE ".ssh\$PublicKeyLeaf") -Purpose 'Git signing public key'
$keyLines = @(Get-Content -LiteralPath $publicKeyPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($keyLines.Count -ne 1) { throw "Signing public key must contain exactly one non-empty line: $publicKeyPath" }
$keyParts = @($keyLines[0] -split '\s+')
if ($keyParts.Count -lt 2 -or $keyParts[0] -cne $ExpectedKeyType) {
    throw "Signing public key must be an $ExpectedKeyType key: $publicKeyPath"
}

$projectRoot = Join-Path $env:LOCALAPPDATA 'hello-approval'
Assert-RealDirectory -Path $projectRoot -Purpose 'hello-approval project root'
$gitRoot = Join-Path $projectRoot 'git'
if (Test-Path -LiteralPath $gitRoot) { Assert-RealDirectory -Path $gitRoot -Purpose 'hello-approval Git configuration directory' }
$ownedConfig = Join-Path $gitRoot 'signing.gitconfig'
$ownedConfigGit = $ownedConfig -replace '\\', '/'
$globalWritePath = Get-GlobalWritePath -Git $git

$existingOwned = Test-Path -LiteralPath $ownedConfig -PathType Leaf
$preserveCommitSigning = $false
$preserveTagSigning = $false
if ($existingOwned) {
    $ownedConfig = Assert-RegularFile -Path $ownedConfig -Purpose 'hello-approval owned Git config'
    $schemaValues = Get-GitValues -Git $git -Scope file -File $ownedConfig -Key 'hello-approval.schema'
    if ($schemaValues.Count -ne 1 -or $schemaValues[0] -ne $Schema) {
        throw "Refusing to replace unowned Git config fragment: $ownedConfig"
    }
    $commitValues = Get-GitValues -Git $git -Scope file -File $ownedConfig -Key 'commit.gpgsign'
    $tagValues = Get-GitValues -Git $git -Scope file -File $ownedConfig -Key 'tag.gpgsign'
    if ($commitValues.Count -gt 1 -or ($commitValues.Count -eq 1 -and $commitValues[0] -ne 'true')) { throw 'Owned fragment has unexpected commit.gpgSign state.' }
    if ($tagValues.Count -gt 1 -or ($tagValues.Count -eq 1 -and $tagValues[0] -ne 'true')) { throw 'Owned fragment has unexpected tag.gpgSign state.' }
    $preserveCommitSigning = $commitValues.Count -eq 1
    $preserveTagSigning = $tagValues.Count -eq 1
} elseif (Test-Path -LiteralPath $ownedConfig) {
    throw "Owned Git config path exists but is not a regular file: $ownedConfig"
}

$desired = @{
    'gpg.format' = 'ssh'
    'gpg.ssh.program' = ($sshencPath -replace '\\', '/')
    'user.signingkey' = ($publicKeyPath -replace '\\', '/')
}
foreach ($key in $OwnedKeys) {
    $values = Get-GitValues -Git $git -Scope global -Key $key
    $conflicts = @($values | Where-Object { $_ -ne $desired[$key] })
    if ($conflicts.Count -gt 0 -and -not $OverrideExistingSigningConfig) {
        throw "Existing global Git setting '$key' conflicts with hello-approval. Re-run with -OverrideExistingSigningConfig to preserve it but give the hello-approval include later precedence. Existing values: $($values -join '; ')"
    }
}

$directIncludes = Get-DirectGlobalValues -Git $git -Key 'include.path'
$ourIncludeCount = @($directIncludes | Where-Object { ($_ -replace '\\','/') -eq $ownedConfigGit }).Count
if ($ourIncludeCount -gt 1) { throw "Global Git config contains duplicate hello-approval include.path entries: $ownedConfigGit" }

if (-not $PSCmdlet.ShouldProcess($ownedConfig, 'Install/update hello-approval Git signing config and global include')) { return }

Ensure-RealDirectory -Path $gitRoot
$stage = Join-Path $gitRoot ('.signing.gitconfig.staging.{0}' -f [Guid]::NewGuid().ToString('N'))
$ownedExisted = Test-Path -LiteralPath $ownedConfig
$ownedBytes = if ($ownedExisted) { [IO.File]::ReadAllBytes($ownedConfig) } else { $null }
$globalExisted = Test-Path -LiteralPath $globalWritePath
$globalBytes = if ($globalExisted) { [IO.File]::ReadAllBytes($globalWritePath) } else { $null }

try {
    Set-ConfigValue -Git $git -File $stage -Key 'hello-approval.schema' -Value $Schema
    Set-ConfigValue -Git $git -File $stage -Key 'gpg.format' -Value $desired['gpg.format']
    Set-ConfigValue -Git $git -File $stage -Key 'gpg.ssh.program' -Value $desired['gpg.ssh.program']
    Set-ConfigValue -Git $git -File $stage -Key 'user.signingkey' -Value $desired['user.signingkey']
    if ($EnableCommitSigning -or $preserveCommitSigning) { Set-ConfigValue -Git $git -File $stage -Key 'commit.gpgsign' -Value 'true' }
    if ($EnableTagSigning -or $preserveTagSigning) { Set-ConfigValue -Git $git -File $stage -Key 'tag.gpgsign' -Value 'true' }

    foreach ($key in @('hello-approval.schema') + $OwnedKeys) {
        $expected = if ($key -eq 'hello-approval.schema') { $Schema } else { $desired[$key] }
        $values = Get-GitValues -Git $git -Scope file -File $stage -Key $key
        if ($values.Count -ne 1 -or $values[0] -ne $expected) { throw "Staged Git config failed verification for $key." }
    }

    if ($ownedExisted) {
        $backup = Join-Path $gitRoot ('.signing.gitconfig.backup.{0}' -f [Guid]::NewGuid().ToString('N'))
        [IO.File]::Replace($stage, $ownedConfig, $backup, $true)
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    } else {
        [IO.File]::Move($stage, $ownedConfig)
    }

    if ($ourIncludeCount -eq 0) {
        & $git config --global --add include.path $ownedConfigGit
        if ($LASTEXITCODE -ne 0) { throw 'Failed to register hello-approval include.path in global Git config.' }
    }

    $postIncludes = Get-DirectGlobalValues -Git $git -Key 'include.path'
    if (@($postIncludes | Where-Object { ($_ -replace '\\','/') -eq $ownedConfigGit }).Count -ne 1) {
        throw 'Global Git config does not contain exactly one hello-approval include.path after installation.'
    }
    foreach ($key in $OwnedKeys) {
        $winner = @(& $git config --global --includes --get $key 2>$null)
        if ($LASTEXITCODE -ne 0 -or $winner.Count -ne 1 -or [string]$winner[0] -ne $desired[$key]) {
            throw "Effective global Git value for '$key' is not the hello-approval value after installation. A later global include may be overriding it."
        }
    }

    $effectiveCommit = @(& $git config --global --includes --get commit.gpgsign 2>$null)
    $commitRc = $LASTEXITCODE
    $effectiveTag = @(& $git config --global --includes --get tag.gpgsign 2>$null)
    $tagRc = $LASTEXITCODE
    if (($EnableCommitSigning -or $preserveCommitSigning) -and ($commitRc -ne 0 -or $effectiveCommit.Count -ne 1 -or $effectiveCommit[0] -ne 'true')) {
        throw 'Explicit/preserved commit signing enablement did not become effective.'
    }
    if (($EnableTagSigning -or $preserveTagSigning) -and ($tagRc -ne 0 -or $effectiveTag.Count -ne 1 -or $effectiveTag[0] -ne 'true')) {
        throw 'Explicit/preserved tag signing enablement did not become effective.'
    }

    Write-Host "HA-1.4 Git signing configuration is installed and verified."
    Write-Host "Owned config: $ownedConfig"
    Write-Host "Global include: $ownedConfigGit"
    Write-Host "Commit signing enabled by hello-approval: $($EnableCommitSigning -or $preserveCommitSigning)"
    Write-Host "Tag signing enabled by hello-approval: $($EnableTagSigning -or $preserveTagSigning)"
    Write-Host 'Author identity was not modified.'
} catch {
    $original = $_
    try { Restore-FileSnapshot -Path $globalWritePath -Existed $globalExisted -Bytes $globalBytes } catch { Write-Warning "Failed to restore global Git config snapshot: $($_.Exception.Message)" }
    try { Restore-FileSnapshot -Path $ownedConfig -Existed $ownedExisted -Bytes $ownedBytes } catch { Write-Warning "Failed to restore hello-approval Git config fragment: $($_.Exception.Message)" }
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue }
    throw $original
}
