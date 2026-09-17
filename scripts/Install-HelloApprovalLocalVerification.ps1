#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Principal,

    [switch]$OverrideExistingVerificationConfig
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Schema = 'hello-approval/ha-1.5/v1'
$ExpectedKeyType = 'sk-ecdsa-sha2-nistp256@openssh.com'
$PublicKeyLeaf = 'github-signing.pub'
$OwnedKey = 'gpg.ssh.allowedSignersFile'
$TrustMarker = "# $Schema"

function Assert-ExactPrincipal {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -notmatch '\A[A-Za-z0-9][A-Za-z0-9@._+:-]*\z') {
        throw "Principal must be one exact literal token using letters, digits, @ . _ + : or -; wildcard/pattern/list syntax is not accepted: $Value"
    }
}

function Test-WindowsPathEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )
    $leftNormalized = $Left -replace '\\','/'
    $rightNormalized = $Right -replace '\\','/'
    return [string]::Equals($leftNormalized, $rightNormalized, [StringComparison]::OrdinalIgnoreCase)
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

function Invoke-GitCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowExitOne
    )
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Git @Arguments 2>$null | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($rc -eq 0 -or ($AllowExitOne -and $rc -eq 1)) {
        return [pscustomobject]@{ ExitCode = $rc; Output = $output }
    }
    throw "$Context failed with exit $rc."
}

function Get-GitValues {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][ValidateSet('global','file')][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Key,
        [string]$File
    )
    $arguments = if ($Scope -eq 'file') { @('config', '--file', $File, '--get-all', $Key) }
        else { @('config', '--global', '--includes', '--get-all', $Key) }
    $result = Invoke-GitCommand -Git $Git -Arguments $arguments -Context "git config --$Scope --get-all $Key" -AllowExitOne
    if ($result.ExitCode -eq 1) { return @() }
    return @($result.Output)
}

function Get-DirectGlobalValues {
    param([Parameter(Mandatory = $true)][string]$Git, [Parameter(Mandatory = $true)][string]$Key)
    $result = Invoke-GitCommand -Git $Git -Arguments @('config', '--global', '--get-all', $Key) -Context "git config --global --get-all $Key" -AllowExitOne
    if ($result.ExitCode -eq 1) { return @() }
    return @($result.Output)
}

function Set-ConfigValue {
    param([string]$Git, [string]$File, [string]$Key, [string]$Value)
    [void](Invoke-GitCommand -Git $Git -Arguments @('config', '--file', $File, '--replace-all', $Key, $Value) -Context "git config --file <staged> --replace-all $Key")
}

function Get-GlobalWritePath {
    param([string]$Git)
    $result = Invoke-GitCommand -Git $Git -Arguments @('var', 'GIT_CONFIG_GLOBAL') -Context 'git var GIT_CONFIG_GLOBAL'
    $paths = @($result.Output | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
    if ($paths.Count -lt 1) { throw 'Git did not report a global configuration path.' }
    $path = $paths[$paths.Count - 1] -replace '/', '\'
    if (-not [IO.Path]::IsPathRooted($path)) { throw "Git global write path is not absolute: $path" }
    return [IO.Path]::GetFullPath($path)
}

function Get-FileSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    return [pscustomobject]@{
        Path = $Path
        Existed = $exists
        Bytes = if ($exists) { [IO.File]::ReadAllBytes($Path) } else { $null }
    }
}

function Restore-FileSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)
    if ($Snapshot.Existed) {
        $parent = Split-Path -Parent $Snapshot.Path
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { [void][IO.Directory]::CreateDirectory($parent) }
        [IO.File]::WriteAllBytes($Snapshot.Path, [byte[]]$Snapshot.Bytes)
    } elseif (Test-Path -LiteralPath $Snapshot.Path) {
        Remove-Item -LiteralPath $Snapshot.Path -Force
    }
}

function Write-Utf8NoBom {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Text)
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Install-StagedFile {
    param([Parameter(Mandatory = $true)][string]$Stage, [Parameter(Mandatory = $true)][string]$Destination)
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        $backup = "$Destination.backup.$([Guid]::NewGuid().ToString('N'))"
        try {
            [IO.File]::Replace($Stage, $Destination, $backup, $true)
        } finally {
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
        }
    } else {
        [IO.File]::Move($Stage, $Destination)
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'Install-HelloApprovalLocalVerification.ps1 supports Windows only.' }
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is not available.' }
if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) { throw 'USERPROFILE is not available.' }
Assert-ExactPrincipal -Value $Principal

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'Git was not found in PATH.' }
$git = $gitCommand.Source
[void](Invoke-GitCommand -Git $git -Arguments @('--version') -Context 'Git executable version probe')

$projectRoot = Join-Path $env:LOCALAPPDATA 'hello-approval'
Assert-RealDirectory -Path $projectRoot -Purpose 'hello-approval project root'
$gitRoot = Join-Path $projectRoot 'git'
if (Test-Path -LiteralPath $gitRoot) { Assert-RealDirectory -Path $gitRoot -Purpose 'hello-approval Git configuration directory' }

$publicKeyPath = Assert-RegularFile -Path (Join-Path $env:USERPROFILE ".ssh\$PublicKeyLeaf") -Purpose 'Git signing public key'
$keyLines = @(Get-Content -LiteralPath $publicKeyPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($keyLines.Count -ne 1) { throw "Signing public key must contain exactly one non-empty line: $publicKeyPath" }
$keyParts = @($keyLines[0] -split '\s+')
if ($keyParts.Count -lt 2 -or $keyParts[0] -cne $ExpectedKeyType) {
    throw "Signing public key must be an $ExpectedKeyType key: $publicKeyPath"
}
$keyType = [string]$keyParts[0]
$keyBlob = [string]$keyParts[1]
if ($keyBlob -notmatch '^[A-Za-z0-9+/]+={0,2}$') { throw "Signing public key blob is malformed: $publicKeyPath" }

$trustFile = Join-Path $gitRoot 'allowed_signers'
$verificationConfig = Join-Path $gitRoot 'verification.gitconfig'
$verificationConfigGit = $verificationConfig -replace '\\', '/'
$trustFileGit = $trustFile -replace '\\', '/'
$globalWritePath = Get-GlobalWritePath -Git $git

if (Test-Path -LiteralPath $trustFile) {
    $trustFile = Assert-RegularFile -Path $trustFile -Purpose 'hello-approval allowed_signers trust store'
    $existingTrustLines = @(Get-Content -LiteralPath $trustFile)
    if ($existingTrustLines.Count -lt 1 -or $existingTrustLines[0] -cne $TrustMarker) {
        throw "Refusing to replace unowned allowed_signers trust store: $trustFile"
    }
}

if (Test-Path -LiteralPath $verificationConfig) {
    $verificationConfig = Assert-RegularFile -Path $verificationConfig -Purpose 'hello-approval verification Git config'
    $schemaValues = @(Get-GitValues -Git $git -Scope file -File $verificationConfig -Key 'hello-approval.schema')
    if ($schemaValues.Count -ne 1 -or $schemaValues[0] -ne $Schema) {
        throw "Refusing to replace unowned verification Git config fragment: $verificationConfig"
    }
    $enumeration = Invoke-GitCommand -Git $git -Arguments @('config', '--file', $verificationConfig, '--name-only', '--list') -Context 'Enumerate existing hello-approval verification Git config fragment'
    $unknownKeys = @($enumeration.Output | Where-Object { @('hello-approval.schema', $OwnedKey) -notcontains $_ } | Select-Object -Unique)
    if ($unknownKeys.Count -gt 0) {
        Write-Warning "Owned hello-approval verification Git config contains extra keys that will be dropped on rewrite: $($unknownKeys -join ', ')"
    }
}

$effectiveValues = @(Get-GitValues -Git $git -Scope global -Key $OwnedKey)
$conflicts = @($effectiveValues | Where-Object { -not (Test-WindowsPathEqual -Left ([string]$_) -Right $trustFileGit) })
if ($conflicts.Count -gt 0 -and -not $OverrideExistingVerificationConfig) {
    throw "Existing global Git setting '$OwnedKey' conflicts with hello-approval. Re-run with -OverrideExistingVerificationConfig to preserve it but give the hello-approval verification include later precedence. Existing values: $($effectiveValues -join '; ')"
}

$directIncludes = @(Get-DirectGlobalValues -Git $git -Key 'include.path')
$ourIncludeCount = @($directIncludes | Where-Object { Test-WindowsPathEqual -Left ([string]$_) -Right $verificationConfigGit }).Count
if ($ourIncludeCount -gt 1) { throw "Global Git config contains duplicate hello-approval verification include.path entries: $verificationConfigGit" }

if (-not $PSCmdlet.ShouldProcess($gitRoot, "Install/update hello-approval local verification trust mapping for principal '$Principal'")) { return }

$gitRootExisted = Test-Path -LiteralPath $gitRoot -PathType Container
Ensure-RealDirectory -Path $gitRoot
$trustStage = Join-Path $gitRoot ('.allowed_signers.staging.{0}' -f [Guid]::NewGuid().ToString('N'))
$configStage = Join-Path $gitRoot ('.verification.gitconfig.staging.{0}' -f [Guid]::NewGuid().ToString('N'))
$globalSnapshot = Get-FileSnapshot -Path $globalWritePath
$trustSnapshot = Get-FileSnapshot -Path $trustFile
$configSnapshot = Get-FileSnapshot -Path $verificationConfig

try {
    $trustText = "$TrustMarker`n$Principal namespaces=`"git`" $keyType $keyBlob`n"
    Write-Utf8NoBom -Path $trustStage -Text $trustText
    $renderedTrust = [IO.File]::ReadAllText($trustStage)
    if ($renderedTrust -cne $trustText) { throw 'Staged allowed_signers trust store failed byte/text verification.' }

    Set-ConfigValue -Git $git -File $configStage -Key 'hello-approval.schema' -Value $Schema
    Set-ConfigValue -Git $git -File $configStage -Key $OwnedKey -Value $trustFileGit
    $schemaValues = @(Get-GitValues -Git $git -Scope file -File $configStage -Key 'hello-approval.schema')
    $pathValues = @(Get-GitValues -Git $git -Scope file -File $configStage -Key $OwnedKey)
    if ($schemaValues.Count -ne 1 -or $schemaValues[0] -ne $Schema) { throw 'Staged verification config failed schema verification.' }
    if ($pathValues.Count -ne 1 -or -not (Test-WindowsPathEqual -Left ([string]$pathValues[0]) -Right $trustFileGit)) { throw 'Staged verification config failed allowedSignersFile verification.' }

    Install-StagedFile -Stage $trustStage -Destination $trustFile
    Install-StagedFile -Stage $configStage -Destination $verificationConfig

    if ($ourIncludeCount -eq 0) {
        [void](Invoke-GitCommand -Git $git -Arguments @('config', '--global', '--add', 'include.path', $verificationConfigGit) -Context 'Register hello-approval verification include.path in global Git config')
    }

    $postIncludes = @(Get-DirectGlobalValues -Git $git -Key 'include.path')
    if (@($postIncludes | Where-Object { Test-WindowsPathEqual -Left ([string]$_) -Right $verificationConfigGit }).Count -ne 1) {
        throw 'Global Git config does not contain exactly one hello-approval verification include.path after installation.'
    }

    $verifyRoot = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-ha15-verify-{0}' -f [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($verifyRoot)
    $oldCeiling = $env:GIT_CEILING_DIRECTORIES
    try {
        $env:GIT_CEILING_DIRECTORIES = $verifyRoot
        $probe = Invoke-GitCommand -Git $git -Arguments @('-C', $verifyRoot, 'config', '--global', '--includes', '--get', $OwnedKey) -Context 'Verify context-neutral global allowedSignersFile' -AllowExitOne
        if ($probe.ExitCode -ne 0 -or $probe.Output.Count -ne 1 -or -not (Test-WindowsPathEqual -Left ([string]$probe.Output[0]) -Right $trustFileGit)) {
            throw 'Context-neutral global gpg.ssh.allowedSignersFile is not the hello-approval value after installation. An unconditional later global include may be overriding it.'
        }
    } finally {
        $env:GIT_CEILING_DIRECTORIES = $oldCeiling
        Remove-Item -LiteralPath $verifyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'HA-1.5 local verification trust mapping is installed and verified.'
    Write-Host "Principal: $Principal"
    Write-Host "Trust store: $trustFile"
    Write-Host "Verification config: $verificationConfig"
    Write-Host 'Trust entry is restricted to SSH signature namespace "git".'
    Write-Host 'Author/committer identity was not modified or inferred from the principal.'
} catch {
    $original = $_
    try { Restore-FileSnapshot -Snapshot $globalSnapshot } catch { Write-Warning "Failed to restore global Git config snapshot: $($_.Exception.Message)" }
    try { Restore-FileSnapshot -Snapshot $trustSnapshot } catch { Write-Warning "Failed to restore allowed_signers snapshot: $($_.Exception.Message)" }
    try { Restore-FileSnapshot -Snapshot $configSnapshot } catch { Write-Warning "Failed to restore verification config snapshot: $($_.Exception.Message)" }
    foreach ($stage in @($trustStage, $configStage)) {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue }
    }
    if (-not $gitRootExisted -and (Test-Path -LiteralPath $gitRoot -PathType Container)) {
        $remaining = @(Get-ChildItem -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue }
    }
    throw $original
}
