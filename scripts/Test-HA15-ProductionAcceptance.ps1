#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HelloApprovalRepo,
    [Parameter(Mandatory = $true)][string]$TargetRepo,
    [Parameter(Mandatory = $true)][string]$Principal,
    [Parameter(Mandatory = $true)][string]$ExpectedKeyFingerprint,
    [switch]$KeepInstalled,
    [switch]$DevelopmentSkipSigningProbe
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedHead = 'e4d0ab4783e790a2d8eed488c6f578b7666beccb'
$ReviewedInputs = @(
    'scripts/Install-HelloApprovalLocalVerification.ps1',
    'scripts/Test-HelloApprovalLocalVerification.ps1'
)

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowExitOne,
        [switch]$IncludeStderr
    )
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($IncludeStderr) {
            $output = @(& $Exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
        } else {
            $output = @(& $Exe @Arguments 2>$null | ForEach-Object { [string]$_ })
        }
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($rc -eq 0 -or ($AllowExitOne -and $rc -eq 1)) {
        return [pscustomobject]@{ ExitCode = $rc; Output = $output }
    }
    $detail = if ($output.Count -gt 0) { ' ' + ($output -join ' | ') } else { '' }
    throw "$Context failed with exit $rc.$detail"
}

function Get-GitOne {
    param([string]$Git, [string[]]$Arguments, [string]$Context)
    $r = Invoke-Native -Exe $Git -Arguments $Arguments -Context $Context -AllowExitOne
    if ($r.ExitCode -eq 1) { return $null }
    if ($r.Output.Count -ne 1) { throw "$Context returned $($r.Output.Count) values; expected exactly one." }
    return [string]$r.Output[0]
}

function Get-GitAll {
    param([string]$Git, [string[]]$Arguments, [string]$Context)
    $r = Invoke-Native -Exe $Git -Arguments $Arguments -Context $Context -AllowExitOne
    if ($r.ExitCode -eq 1) { return @() }
    return @($r.Output)
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Get-FileSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $exists = Test-Path -LiteralPath $Path -PathType Leaf
    if (-not $exists) {
        return [pscustomobject]@{ Path=$Path; Existed=$false; Bytes=$null; Attributes=$null; Sha256=$null }
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [pscustomobject]@{
        Path=$Path
        Existed=$true
        Bytes=[IO.File]::ReadAllBytes($Path)
        Attributes=$item.Attributes
        Sha256=Get-Sha256 -Path $Path
    }
}

function Restore-FileSnapshot {
    param([Parameter(Mandatory = $true)]$Snapshot)
    if ($Snapshot.Existed) {
        $parent = Split-Path -Parent $Snapshot.Path
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { [void][IO.Directory]::CreateDirectory($parent) }
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

function Assert-SnapshotRestored {
    param([Parameter(Mandatory = $true)]$Snapshot)
    if ($Snapshot.Existed) {
        if (-not (Test-Path -LiteralPath $Snapshot.Path -PathType Leaf)) { throw "Rollback did not restore file: $($Snapshot.Path)" }
        $now = Get-Sha256 -Path $Snapshot.Path
        if ($now -cne $Snapshot.Sha256) { throw "Rollback hash mismatch for $($Snapshot.Path): expected $($Snapshot.Sha256), got $now" }
    } elseif (Test-Path -LiteralPath $Snapshot.Path) {
        throw "Rollback left a file that did not exist in baseline: $($Snapshot.Path)"
    }
}

function Get-Ident {
    param([string]$Git, [string]$Repo, [ValidateSet('AUTHOR','COMMITTER')][string]$Kind)
    $raw = Get-GitOne -Git $Git -Arguments @('-C',$Repo,'var',"GIT_${Kind}_IDENT") -Context "Read GIT_${Kind}_IDENT"
    if ($raw -notmatch '^(?<name>.+) <(?<email>[^<>]+)> \d+ [+-]\d{4}$') { throw "Could not parse GIT_${Kind}_IDENT: $raw" }
    return [pscustomobject]@{ Name=$Matches.name; Email=$Matches.email }
}

function Format-Value { param($Value); if ($null -eq $Value) { return '<absent>' }; return [string]$Value }

if ($env:OS -ne 'Windows_NT') { throw 'HA-1.5 production acceptance supports Windows only.' }
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is not available.' }
if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) { throw 'USERPROFILE is not available.' }
if ($ExpectedKeyFingerprint -notmatch '\ASHA256:[A-Za-z0-9+/]+={0,2}\z') { throw "ExpectedKeyFingerprint must be one exact SHA256 OpenSSH fingerprint, got: $ExpectedKeyFingerprint" }

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'git.exe was not found.' }
$git = $gitCommand.Source

$helloRepo = [IO.Path]::GetFullPath($HelloApprovalRepo)
$target = [IO.Path]::GetFullPath($TargetRepo)
if (-not (Test-Path -LiteralPath $helloRepo -PathType Container)) { throw "HelloApprovalRepo is missing: $helloRepo" }
if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw "TargetRepo is missing: $target" }

$actualHead = Get-GitOne -Git $git -Arguments @('-C',$helloRepo,'rev-parse','HEAD') -Context 'Read hello-approval HEAD'
$ancestor = Invoke-Native -Exe $git -Arguments @('-C',$helloRepo,'merge-base','--is-ancestor',$ExpectedHead,'HEAD') -Context 'Verify reviewed HA-1.5 commit ancestry' -AllowExitOne
if ($ancestor.ExitCode -ne 0) { throw "Reviewed HA-1.5 commit $ExpectedHead is not an ancestor of checkout HEAD $actualHead." }
foreach ($path in $ReviewedInputs) {
    $diff = Invoke-Native -Exe $git -Arguments @('-C',$helloRepo,'diff','--quiet',$ExpectedHead,'--',$path) -Context "Compare reviewed HA-1.5 input $path" -AllowExitOne
    if ($diff.ExitCode -ne 0) { throw "Refusing production acceptance: $path differs from reviewed commit $ExpectedHead." }
}

$installer = Join-Path $helloRepo 'scripts\Install-HelloApprovalLocalVerification.ps1'
$verifier = Join-Path $helloRepo 'scripts\Test-HelloApprovalLocalVerification.ps1'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "Installer missing: $installer" }
if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) { throw "Verifier missing: $verifier" }

$isWorkTree = Get-GitOne -Git $git -Arguments @('-C',$target,'rev-parse','--is-inside-work-tree') -Context 'Check target worktree'
if ($isWorkTree -ne 'true') { throw "TargetRepo is not a Git worktree: $target" }

$globalCandidates = @(Get-GitAll -Git $git -Arguments @('var','GIT_CONFIG_GLOBAL') -Context 'git var GIT_CONFIG_GLOBAL' | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
if ($globalCandidates.Count -lt 1) { throw 'Git did not report any global configuration path.' }
$globalPath = [IO.Path]::GetFullPath(($globalCandidates[$globalCandidates.Count - 1] -replace '/', '\'))
$gitRoot = Join-Path $env:LOCALAPPDATA 'hello-approval\git'
$trustFile = Join-Path $gitRoot 'allowed_signers'
$verificationConfig = Join-Path $gitRoot 'verification.gitconfig'
$gitRootExisted = Test-Path -LiteralPath $gitRoot -PathType Container

$globalSnapshot = Get-FileSnapshot -Path $globalPath
$trustSnapshot = Get-FileSnapshot -Path $trustFile
$configSnapshot = Get-FileSnapshot -Path $verificationConfig

$baselineAllowedRaw = Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--path','--get','gpg.ssh.allowedSignersFile') -Context 'Read baseline effective allowedSignersFile'
$baselineAllowedPath = $null
$baselineAllowedSnapshot = $null
if (-not [string]::IsNullOrWhiteSpace($baselineAllowedRaw)) {
    $baselineAllowedPath = [IO.Path]::GetFullPath(($baselineAllowedRaw -replace '/', '\'))
    if (Test-Path -LiteralPath $baselineAllowedPath -PathType Leaf) { $baselineAllowedSnapshot = Get-FileSnapshot -Path $baselineAllowedPath }
}
$baselineFormat = Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--get','gpg.format') -Context 'Read baseline gpg.format'
$baselineProgram = Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--get','gpg.ssh.program') -Context 'Read baseline gpg.ssh.program'
$baselineSigningKey = Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--get','user.signingkey') -Context 'Read baseline user.signingkey'
$baselineAuthor = Get-Ident -Git $git -Repo $target -Kind AUTHOR
$baselineCommitter = Get-Ident -Git $git -Repo $target -Kind COMMITTER

Write-Host '=== HA-1.5 production acceptance baseline ==='
Write-Host "checkout HEAD:       $actualHead"
Write-Host "reviewed HA-1.5:     $ExpectedHead"
Write-Host "target repo:         $target"
Write-Host ("global candidates:   {0}" -f ($globalCandidates -join '; '))
Write-Host "global write path:   $globalPath"
Write-Host "global SHA256:       $(Format-Value $globalSnapshot.Sha256)"
Write-Host "project trust SHA256: $(Format-Value $trustSnapshot.Sha256)"
Write-Host "project cfg SHA256:   $(Format-Value $configSnapshot.Sha256)"
Write-Host "baseline allowed:    $(Format-Value $baselineAllowedPath)"
if ($null -ne $baselineAllowedSnapshot) { Write-Host "baseline allowed SHA256: $($baselineAllowedSnapshot.Sha256)" }
Write-Host "gpg.format:          $(Format-Value $baselineFormat)"
Write-Host "gpg.ssh.program:     $(Format-Value $baselineProgram)"
Write-Host "user.signingkey:     $(Format-Value $baselineSigningKey)"
Write-Host "author:               $($baselineAuthor.Name) <$($baselineAuthor.Email)>"
Write-Host "committer:            $($baselineCommitter.Name) <$($baselineCommitter.Email)>"
Write-Host "expected principal:    $Principal"
Write-Host "expected fingerprint:  $ExpectedKeyFingerprint"

$mutated = $false
$acceptancePassed = $false
$probeRoot = $null
try {
    $expectedTrustPath = [IO.Path]::GetFullPath($trustFile)
    if ($null -ne $baselineAllowedPath -and $baselineAllowedPath -ne $expectedTrustPath) {
        Write-Host '=== Expected no-override refusal ==='
        $failedAsExpected = $false
        try {
            & $installer -Principal $Principal
        } catch {
            $failedAsExpected = $true
            Write-Host "No-override refusal: PASS ($($_.Exception.Message))"
        }
        if (-not $failedAsExpected) { throw 'Installer unexpectedly accepted conflicting baseline allowedSignersFile without override.' }
        Assert-SnapshotRestored -Snapshot $globalSnapshot
        Assert-SnapshotRestored -Snapshot $trustSnapshot
        Assert-SnapshotRestored -Snapshot $configSnapshot
    } else {
        Write-Host 'No conflicting baseline allowedSignersFile; no-override refusal probe is not applicable.'
    }

    Write-Host '=== Installing HA-1.5 for acceptance ==='
    & $installer -Principal $Principal -OverrideExistingVerificationConfig
    $mutated = $true

    $effectiveAllowedRaw = Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--path','--get','gpg.ssh.allowedSignersFile') -Context 'Read post-install target allowedSignersFile'
    $effectiveAllowed = [IO.Path]::GetFullPath(($effectiveAllowedRaw -replace '/', '\'))
    if ($effectiveAllowed -ne [IO.Path]::GetFullPath($trustFile)) { throw "Target repository verification trust path did not become project-owned. Effective=$effectiveAllowed" }
    if ($baselineFormat -ne (Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--get','gpg.format') -Context 'Re-read gpg.format')) { throw 'HA-1.5 changed target gpg.format.' }
    if ($baselineProgram -ne (Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--get','gpg.ssh.program') -Context 'Re-read gpg.ssh.program')) { throw 'HA-1.5 changed target gpg.ssh.program.' }
    if ($baselineSigningKey -ne (Get-GitOne -Git $git -Arguments @('-C',$target,'config','--includes','--get','user.signingkey') -Context 'Re-read user.signingkey')) { throw 'HA-1.5 changed target user.signingkey.' }
    $authorAfter = Get-Ident -Git $git -Repo $target -Kind AUTHOR
    $committerAfter = Get-Ident -Git $git -Repo $target -Kind COMMITTER
    if ($authorAfter.Name -cne $baselineAuthor.Name -or $authorAfter.Email -cne $baselineAuthor.Email) { throw 'HA-1.5 changed effective author identity.' }
    if ($committerAfter.Name -cne $baselineCommitter.Name -or $committerAfter.Email -cne $baselineCommitter.Email) { throw 'HA-1.5 changed effective committer identity.' }
    if ($null -ne $baselineAllowedSnapshot -and (Get-Sha256 -Path $baselineAllowedSnapshot.Path) -cne $baselineAllowedSnapshot.Sha256) { throw 'HA-1.5 modified the pre-existing manual allowed_signers file.' }

    if ($DevelopmentSkipSigningProbe) {
        Write-Warning 'DEVELOPMENT ONLY: real signing/verification probe skipped. This run does NOT satisfy production acceptance.'
    } else {
        Write-Host '=== Real Windows Hello signing + independent OpenSSH verification ==='
        Write-Host 'A Windows Hello prompt is expected now.'
        $probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-ha15-sign-{0}' -f [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($probeRoot)
        [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'init') -Context 'git init HA-1.5 signing probe')
        [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'config','--local','user.name',$baselineAuthor.Name) -Context 'Set probe user.name')
        [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'config','--local','user.email',$baselineAuthor.Email) -Context 'Set probe user.email')
        [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'commit','--allow-empty','-S','-m','hello-approval HA-1.5 production acceptance') -Context 'Real Windows Hello-backed git commit -S' -IncludeStderr)
        $commit = Get-GitOne -Git $git -Arguments @('-C',$probeRoot,'rev-parse','HEAD') -Context 'Read HA-1.5 signed probe commit'
        Write-Host "Signed disposable commit: $commit"
        & $verifier -Repo $probeRoot -Commit $commit -ExpectedPrincipal $Principal -ExpectedKeyFingerprint $ExpectedKeyFingerprint
    }

    Write-Host '=== Production idempotence ==='
    $g0 = Get-Sha256 -Path $globalPath
    $t0 = Get-Sha256 -Path $trustFile
    $c0 = Get-Sha256 -Path $verificationConfig
    & $installer -Principal $Principal -OverrideExistingVerificationConfig
    if ((Get-Sha256 -Path $globalPath) -cne $g0) { throw 'Idempotent rerun changed global Git config bytes.' }
    if ((Get-Sha256 -Path $trustFile) -cne $t0) { throw 'Idempotent rerun changed project trust-store bytes.' }
    if ((Get-Sha256 -Path $verificationConfig) -cne $c0) { throw 'Idempotent rerun changed verification-config bytes.' }
    Write-Host 'Production idempotence: PASS'

    $acceptancePassed = -not $DevelopmentSkipSigningProbe
    if ($acceptancePassed) { Write-Host 'HA-1.5 PRODUCTION ACCEPTANCE: PASS' -ForegroundColor Green }
    else { Write-Warning 'All non-signing checks passed, but production acceptance remains INCOMPLETE because signing/verification was skipped.' }
} finally {
    if ($null -ne $probeRoot -and (Test-Path -LiteralPath $probeRoot)) { Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue }
    if (-not $KeepInstalled) {
        Write-Host '=== Restoring pre-acceptance verification configuration ==='
        Restore-FileSnapshot -Snapshot $globalSnapshot
        Restore-FileSnapshot -Snapshot $trustSnapshot
        Restore-FileSnapshot -Snapshot $configSnapshot
        if (-not $gitRootExisted -and (Test-Path -LiteralPath $gitRoot -PathType Container)) {
            $remaining = @(Get-ChildItem -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue }
        }
        Assert-SnapshotRestored -Snapshot $globalSnapshot
        Assert-SnapshotRestored -Snapshot $trustSnapshot
        Assert-SnapshotRestored -Snapshot $configSnapshot
        if ($null -ne $baselineAllowedSnapshot -and (Get-Sha256 -Path $baselineAllowedSnapshot.Path) -cne $baselineAllowedSnapshot.Sha256) { throw 'Manual baseline allowed_signers changed during acceptance/rollback.' }
        Write-Host 'Baseline verification configuration restored: PASS'
    } else {
        Write-Warning '-KeepInstalled specified: HA-1.5 verification state intentionally left installed.'
    }
}

if ($DevelopmentSkipSigningProbe) { exit 3 }
if (-not $acceptancePassed) { exit 1 }
exit 0
