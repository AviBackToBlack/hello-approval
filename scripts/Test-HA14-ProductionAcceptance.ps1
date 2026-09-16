#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TargetRepo = '.',
    [Parameter(Mandatory = $true)][string]$HelloApprovalRepo,
    [switch]$EnableCommitSigning,
    [switch]$EnableTagSigning,
    [switch]$KeepInstalled,
    [switch]$DevelopmentSkipSigningProbe
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedHead = '8801a1a3e235fd062d092d0e726f7ff74aa8e21a'
$ExpectedSchema = 'hello-approval/ha-1.4/v1'
$OwnedKeys = @('gpg.format', 'gpg.ssh.program', 'user.signingkey')
$RelevantKeys = @(
    'core.sshCommand',
    'gpg.format',
    'gpg.ssh.program',
    'gpg.ssh.allowedSignersFile',
    'user.signingkey',
    'commit.gpgsign',
    'tag.gpgsign',
    'user.name',
    'user.email'
)

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowExitOne
    )
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Exe @Arguments 2>$null | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($rc -eq 0 -or ($AllowExitOne -and $rc -eq 1)) {
        return [pscustomobject]@{ ExitCode = $rc; Output = $output }
    }
    throw "$Context failed with exit $rc."
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
        return [pscustomobject]@{ Path = $Path; Existed = $false; Bytes = $null; Attributes = $null; Sha256 = $null }
    }
    $item = Get-Item -LiteralPath $Path -Force
    return [pscustomobject]@{
        Path       = $Path
        Existed    = $true
        Bytes      = [IO.File]::ReadAllBytes($Path)
        Attributes = $item.Attributes
        Sha256     = Get-Sha256 -Path $Path
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

function Get-GitOne {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $r = Invoke-Native -Exe $Git -Arguments $Arguments -Context ('git ' + ($Arguments -join ' ')) -AllowExitOne
    if ($r.ExitCode -eq 1) { return $null }
    if ($r.Output.Count -ne 1) { throw "Expected exactly one value from git $($Arguments -join ' '), got $($r.Output.Count)." }
    return [string]$r.Output[0]
}

function Get-GitAll {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $r = Invoke-Native -Exe $Git -Arguments $Arguments -Context ('git ' + ($Arguments -join ' ')) -AllowExitOne
    if ($r.ExitCode -eq 1) { return @() }
    return @($r.Output)
}

function Get-RepoEffectiveState {
    param([string]$Git, [string]$Repo)
    $state = [ordered]@{}
    foreach ($key in $RelevantKeys) {
        $state[$key] = Get-GitOne -Git $Git -Arguments @('-C', $Repo, 'config', '--includes', '--get', $key)
    }
    return $state
}

function Format-StateValue {
    param($Value)
    if ($null -eq $Value) { return '<absent>' }
    return [string]$Value
}

function Get-IdentNameEmail {
    param([string]$Git, [string]$Repo, [ValidateSet('AUTHOR','COMMITTER')][string]$Kind)
    $raw = Get-GitOne -Git $Git -Arguments @('-C', $Repo, 'var', "GIT_${Kind}_IDENT")
    if ($raw -notmatch '^(?<name>.+) <(?<email>[^<>]+)> \d+ [+-]\d{4}$') {
        throw "Could not parse GIT_${Kind}_IDENT: $raw"
    }
    return [pscustomobject]@{ Name = $Matches.name; Email = $Matches.email }
}

function Get-EnvTriplet {
    param([string]$Name)
    return [pscustomobject]@{
        Process = [Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::Process)
        User    = [Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::User)
        Machine = [Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::Machine)
    }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -cne $Expected) {
        throw "$Message Expected='$(Format-StateValue $Expected)' Actual='$(Format-StateValue $Actual)'"
    }
}

function Assert-BytesRestored {
    param($Snapshot)
    if ($Snapshot.Existed) {
        if (-not (Test-Path -LiteralPath $Snapshot.Path -PathType Leaf)) { throw "Rollback did not restore file: $($Snapshot.Path)" }
        $now = Get-Sha256 -Path $Snapshot.Path
        if ($now -cne $Snapshot.Sha256) { throw "Rollback hash mismatch for $($Snapshot.Path): expected $($Snapshot.Sha256), got $now" }
    } elseif (Test-Path -LiteralPath $Snapshot.Path) {
        throw "Rollback left a file that did not exist in the baseline: $($Snapshot.Path)"
    }
}

if ($env:OS -ne 'Windows_NT') { throw 'Production acceptance supports Windows only.' }

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'git.exe was not found.' }
$git = $gitCommand.Source

$helloRepo = [IO.Path]::GetFullPath($HelloApprovalRepo)
$target = [IO.Path]::GetFullPath($TargetRepo)
if (-not (Test-Path -LiteralPath $helloRepo -PathType Container)) { throw "HelloApprovalRepo is missing: $helloRepo" }
if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw "TargetRepo is missing: $target" }

$actualHead = Get-GitOne -Git $git -Arguments @('-C', $helloRepo, 'rev-parse', 'HEAD')
$ancestorProbe = Invoke-Native -Exe $git -Arguments @('-C', $helloRepo, 'merge-base', '--is-ancestor', $ExpectedHead, 'HEAD') -Context 'verify reviewed HA-1.4 commit ancestry' -AllowExitOne
if ($ancestorProbe.ExitCode -ne 0) { throw "Refusing production acceptance: reviewed HA-1.4 commit $ExpectedHead is not an ancestor of HEAD $actualHead." }
foreach ($reviewedPath in @('scripts/Install-HelloApprovalGitConfig.ps1','provenance/sshenc-v0.6.101.json')) {
    $diffProbe = Invoke-Native -Exe $git -Arguments @('-C', $helloRepo, 'diff', '--quiet', $ExpectedHead, '--', $reviewedPath) -Context "compare reviewed HA-1.4 input $reviewedPath" -AllowExitOne
    if ($diffProbe.ExitCode -ne 0) { throw "Refusing production acceptance: $reviewedPath differs from reviewed commit $ExpectedHead." }
}

$installer = Join-Path $helloRepo 'scripts\Install-HelloApprovalGitConfig.ps1'
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw "HA-1.4 installer is missing: $installer" }

$isWorkTree = Get-GitOne -Git $git -Arguments @('-C', $target, 'rev-parse', '--is-inside-work-tree')
Assert-Equal -Actual $isWorkTree -Expected 'true' -Message 'TargetRepo must be a Git worktree.'

$globalCandidates = @(Get-GitAll -Git $git -Arguments @('var', 'GIT_CONFIG_GLOBAL') | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
if ($globalCandidates.Count -lt 1) { throw 'Git did not report any global configuration path.' }
# Match Install-HelloApprovalGitConfig.ps1: git config --global writes the last
# path reported by modern Git when both XDG and ~/.gitconfig candidates exist.
$globalPathRaw = [string]$globalCandidates[$globalCandidates.Count - 1]
$globalPath = [IO.Path]::GetFullPath(($globalPathRaw -replace '/', '\'))
$ownedConfig = Join-Path $env:LOCALAPPDATA 'hello-approval\git\signing.gitconfig'
$runtimeSshenc = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'hello-approval\runtime\sshenc\v0.6.101\bin\sshenc.exe'))
$publicKey = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.ssh\github-signing.pub'))
$desired = @{
    'gpg.format'       = 'ssh'
    'gpg.ssh.program' = ($runtimeSshenc -replace '\\','/')
    'user.signingkey' = ($publicKey -replace '\\','/')
}

$globalSnapshot = Get-FileSnapshot -Path $globalPath
$ownedSnapshot = Get-FileSnapshot -Path $ownedConfig
$gitRoot = Split-Path -Parent $ownedConfig
$gitRootExisted = Test-Path -LiteralPath $gitRoot -PathType Container

$baselineRepo = Get-RepoEffectiveState -Git $git -Repo $target
$baselineDirect = [ordered]@{}
foreach ($key in $OwnedKeys) {
    $baselineDirect[$key] = @(Get-GitAll -Git $git -Arguments @('config', '--global', '--get-all', $key))
}
$baselineAuthor = Get-IdentNameEmail -Git $git -Repo $target -Kind AUTHOR
$baselineCommitter = Get-IdentNameEmail -Git $git -Repo $target -Kind COMMITTER
$baselineSshAuthSock = Get-EnvTriplet -Name 'SSH_AUTH_SOCK'
$baselineGitSshCommand = Get-EnvTriplet -Name 'GIT_SSH_COMMAND'
$baselineService = $null
try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='ssh-agent'" -ErrorAction Stop
    if ($null -ne $svc) { $baselineService = [pscustomobject]@{ State = $svc.State; StartMode = $svc.StartMode } }
} catch {
    Write-Warning "Could not snapshot stock ssh-agent service: $($_.Exception.Message)"
}

Write-Host '=== HA-1.4 production acceptance baseline ==='
Write-Host "checkout HEAD:    $actualHead"
Write-Host "reviewed HA-1.4:  $ExpectedHead"
Write-Host "target repo:      $target"
Write-Host ("global candidates: {0}" -f ($globalCandidates -join "; "))
Write-Host "global write path: $globalPath"
Write-Host "owned config:     $ownedConfig"
Write-Host "global SHA256:    $(Format-StateValue $globalSnapshot.Sha256)"
Write-Host "owned SHA256:     $(Format-StateValue $ownedSnapshot.Sha256)"
foreach ($key in $RelevantKeys) { Write-Host ("target {0} = {1}" -f $key, (Format-StateValue $baselineRepo[$key])) }
Write-Host "author:            $($baselineAuthor.Name) <$($baselineAuthor.Email)>"
Write-Host "committer:         $($baselineCommitter.Name) <$($baselineCommitter.Email)>"

$conflicts = New-Object 'System.Collections.Generic.List[string]'
foreach ($key in $OwnedKeys) {
    $all = @(Get-GitAll -Git $git -Arguments @('config', '--global', '--includes', '--get-all', $key))
    foreach ($value in $all) {
        if ([string]$value -cne [string]$desired[$key]) { $conflicts.Add("$key=$value") | Out-Null }
    }
}

$mutated = $false
$acceptancePassed = $false
try {
    if ($conflicts.Count -gt 0) {
        Write-Host '=== Expected no-override refusal ==='
        Write-Host ($conflicts -join "`n")
        $failedAsExpected = $false
        try {
            & $installer -EnableCommitSigning:$EnableCommitSigning -EnableTagSigning:$EnableTagSigning
        } catch {
            $failedAsExpected = $true
            Write-Host "No-override refusal: PASS ($($_.Exception.Message))"
        }
        if (-not $failedAsExpected) { throw 'Installer unexpectedly accepted conflicting global signing state without -OverrideExistingSigningConfig.' }
        Assert-BytesRestored -Snapshot $globalSnapshot
        Assert-BytesRestored -Snapshot $ownedSnapshot
    } else {
        Write-Host 'No conflicting global signing values were present; no-override refusal probe is not applicable.'
    }

    Write-Host '=== Installing HA-1.4 for acceptance ==='
    & $installer -OverrideExistingSigningConfig -EnableCommitSigning:$EnableCommitSigning -EnableTagSigning:$EnableTagSigning
    $mutated = $true

    $afterDirect = [ordered]@{}
    foreach ($key in $OwnedKeys) {
        $afterDirect[$key] = @(Get-GitAll -Git $git -Arguments @('config', '--global', '--get-all', $key))
        if (($afterDirect[$key] -join "`0") -cne ($baselineDirect[$key] -join "`0")) {
            throw "Direct global values for '$key' changed. HA-1.4 must preserve pre-existing direct settings."
        }
    }

    $ownedSchema = Get-GitOne -Git $git -Arguments @('config', '--file', $ownedConfig, '--get', 'hello-approval.schema')
    Assert-Equal -Actual $ownedSchema -Expected $ExpectedSchema -Message 'Owned fragment schema mismatch.'

    $targetAfter = Get-RepoEffectiveState -Git $git -Repo $target
    foreach ($key in $OwnedKeys) {
        Assert-Equal -Actual $targetAfter[$key] -Expected $desired[$key] -Message "Target repo effective '$key' is not HA-1.4 value. A repo-local/includeIf override may be active."
    }
    if ($EnableCommitSigning) { Assert-Equal -Actual $targetAfter['commit.gpgsign'] -Expected 'true' -Message 'Target repo commit.gpgsign is not true.' }
    if ($EnableTagSigning) { Assert-Equal -Actual $targetAfter['tag.gpgsign'] -Expected 'true' -Message 'Target repo tag.gpgsign is not true.' }

    foreach ($key in @('core.sshCommand','gpg.ssh.allowedSignersFile','user.name','user.email')) {
        Assert-Equal -Actual $targetAfter[$key] -Expected $baselineRepo[$key] -Message "HA-1.4 changed unrelated target-repo setting '$key'."
    }

    $authorAfter = Get-IdentNameEmail -Git $git -Repo $target -Kind AUTHOR
    $committerAfter = Get-IdentNameEmail -Git $git -Repo $target -Kind COMMITTER
    Assert-Equal -Actual $authorAfter.Name -Expected $baselineAuthor.Name -Message 'Effective author name changed.'
    Assert-Equal -Actual $authorAfter.Email -Expected $baselineAuthor.Email -Message 'Effective author email changed.'
    Assert-Equal -Actual $committerAfter.Name -Expected $baselineCommitter.Name -Message 'Effective committer name changed.'
    Assert-Equal -Actual $committerAfter.Email -Expected $baselineCommitter.Email -Message 'Effective committer email changed.'

    foreach ($name in @('SSH_AUTH_SOCK','GIT_SSH_COMMAND')) {
        $before = if ($name -eq 'SSH_AUTH_SOCK') { $baselineSshAuthSock } else { $baselineGitSshCommand }
        $after = Get-EnvTriplet -Name $name
        foreach ($scope in @('Process','User','Machine')) {
            Assert-Equal -Actual $after.$scope -Expected $before.$scope -Message "$name/$scope changed."
        }
    }

    if ($null -ne $baselineService) {
        $svcAfter = Get-CimInstance Win32_Service -Filter "Name='ssh-agent'" -ErrorAction Stop
        Assert-Equal -Actual $svcAfter.State -Expected $baselineService.State -Message 'Stock ssh-agent service state changed.'
        Assert-Equal -Actual $svcAfter.StartMode -Expected $baselineService.StartMode -Message 'Stock ssh-agent service start mode changed.'
    }

    if ($DevelopmentSkipSigningProbe) {
        Write-Warning 'DEVELOPMENT ONLY: signing probe skipped. This run does NOT satisfy production acceptance.'
    } else {
        Write-Host '=== Real Windows Hello signing probe ==='
        Write-Host 'A Windows Hello prompt is expected now.'
        $probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-ha14-sign-{0}' -f [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($probeRoot)
        try {
            [void](Invoke-Native -Exe $git -Arguments @('-C', $probeRoot, 'init') -Context 'git init signing probe')
            [void](Invoke-Native -Exe $git -Arguments @('-C', $probeRoot, 'config', '--local', 'user.name', $baselineAuthor.Name) -Context 'set probe user.name')
            [void](Invoke-Native -Exe $git -Arguments @('-C', $probeRoot, 'config', '--local', 'user.email', $baselineAuthor.Email) -Context 'set probe user.email')
            [void](Invoke-Native -Exe $git -Arguments @('-C', $probeRoot, 'commit', '--allow-empty', '-S', '-m', 'hello-approval HA-1.4 production acceptance') -Context 'real Windows Hello-backed git commit -S')
            $commit = Get-GitOne -Git $git -Arguments @('-C', $probeRoot, 'rev-parse', 'HEAD')
            $rawCommit = @(Invoke-Native -Exe $git -Arguments @('-C', $probeRoot, 'cat-file', 'commit', $commit) -Context 'read signed acceptance commit').Output -join "`n"
            if ($rawCommit -notmatch 'gpgsig -----BEGIN SSH SIGNATURE-----') { throw 'Acceptance commit does not contain an SSH signature header.' }
            Write-Host "Signed disposable commit: $commit"

            $allowed = Get-GitOne -Git $git -Arguments @('-C', $probeRoot, 'config', '--includes', '--get', 'gpg.ssh.allowedSignersFile')
            if ($null -ne $allowed) {
                [void](Invoke-Native -Exe $git -Arguments @('-C', $probeRoot, 'verify-commit', 'HEAD') -Context 'git verify-commit acceptance commit')
                Write-Host 'git verify-commit: PASS'
            } else {
                Write-Host 'git verify-commit: SKIPPED (gpg.ssh.allowedSignersFile is not configured; HA-1.5 owns local trust mapping).'
            }
        } finally {
            if (Test-Path -LiteralPath $probeRoot) { Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    Write-Host '=== Production idempotence ==='
    $beforeGlobalHash = Get-Sha256 -Path $globalPath
    $beforeOwnedHash = Get-Sha256 -Path $ownedConfig
    & $installer -OverrideExistingSigningConfig -EnableCommitSigning:$EnableCommitSigning -EnableTagSigning:$EnableTagSigning
    $afterGlobalHash = Get-Sha256 -Path $globalPath
    $afterOwnedHash = Get-Sha256 -Path $ownedConfig
    Assert-Equal -Actual $afterGlobalHash -Expected $beforeGlobalHash -Message 'Second run changed global Git config bytes.'
    Assert-Equal -Actual $afterOwnedHash -Expected $beforeOwnedHash -Message 'Second run changed owned fragment bytes.'
    Write-Host 'Production idempotence: PASS'

    $acceptancePassed = -not $DevelopmentSkipSigningProbe
    if ($DevelopmentSkipSigningProbe) {
        Write-Warning 'All non-signing checks passed, but production acceptance remains INCOMPLETE because signing was skipped.'
    } else {
        Write-Host 'HA-1.4 PRODUCTION ACCEPTANCE: PASS' -ForegroundColor Green
    }
} finally {
    if (-not $KeepInstalled) {
        Write-Host '=== Restoring pre-acceptance Git configuration ==='
        Restore-FileSnapshot -Snapshot $globalSnapshot
        Restore-FileSnapshot -Snapshot $ownedSnapshot
        if (-not $gitRootExisted -and (Test-Path -LiteralPath $gitRoot -PathType Container)) {
            $remaining = @(Get-ChildItem -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) { Remove-Item -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue }
        }
        Assert-BytesRestored -Snapshot $globalSnapshot
        Assert-BytesRestored -Snapshot $ownedSnapshot
        Write-Host 'Baseline Git configuration restored: PASS'
    } else {
        Write-Warning '-KeepInstalled was specified: HA-1.4 state was intentionally left installed.'
    }
}

if ($DevelopmentSkipSigningProbe) { exit 3 }
if (-not $acceptancePassed) { exit 1 }
exit 0
