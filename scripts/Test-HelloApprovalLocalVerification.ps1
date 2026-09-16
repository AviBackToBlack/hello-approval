#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Repo = '.',
    [string]$Commit = 'HEAD'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedSchema = 'hello-approval/ha-1.5/v1'
$ExpectedTrustMarker = "# $ExpectedSchema"

function Invoke-GitCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowExitOne,
        [switch]$IncludeStderr
    )
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($IncludeStderr) {
            $output = @(& $Git @Arguments 2>&1 | ForEach-Object { [string]$_ })
        } else {
            $output = @(& $Git @Arguments 2>$null | ForEach-Object { [string]$_ })
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
    $result = Invoke-GitCommand -Git $Git -Arguments $Arguments -Context $Context -AllowExitOne
    if ($result.ExitCode -eq 1) { return $null }
    if ($result.Output.Count -ne 1) { throw "$Context returned $($result.Output.Count) values; expected exactly one." }
    return [string]$result.Output[0]
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

if ($env:OS -ne 'Windows_NT') { throw 'Test-HelloApprovalLocalVerification.ps1 supports Windows only.' }
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA is not available.' }
if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) { throw 'USERPROFILE is not available.' }

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'Git was not found in PATH.' }
$git = $gitCommand.Source
$systemSshKeygen = Assert-RegularFile -Path (Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe') -Purpose 'stock Windows OpenSSH verifier'
$verificationProgram = $systemSshKeygen -replace '\\','/'

$repoPath = [IO.Path]::GetFullPath($Repo)
$isWorkTree = Get-GitOne -Git $git -Arguments @('-C', $repoPath, 'rev-parse', '--is-inside-work-tree') -Context 'Check repository worktree'
if ($isWorkTree -ne 'true') { throw "Repository path is not a Git worktree: $repoPath" }

$resolvedCommit = Get-GitOne -Git $git -Arguments @('-C', $repoPath, 'rev-parse', "$Commit^{commit}") -Context "Resolve commit '$Commit'"
$format = Get-GitOne -Git $git -Arguments @('-C', $repoPath, 'config', '--includes', '--get', 'gpg.format') -Context 'Read effective gpg.format'
if ($format -ne 'ssh') { throw "Effective gpg.format is not ssh in target repository: $(if ($null -eq $format) { '<absent>' } else { $format })" }

$allowedRaw = Get-GitOne -Git $git -Arguments @('-C', $repoPath, 'config', '--includes', '--path', '--get', 'gpg.ssh.allowedSignersFile') -Context 'Read effective gpg.ssh.allowedSignersFile'
if ([string]::IsNullOrWhiteSpace($allowedRaw)) { throw 'Effective gpg.ssh.allowedSignersFile is absent.' }
$allowedPath = [IO.Path]::GetFullPath(($allowedRaw -replace '/', '\'))
$expectedAllowedPath = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'hello-approval\git\allowed_signers'))
if ($allowedPath -ne $expectedAllowedPath) {
    throw "Target repository effective gpg.ssh.allowedSignersFile is not the hello-approval trust store. Effective='$allowedPath' Expected='$expectedAllowedPath'. A repo-local/includeIf override may be active."
}
$allowedPath = Assert-RegularFile -Path $allowedPath -Purpose 'hello-approval allowed_signers trust store'

$lines = @(Get-Content -LiteralPath $allowedPath)
if ($lines.Count -lt 2 -or $lines[0] -cne $ExpectedTrustMarker) { throw "allowed_signers ownership/schema marker mismatch: $allowedPath" }
$entries = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#') })
if ($entries.Count -ne 1) { throw "HA-1.5 v0.1 trust store must contain exactly one non-comment signer entry; found $($entries.Count)." }
if ($entries[0] -notmatch '^(?<principal>[A-Za-z0-9][A-Za-z0-9@._+:-]*) namespaces="git" (?<type>\S+) (?<blob>\S+)$') {
    throw 'allowed_signers entry is not the expected exact-principal, git-namespace-only v0.1 form.'
}
$principal = [string]$Matches.principal
$trustType = [string]$Matches.type
$trustBlob = [string]$Matches.blob

$publicKey = Assert-RegularFile -Path (Join-Path $env:USERPROFILE '.ssh\github-signing.pub') -Purpose 'canonical Git signing public key'
$keyLines = @(Get-Content -LiteralPath $publicKey | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($keyLines.Count -ne 1) { throw "Canonical signing public key must contain exactly one non-empty line: $publicKey" }
$keyParts = @($keyLines[0] -split '\s+')
if ($keyParts.Count -lt 2 -or $keyParts[0] -cne $trustType -or $keyParts[1] -cne $trustBlob) {
    throw 'allowed_signers key does not match the canonical hello-approval Git signing public key.'
}

$verify = Invoke-GitCommand -Git $git -Arguments @('-c', "gpg.ssh.program=$verificationProgram", '-C', $repoPath, 'verify-commit', $resolvedCommit) -Context "git verify-commit $resolvedCommit" -AllowExitOne -IncludeStderr
if ($verify.ExitCode -ne 0) {
    $detail = if ($verify.Output.Count -gt 0) { $verify.Output -join ' | ' } else { '<no output>' }
    throw "git verify-commit rejected $resolvedCommit. $detail"
}

$status = Get-GitOne -Git $git -Arguments @('-c', "gpg.ssh.program=$verificationProgram", '-C', $repoPath, 'log', '-1', '--format=%G?', $resolvedCommit) -Context 'Read Git signature status'
$signer = Get-GitOne -Git $git -Arguments @('-c', "gpg.ssh.program=$verificationProgram", '-C', $repoPath, 'log', '-1', '--format=%GS', $resolvedCommit) -Context 'Read Git signature principal'
$keyFingerprint = Get-GitOne -Git $git -Arguments @('-c', "gpg.ssh.program=$verificationProgram", '-C', $repoPath, 'log', '-1', '--format=%GK', $resolvedCommit) -Context 'Read Git signature key fingerprint'
$trust = Get-GitOne -Git $git -Arguments @('-c', "gpg.ssh.program=$verificationProgram", '-C', $repoPath, 'log', '-1', '--format=%GT', $resolvedCommit) -Context 'Read Git signature trust level'

if ($status -ne 'G') { throw "Git signature status is '$status', expected 'G'." }
if ($trust -ne 'fully') { throw "Git SSH signature trust is '$trust', expected 'fully'." }
if ($signer -cne $principal) { throw "Git reported signer principal '$signer', expected '$principal' from the project-owned trust store." }
if ([string]::IsNullOrWhiteSpace($keyFingerprint)) { throw 'Git did not report a signing-key fingerprint.' }

$display = Invoke-GitCommand -Git $git -Arguments @('-c', "gpg.ssh.program=$verificationProgram", '-C', $repoPath, 'log', '-1', '--show-signature', '--format=fuller', $resolvedCommit) -Context 'git log --show-signature' -IncludeStderr

Write-Host 'HA-1.5 LOCAL VERIFICATION: PASS' -ForegroundColor Green
Write-Host "Commit: $resolvedCommit"
Write-Host "Principal: $principal"
Write-Host "Key fingerprint: $keyFingerprint"
Write-Host "Trust: $trust"
Write-Host "Trust store: $allowedPath"
Write-Host "Verifier: $systemSshKeygen"
Write-Host 'Note: the allowed_signers principal is a local trust label for the key; it is not automatically compared with Git author/committer identity.'
Write-Host '--- git log --show-signature ---'
$display.Output | ForEach-Object { Write-Host $_ }
exit 0
