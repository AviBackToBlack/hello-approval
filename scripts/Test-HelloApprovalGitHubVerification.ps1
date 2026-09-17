#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Repository,

    [string]$Repo = '.',
    [string]$Commit = 'HEAD'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowExitOne,
        [switch]$IncludeStderr
    )

    $saved = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 can promote native stderr to NativeCommandError
        # when ErrorActionPreference=Stop. Native exit status is authoritative here.
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

function Get-OneLine {
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][string]$Context)
    if ($Result.Output.Count -ne 1) {
        throw "$Context returned $($Result.Output.Count) lines; expected exactly one."
    }
    return [string]$Result.Output[0]
}

if ($Repository -notmatch '\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z') {
    throw "Repository must be an exact GitHub owner/name pair, got: $Repository"
}

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'Git was not found in PATH.' }
$git = $gitCommand.Source

$ghCommand = Get-Command gh.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $ghCommand) { $ghCommand = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $ghCommand) { throw 'GitHub CLI (gh) was not found in PATH.' }
$gh = $ghCommand.Source

$repoPath = [IO.Path]::GetFullPath($Repo)
$isWorkTree = Get-OneLine -Result (Invoke-NativeCommand -Exe $git -Arguments @('-C', $repoPath, 'rev-parse', '--is-inside-work-tree') -Context 'Check repository worktree') -Context 'Check repository worktree'
if ($isWorkTree -ne 'true') { throw "Repository path is not a Git worktree: $repoPath" }

$resolved = Invoke-NativeCommand -Exe $git -Arguments @('-C', $repoPath, 'rev-parse', '--verify', '--end-of-options', "$Commit^{commit}") -Context "Resolve commit '$Commit'"
$sha = Get-OneLine -Result $resolved -Context "Resolve commit '$Commit'"
if ($sha -notmatch '\A[0-9a-fA-F]{40}\z') { throw "Resolved commit is not a full SHA-1 object id: $sha" }
$sha = $sha.ToLowerInvariant()

$rawCommit = Invoke-NativeCommand -Exe $git -Arguments @('-C', $repoPath, 'cat-file', 'commit', $sha) -Context "Read local commit object $sha"
$rawText = ($rawCommit.Output -join "`n")
if ($rawText -notmatch '(?m)^gpgsig -----BEGIN SSH SIGNATURE-----$') {
    throw "Local commit $sha is not an SSH-signed Git commit. Refusing to treat a hosting-platform signature or an unsigned commit as hello-approval evidence."
}
if ($rawText -match '(?m)^gpgsig -----BEGIN PGP SIGNATURE-----$') {
    throw "Local commit $sha contains a PGP signature, not the expected SSH signature."
}

$apiPath = "repos/$Repository/commits/$sha"
$api = Invoke-NativeCommand -Exe $gh -Arguments @('api', '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28', $apiPath) -Context "Read GitHub commit verification for $Repository@$sha"
$jsonText = $api.Output -join "`n"
try {
    $response = $jsonText | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "GitHub commit API returned invalid JSON for $Repository@$sha. $($_.Exception.Message)"
}

if ([string]::IsNullOrWhiteSpace([string]$response.sha) -or ([string]$response.sha).ToLowerInvariant() -cne $sha) {
    throw "GitHub returned a different commit SHA. Local=$sha Remote=$($response.sha)"
}
if ($null -eq $response.commit -or $null -eq $response.commit.verification) {
    throw 'GitHub response is missing commit.verification.'
}

$verification = $response.commit.verification
if ($verification.verified -ne $true) {
    throw "GitHub did not verify $sha. verified=$($verification.verified) reason=$($verification.reason)"
}
if ([string]$verification.reason -cne 'valid') {
    throw "GitHub verification reason is '$($verification.reason)', expected 'valid'."
}
if ([string]::IsNullOrWhiteSpace([string]$verification.signature)) {
    throw 'GitHub verified the commit but did not return the extracted signature.'
}
if ([string]$verification.signature -notmatch '\A-----BEGIN SSH SIGNATURE-----') {
    throw 'GitHub verification signature is not an SSH signature. A GitHub-generated PGP signature does not prove the local hello-approval signing path.'
}
if ([string]::IsNullOrWhiteSpace([string]$verification.payload)) {
    throw 'GitHub verification response is missing the signed payload.'
}
if ([string]::IsNullOrWhiteSpace([string]$verification.verified_at)) {
    throw 'GitHub verification response is missing verified_at.'
}

Write-Host 'HA-1.6 GITHUB VERIFICATION: PASS' -ForegroundColor Green
Write-Host "Repository: $Repository"
Write-Host "Commit: $sha"
Write-Host 'Local signature type: SSH'
Write-Host "GitHub verified: $($verification.verified)"
Write-Host "GitHub reason: $($verification.reason)"
Write-Host "GitHub verified_at: $($verification.verified_at)"
Write-Host 'GitHub signature type: SSH'
Write-Host 'The exact locally SSH-signed commit object is verified by GitHub; this is distinct from GitHub-generated PGP signing.'
