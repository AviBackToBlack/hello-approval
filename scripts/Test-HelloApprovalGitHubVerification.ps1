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
        [switch]$AllowExitOne
    )

    $saved = $ErrorActionPreference
    $stderrPath = [IO.Path]::GetTempFileName()
    $output = @()
    $stderr = @()
    $rc = $null
    try {
        # Windows PowerShell 5.1 can promote native stderr to NativeCommandError
        # when ErrorActionPreference=Stop. Native exit status is authoritative here.
        $ErrorActionPreference = 'Continue'
        $output = @(& $Exe @Arguments 2> $stderrPath | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
        $stderr = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            @([IO.File]::ReadAllLines($stderrPath) | ForEach-Object { [string]$_ })
        } else {
            @()
        }
    } finally {
        $ErrorActionPreference = $saved
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }

    if ($rc -eq 0 -or ($AllowExitOne -and $rc -eq 1)) {
        return [pscustomobject]@{ ExitCode = $rc; Output = $output; Stderr = $stderr }
    }

    $detailLines = @($stderr) + @($output)
    $detail = if ($detailLines.Count -gt 0) { ' ' + ($detailLines -join ' | ') } else { '' }
    throw "$Context failed with exit $rc.$detail"
}
function Get-OneLine {
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][string]$Context)
    if ($Result.Output.Count -ne 1) {
        throw "$Context returned $($Result.Output.Count) lines; expected exactly one."
    }
    return [string]$Result.Output[0]
}

function Test-ObjectProperty {
    param([Parameter(Mandatory = $true)]$Object, [Parameter(Mandatory = $true)][string]$Name)
    return $null -ne $Object.PSObject.Properties[$Name]
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
$headerLines = New-Object System.Collections.Generic.List[string]
foreach ($line in $rawCommit.Output) {
    if ([string]::IsNullOrEmpty([string]$line)) { break }
    [void]$headerLines.Add([string]$line)
}
$gpgSigHeaders = @($headerLines | Where-Object { $_ -match '\Agpgsig ' })
if ($gpgSigHeaders.Count -ne 1) {
    throw "Local commit $sha does not contain exactly one gpgsig header. Refusing to treat commit-message text or an unsigned/malformed commit as hello-approval evidence."
}
if ([string]$gpgSigHeaders[0] -cne 'gpgsig -----BEGIN SSH SIGNATURE-----') {
    throw "Local commit $sha is not SSH-signed; gpgsig header is '$($gpgSigHeaders[0])'."
}
$apiPath = "repos/$Repository/commits/$sha"
$api = Invoke-NativeCommand -Exe $gh -Arguments @('api', '--hostname', 'github.com', '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28', $apiPath) -Context "Read GitHub commit verification for $Repository@$sha"
$jsonText = $api.Output -join "`n"
try {
    $response = $jsonText | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "GitHub commit API returned invalid JSON for $Repository@$sha. $($_.Exception.Message)"
}

if (-not (Test-ObjectProperty -Object $response -Name 'sha')) {
    throw 'GitHub response is missing sha.'
}
$remoteSha = [string]$response.sha
if ([string]::IsNullOrWhiteSpace($remoteSha) -or $remoteSha.ToLowerInvariant() -cne $sha) {
    throw "GitHub returned a different commit SHA. Local=$sha Remote=$remoteSha"
}
if (-not (Test-ObjectProperty -Object $response -Name 'commit') -or $null -eq $response.commit) {
    throw 'GitHub response is missing commit.'
}
if (-not (Test-ObjectProperty -Object $response.commit -Name 'verification') -or $null -eq $response.commit.verification) {
    throw 'GitHub response is missing commit.verification.'
}

$verification = $response.commit.verification
foreach ($requiredProperty in @('verified', 'reason', 'signature', 'payload', 'verified_at')) {
    if (-not (Test-ObjectProperty -Object $verification -Name $requiredProperty)) {
        throw "GitHub commit.verification is missing '$requiredProperty'."
    }
}
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
