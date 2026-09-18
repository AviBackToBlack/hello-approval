#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HelloApprovalRepo,
    [Parameter(Mandatory = $true)][string]$Repository,
    [Parameter(Mandatory = $true)][string]$ExpectedPrincipal,
    [Parameter(Mandatory = $true)][string]$ExpectedKeyFingerprint,
    [switch]$DevelopmentSkipPushProbe
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedHead = 'e52f581e8a12b7a812165ca520f651480780ee04'
$ReviewedInput = 'scripts/Test-HelloApprovalGitHubVerification.ps1'

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
        return [pscustomobject]@{ ExitCode=$rc; Output=$output }
    }
    $detail = if ($output.Count -gt 0) { ' ' + ($output -join ' | ') } else { '' }
    throw "$Context failed with exit $rc.$detail"
}

function Get-One {
    param([string]$Exe, [string[]]$Arguments, [string]$Context)
    $r = Invoke-Native -Exe $Exe -Arguments $Arguments -Context $Context
    if ($r.Output.Count -ne 1) { throw "$Context returned $($r.Output.Count) lines; expected one." }
    return [string]$r.Output[0]
}

if ($env:OS -ne 'Windows_NT') { throw 'HA-1.6 production acceptance supports Windows only.' }
if (-not [Environment]::Is64BitProcess) { throw 'Run HA-1.6 production acceptance from 64-bit Windows PowerShell.' }
if ($Repository -notmatch '\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z') { throw "Invalid GitHub repository: $Repository" }
if ($ExpectedPrincipal -notmatch '\A[A-Za-z0-9][A-Za-z0-9@._+:-]*\z') { throw "Invalid expected principal: $ExpectedPrincipal" }
if ($ExpectedKeyFingerprint -notmatch '\ASHA256:[A-Za-z0-9+/]+={0,2}\z') { throw "Invalid expected key fingerprint: $ExpectedKeyFingerprint" }

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'Git was not found.' }
$git = $gitCommand.Source

$ghCommand = Get-Command gh.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $ghCommand) { $ghCommand = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $ghCommand) { throw 'GitHub CLI (gh) was not found.' }
$gh = $ghCommand.Source

$helloRepo = [IO.Path]::GetFullPath($HelloApprovalRepo)
if (-not (Test-Path -LiteralPath $helloRepo -PathType Container)) { throw "HelloApprovalRepo is missing: $helloRepo" }
$actualHead = Get-One -Exe $git -Arguments @('-C',$helloRepo,'rev-parse','HEAD') -Context 'Read hello-approval checkout HEAD'
$ancestor = Invoke-Native -Exe $git -Arguments @('-C',$helloRepo,'merge-base','--is-ancestor',$ExpectedHead,'HEAD') -Context 'Verify HA-1.6 reviewed commit ancestry' -AllowExitOne
if ($ancestor.ExitCode -ne 0) { throw "Reviewed HA-1.6 commit $ExpectedHead is not an ancestor of checkout HEAD $actualHead." }
$diff = Invoke-Native -Exe $git -Arguments @('-C',$helloRepo,'diff','--quiet',$ExpectedHead,'--',$ReviewedInput) -Context 'Compare reviewed HA-1.6 verifier input' -AllowExitOne
if ($diff.ExitCode -ne 0) { throw "Refusing acceptance: $ReviewedInput differs from reviewed commit $ExpectedHead." }
$verifier = Join-Path $helloRepo 'scripts\Test-HelloApprovalGitHubVerification.ps1'
if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) { throw "Verifier missing: $verifier" }

$stockSshKeygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
if (-not (Test-Path -LiteralPath $stockSshKeygen -PathType Leaf)) { throw "Stock OpenSSH verifier missing: $stockSshKeygen" }
$stockSshKeygenGit = $stockSshKeygen -replace '\\','/'

Write-Host '=== HA-1.6 production acceptance baseline ==='
Write-Host "checkout HEAD:        $actualHead"
Write-Host "reviewed HA-1.6:      $ExpectedHead"
Write-Host "repository:           $Repository"
Write-Host "expected principal:   $ExpectedPrincipal"
Write-Host "expected fingerprint: $ExpectedKeyFingerprint"
Write-Host "local verifier:       $stockSshKeygen"

if ($DevelopmentSkipPushProbe) {
    Write-Warning 'DEVELOPMENT ONLY: signing/push/GitHub verification skipped. Production acceptance is INCOMPLETE.'
    exit 3
}

$probeRoot = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-ha16-{0}' -f [Guid]::NewGuid().ToString('N'))
$remoteBranch = 'acceptance/ha16-z-' + [Guid]::NewGuid().ToString('N')
$remotePushed = $false
$cleanupFailure = $null
try {
    Write-Host '=== Preparing isolated acceptance clone ==='
    [void](Invoke-Native -Exe $gh -Arguments @('repo','clone',$Repository,$probeRoot,'--','--no-checkout') -Context 'Clone acceptance repository' -IncludeStderr)
    [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'checkout','--detach',$ExpectedHead) -Context 'Checkout exact HA-1.6 product HEAD')

    $authorRaw = Get-One -Exe $git -Arguments @('-C',$probeRoot,'var','GIT_AUTHOR_IDENT') -Context 'Read production author identity'
    $committerRaw = Get-One -Exe $git -Arguments @('-C',$probeRoot,'var','GIT_COMMITTER_IDENT') -Context 'Read production committer identity'
    Write-Host "author:    $authorRaw"
    Write-Host "committer: $committerRaw"

    $format = Get-One -Exe $git -Arguments @('-C',$probeRoot,'config','--includes','--get','gpg.format') -Context 'Read effective gpg.format'
    if ($format -cne 'ssh') { throw "Expected production gpg.format=ssh, got '$format'." }
    $program = Get-One -Exe $git -Arguments @('-C',$probeRoot,'config','--includes','--get','gpg.ssh.program') -Context 'Read effective gpg.ssh.program'
    $signingKey = Get-One -Exe $git -Arguments @('-C',$probeRoot,'config','--includes','--get','user.signingkey') -Context 'Read effective user.signingkey'
    $allowed = Get-One -Exe $git -Arguments @('-C',$probeRoot,'config','--includes','--path','--get','gpg.ssh.allowedSignersFile') -Context 'Read effective allowedSignersFile'
    Write-Host "signing program: $program"
    Write-Host "signing key:     $signingKey"
    Write-Host "allowed signers: $allowed"

    Write-Host '=== Real Windows Hello signing probe ==='
    Write-Host 'A Windows Hello prompt is expected now.'
    [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'commit','--allow-empty','-S','-m','hello-approval HA-1.6 GitHub verification acceptance') -Context 'Create real Windows Hello-backed acceptance commit' -IncludeStderr)
    $sha = Get-One -Exe $git -Arguments @('-C',$probeRoot,'rev-parse','HEAD') -Context 'Read signed acceptance commit SHA'
    Write-Host "signed commit: $sha"

    Write-Host '=== Independent local verification ==='
    [void](Invoke-Native -Exe $git -Arguments @('-c',"gpg.ssh.program=$stockSshKeygenGit",'-C',$probeRoot,'verify-commit',$sha) -Context 'Verify signed acceptance commit with stock OpenSSH' -IncludeStderr)
    $status = Get-One -Exe $git -Arguments @('-c',"gpg.ssh.program=$stockSshKeygenGit",'-C',$probeRoot,'log','-1','--format=%G?',$sha) -Context 'Read local signature status'
    $trust = Get-One -Exe $git -Arguments @('-c',"gpg.ssh.program=$stockSshKeygenGit",'-C',$probeRoot,'log','-1','--format=%GT',$sha) -Context 'Read local signature trust'
    $principal = Get-One -Exe $git -Arguments @('-c',"gpg.ssh.program=$stockSshKeygenGit",'-C',$probeRoot,'log','-1','--format=%GS',$sha) -Context 'Read local signer principal'
    $fingerprint = Get-One -Exe $git -Arguments @('-c',"gpg.ssh.program=$stockSshKeygenGit",'-C',$probeRoot,'log','-1','--format=%GK',$sha) -Context 'Read local signing fingerprint'
    if ($status -cne 'G') { throw "Local signature status '$status' != G." }
    if ($trust -cne 'fully') { throw "Local trust '$trust' != fully." }
    if ($principal -cne $ExpectedPrincipal) { throw "Local principal '$principal' != expected '$ExpectedPrincipal'." }
    if ($fingerprint -cne $ExpectedKeyFingerprint) { throw "Local fingerprint '$fingerprint' != expected '$ExpectedKeyFingerprint'." }
    Write-Host "local principal:   $principal"
    Write-Host "local fingerprint: $fingerprint"
    Write-Host 'Independent local verification: PASS'

    Write-Host '=== Push exact signed object to ephemeral branch ==='
    [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'push','origin',"HEAD:refs/heads/$remoteBranch") -Context "Push ephemeral acceptance branch $remoteBranch" -IncludeStderr)
    $remotePushed = $true
    Write-Host "remote branch: $remoteBranch"

    Write-Host '=== GitHub verification of exact SHA ==='
    $lastError = $null
    $remoteVerified = $false
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            & $verifier -Repository $Repository -Repo $probeRoot -Commit $sha
            $remoteVerified = $true
            break
        } catch {
            $lastError = $_
            if ($attempt -lt 6) { Start-Sleep -Seconds 1 }
        }
    }
    if (-not $remoteVerified) { throw $lastError }

    Write-Host 'HA-1.6 PRODUCTION ACCEPTANCE: PASS' -ForegroundColor Green
} finally {
    if ($remotePushed) {
        try {
            Write-Host '=== Removing ephemeral remote branch ==='
            [void](Invoke-Native -Exe $git -Arguments @('-C',$probeRoot,'push','origin','--delete',$remoteBranch) -Context "Delete ephemeral branch $remoteBranch" -IncludeStderr)
            Write-Host 'Remote branch cleanup: PASS'
        } catch {
            $cleanupFailure = $_
            Write-Warning "Remote branch cleanup failed: $($_.Exception.Message)"
        }
    }
    if (Test-Path -LiteralPath $probeRoot) { Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue }
    if ($null -ne $cleanupFailure) { throw $cleanupFailure }
}
