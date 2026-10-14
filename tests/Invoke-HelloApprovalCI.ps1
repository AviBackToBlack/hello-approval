#requires -Version 5.1
<#
.SYNOPSIS
    Unattended Windows PowerShell 5.1 acceptance runner used by CI.

.DESCRIPTION
    -Plan   validates that every tests\Test-HelloApproval*.ps1 harness is classified in the suite
            manifest below, then emits the CI-safe suites present on this baseline as a JSON matrix.
            An unclassified harness fails the plan, so a new suite can never be silently omitted.
    -Suite  runs exactly one manifest suite in its own Windows PowerShell 5.1 process. The suite
            passes only if the process exits 0 AND prints a RESULT line reporting failed=0.

    Every suite listed here was audited for unattended CI: it works on disposable temp fixtures
    (redirected LOCALAPPDATA/USERPROFILE/HOME, pinned GIT_CONFIG_GLOBAL/NOSYSTEM), uses -WhatIf or
    in-scope stubs for Scheduled Task operations, a dedicated test pipe instead of the signing pipe,
    and synthetic keys; none needs hardware presence or modifies real signing configuration.
#>
[CmdletBinding(DefaultParameterSetName = 'Plan')]
param(
    [Parameter(ParameterSetName = 'Plan', Mandatory = $true)]
    [switch]$Plan,

    [Parameter(ParameterSetName = 'Suite', Mandatory = $true)]
    [ValidatePattern('\ATest-HelloApproval[A-Za-z0-9]+\.ps1\z')]
    [string]$Suite
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$SuiteNamePattern = '\ATest-HelloApproval[A-Za-z0-9]+\.ps1\z'
$testsRoot = Join-Path $repoRoot 'tests'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

# Suite manifest. Every Test-HelloApproval*.ps1 harness must appear here. Entries whose file is not
# on the current baseline (suites added by open PRs) are reported as "not on this baseline" and
# start running automatically once they land.
$manifest = [ordered]@{
    'Test-HelloApprovalValidation.ps1'                 = 'Shared validation module contract; pure in-memory and temp-fixture checks.'
    'Test-HelloApprovalLauncherBundleContract.ps1'     = 'Launcher/module hash and bundle contract; reads repository files only.'
    'Test-HelloApprovalAgentLauncherValidation.ps1'    = 'Launcher against a csc-compiled synthetic agent on a dedicated test pipe; temp LOCALAPPDATA.'
    'Test-HelloApprovalPreflightValidation.ps1'        = 'Read-only preflight against temp fixtures.'
    'Test-HelloApprovalDoctorValidation.ps1'           = 'Read-only Doctor against temp fixtures; contract probes run installers with -WhatIf; isolated Git config.'
    'Test-HelloApprovalRuntimeInstaller.ps1'           = 'Synthetic archive installed into a temp LOCALAPPDATA.'
    'Test-HelloApprovalScheduledTaskInstaller.ps1'     = 'Installer with -WhatIf or in-scope Register/Unregister stubs; refuses to run if the real task exists.'
    'Test-HelloApprovalGitConfigInstaller.ps1'         = 'Writes only a fixture GIT_CONFIG_GLOBAL with GIT_CONFIG_NOSYSTEM=1 in temp fixtures.'
    'Test-HelloApprovalLocalVerificationInstaller.ps1' = 'Writes only fixture trust/config files with isolated Git config sources.'
    'Test-HelloApprovalLocalVerificationVerifier.ps1'  = 'Verifies commits signed with a throwaway ed25519 key generated in temp; isolated Git config sources.'
    'Test-HelloApprovalUninstallValidation.ps1'        = 'Uninstall with -WhatIf against temp fixtures and an isolated Git config.'
    'Test-HelloApprovalGitResolution.ps1'              = 'Git executable resolution with synthetic process-local PATH fixtures and temp profiles (PR #34).'
    'Test-HelloApprovalScheduledTaskUninstaller.ps1'   = 'Task uninstaller with in-scope ScheduledTasks stubs; refuses to run if the real task exists (PR #41).'
}

function Write-Summary([string[]]$Lines) {
    if (-not [string]::IsNullOrEmpty($env:GITHUB_STEP_SUMMARY)) {
        [IO.File]::AppendAllText($env:GITHUB_STEP_SUMMARY, (($Lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
    }
}

function Write-Output-Variable([string]$Name, [string]$Value) {
    if (-not [string]::IsNullOrEmpty($env:GITHUB_OUTPUT)) {
        [IO.File]::AppendAllText($env:GITHUB_OUTPUT, ("{0}={1}`n" -f $Name, $Value), (New-Object Text.UTF8Encoding($false)))
    }
}

$engine = $PSVersionTable.PSVersion
if ($engine.Major -ne 5 -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw "Acceptance must run on Windows PowerShell 5.1 (Desktop); got $($PSVersionTable.PSEdition) $engine."
}

if ($PSCmdlet.ParameterSetName -eq 'Plan') {
    $present = @(Get-ChildItem -LiteralPath $testsRoot -Filter 'Test-HelloApproval*.ps1' -File | ForEach-Object { $_.Name } | Sort-Object)
    $unclassified = @($present | Where-Object { -not $manifest.Contains($_) })
    # -Suite only accepts this name shape, so reject any other shape at plan time with a clear error.
    $badNames = @(@($manifest.Keys) + $present | Where-Object { $_ -notmatch $SuiteNamePattern } | Sort-Object -Unique)
    $runnable = @($manifest.Keys | Where-Object { $present -contains $_ })

    $summary = @('## Windows PowerShell 5.1 acceptance plan', '', ('Engine: Windows PowerShell {0} ({1})' -f $engine, $PSVersionTable.PSEdition), '', '| Suite | Status | CI safety basis |', '|---|---|---|')
    foreach ($name in $manifest.Keys) {
        $status = if ($present -contains $name) { 'runs' } else { 'not on this baseline' }
        $summary += ('| `{0}` | {1} | {2} |' -f $name, $status, $manifest[$name])
    }
    foreach ($name in $unclassified) { $summary += ('| `{0}` | **UNCLASSIFIED** | add it to tests/Invoke-HelloApprovalCI.ps1 after a CI-safety review |' -f $name) }
    Write-Summary $summary
    $summary | ForEach-Object { Write-Host $_ }

    if ($badNames.Count -gt 0) {
        Write-Host ("::error::Suite name(s) not matching {0}: {1}. Rename the harness or widen the pattern in both places." -f $SuiteNamePattern, ($badNames -join ', '))
        exit 1
    }
    if ($unclassified.Count -gt 0) {
        Write-Host ("::error::Unclassified test harness(es): {0}. Classify each in tests/Invoke-HelloApprovalCI.ps1." -f ($unclassified -join ', '))
        exit 1
    }
    if ($runnable.Count -eq 0) {
        Write-Host '::error::No runnable suites found.'
        exit 1
    }

    $json = ConvertTo-Json -InputObject @($runnable) -Compress
    Write-Output-Variable -Name 'suites' -Value $json
    Write-Host "suites=$json"
    exit 0
}

if (-not $manifest.Contains($Suite)) {
    throw "Suite is not in the CI manifest: $Suite"
}
$suitePath = Join-Path $testsRoot $Suite
if (-not (Test-Path -LiteralPath $suitePath -PathType Leaf)) {
    throw "Suite file is missing: $suitePath"
}

Write-Host ("Running {0} with Windows PowerShell {1}" -f $Suite, $engine)
$started = [DateTime]::UtcNow
$lines = New-Object System.Collections.Generic.List[string]
$saved = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    & $ps51 -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $suitePath 2>&1 | ForEach-Object {
        $line = [string]$_
        $lines.Add($line)
        Write-Host $line
    }
    $exitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $saved
}
$elapsed = [int]([DateTime]::UtcNow - $started).TotalSeconds

$resultLine = @($lines | Where-Object { $_ -match '^RESULT passed=\d+ failed=\d+' } | Select-Object -Last 1)
$passed = $null; $failed = $null; $skipped = 0
if ($resultLine.Count -eq 1) {
    $match = [regex]::Match($resultLine[0], '^RESULT passed=(?<p>\d+) failed=(?<f>\d+)(?: skipped=(?<s>\d+))?')
    $passed = [int]$match.Groups['p'].Value
    $failed = [int]$match.Groups['f'].Value
    if ($match.Groups['s'].Success) { $skipped = [int]$match.Groups['s'].Value }
}
$skipLines = @($lines | Where-Object { $_ -match '^SKIP\s' })
$failLines = @($lines | Where-Object { $_ -match '^FAIL\s' })
$skipped = [Math]::Max($skipped, $skipLines.Count)

$ok = ($exitCode -eq 0 -and $resultLine.Count -eq 1 -and $failed -eq 0)
$verdict = if ($ok) { 'PASS' } else { 'FAIL' }
$reason = if ($ok) { '' }
    elseif ($resultLine.Count -ne 1) { " (no RESULT line; exit $exitCode)" }
    elseif ($exitCode -ne 0) { " (exit $exitCode)" }
    else { '' }

$summary = @(
    ('### {0} `{1}`{2}' -f $verdict, $Suite, $reason),
    '',
    ('passed: {0} | failed: {1} | skipped: {2} | exit: {3} | {4}s' -f $(if ($null -eq $passed) { '?' } else { $passed }), $(if ($null -eq $failed) { '?' } else { $failed }), $skipped, $exitCode, $elapsed)
)
if ($skipLines.Count -gt 0) {
    $summary += ''
    $summary += 'Environmental skips (not passes):'
    $summary += ($skipLines | ForEach-Object { '- ' + $_ })
}
if ($failLines.Count -gt 0) {
    $summary += ''
    $summary += 'Failures:'
    $summary += ($failLines | ForEach-Object { '- ' + $(if ($_.Length -gt 400) { $_.Substring(0, 400) + '...' } else { $_ }) })
}
Write-Summary $summary

if (-not $ok) {
    Write-Host ("::error::{0} failed{1}" -f $Suite, $reason)
    exit 1
}
exit 0
