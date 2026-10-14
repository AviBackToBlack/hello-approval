#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Test-HelloApprovalGitResolution.ps1 supports Windows only.' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$scriptNames = @(
    'Install-HelloApprovalGitConfig.ps1',
    'Install-HelloApprovalLocalVerification.ps1',
    'Test-HelloApprovalDoctor.ps1',
    'Test-HelloApprovalGitHubVerification.ps1',
    'Test-HelloApprovalLocalVerification.ps1',
    'Test-HelloApprovalPreflight.ps1',
    'Uninstall-HelloApproval.ps1'
)

$script:Passed = 0
$script:Failed = 0
function Pass([string]$Name) { $script:Passed++; Write-Host "PASS  $Name" }
function Fail([string]$Name,[string]$Message) { $script:Failed++; Write-Host "FAIL  $Name - $Message" }

$helperPattern = '(?s)function Resolve-HelloApprovalGitExecutable \{.*?\n\}'
$noGitPath = (@(
    (Join-Path $env:SystemRoot 'System32'),
    $env:SystemRoot,
    (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0')
) -join ';')

function Invoke-WithPath {
    param(
        [Parameter(Mandatory = $true)][string]$PathValue,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [hashtable]$Environment = @{}
    )

    $names = @('PATH') + @($Environment.Keys)
    $old = @{}
    foreach ($name in $names) { $old[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
    try {
        [Environment]::SetEnvironmentVariable('PATH', $PathValue, 'Process')
        foreach ($name in $Environment.Keys) { [Environment]::SetEnvironmentVariable($name, [string]$Environment[$name], 'Process') }
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $ps51 @Arguments 2>&1 | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }
        return [pscustomobject]@{ ExitCode = $rc; Output = $output }
    } finally {
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $old[$name], 'Process') }
    }
}

function Get-JsonFinding($Result, [string]$Check) {
    $json = ($Result.Output -join [Environment]::NewLine) | ConvertFrom-Json
    return @($json.findings | Where-Object { $_.check -eq $Check })
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-git-resolution-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    # Static contract: one shared-shape helper per caller, resolved exactly once, never re-resolved by bare name.
    $helperBodies = @{}
    foreach ($name in $scriptNames) {
        $text = [IO.File]::ReadAllText((Join-Path $repoRoot "scripts\$name"))
        $helpers = [regex]::Matches($text, $helperPattern)
        $calls = [regex]::Matches($text, '(?m)^[^#\r\n]*=\s*Resolve-HelloApprovalGitExecutable\s*$')
        $outsideHelper = $text
        if ($helpers.Count -eq 1) { $outsideHelper = $text.Remove($helpers[0].Index, $helpers[0].Length) }
        $strayLookups = [regex]::Matches($outsideHelper, '(?i)Get-Command\s+[''"]?git')
        $bareInvocations = [regex]::Matches($outsideHelper, '(?im)(^\s*|&\s*)[''"]?git(\.exe)?[''"]?\s+(config|rev-parse|verify-commit|log|cat-file|-C|-c)\b')
        if ($helpers.Count -eq 1 -and $calls.Count -eq 1 -and $strayLookups.Count -eq 0 -and $bareInvocations.Count -eq 0) {
            Pass "$name resolves Git once through the first-on-PATH helper"
            $helperBodies[$name] = $helpers[0].Value
        } else {
            Fail "$name resolves Git once through the first-on-PATH helper" ("helpers={0} calls={1} strayLookups={2} bareInvocations={3}" -f $helpers.Count, $calls.Count, $strayLookups.Count, $bareInvocations.Count)
        }
    }
    $distinctBodies = @($helperBodies.Values | Sort-Object -Unique)
    if ($helperBodies.Count -eq $scriptNames.Count -and $distinctBodies.Count -eq 1) {
        Pass 'every caller carries a byte-identical Git resolution helper'
    } else {
        Fail 'every caller carries a byte-identical Git resolution helper' ("helpers={0} distinct={1}" -f $helperBodies.Count, $distinctBodies.Count)
    }

    # Unit contract under synthetic process-local PATH fixtures (Get-Command only resolves, never executes).
    $dirA = Join-Path $root 'git-a'
    $dirB = Join-Path $root 'git-b'
    foreach ($dir in @($dirA, $dirB)) {
        [void][IO.Directory]::CreateDirectory($dir)
        Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\where.exe') -Destination (Join-Path $dir 'git.exe') -Force
    }
    $gitA = Join-Path $dirA 'git.exe'
    $gitB = Join-Path $dirB 'git.exe'
    $unitCases = @(
        [pscustomobject]@{ Name = 'single Git'; Path = "$dirA;$noGitPath"; Expected = $gitA },
        [pscustomobject]@{ Name = 'two Gits, A first'; Path = "$dirA;$dirB;$noGitPath"; Expected = $gitA },
        [pscustomobject]@{ Name = 'two Gits, B first (reversed)'; Path = "$dirB;$dirA;$noGitPath"; Expected = $gitB },
        [pscustomobject]@{ Name = 'no Git'; Path = $noGitPath; Expected = '<null>' }
    )
    foreach ($name in $scriptNames) {
        if (-not $helperBodies.ContainsKey($name)) { continue }
        $probe = Join-Path $root ('probe-' + ($name -replace '\.ps1$', '') + '.ps1')
        $probeText = "Set-StrictMode -Version 2.0`n" + $helperBodies[$name] + "`n`$r = Resolve-HelloApprovalGitExecutable`nif (`$null -eq `$r) { '<null>' } else { `$r }`n"
        [IO.File]::WriteAllText($probe, $probeText, [Text.UTF8Encoding]::new($false))
        foreach ($case in $unitCases) {
            $result = Invoke-WithPath -PathValue $case.Path -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $probe)
            $actual = ($result.Output -join '|')
            if ($result.ExitCode -eq 0 -and $actual -ceq $case.Expected) {
                Pass "$name helper selects expected Git for $($case.Name)"
            } else {
                Fail "$name helper selects expected Git for $($case.Name)" ("rc={0} expected={1} actual={2}" -f $result.ExitCode, $case.Expected, $actual)
            }
        }
    }

    # End-to-end with the host's actual Git installations, in both PATH orders.
    $realGits = @(Get-Command git.exe -CommandType Application -All -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Source } | Select-Object -Unique)
    if ($realGits.Count -lt 2) {
        Write-Host "SKIP  real multi-Git end-to-end checks need at least two git.exe on PATH; found $($realGits.Count)"
    } else {
        $realDirs = @($realGits[0], $realGits[1] | ForEach-Object { Split-Path -Parent $_ })
        $local = Join-Path $root 'local'
        $app = Join-Path $root 'roaming'
        $profileDir = Join-Path $root 'profile'
        foreach ($dir in @($local, $app, $profileDir)) { [void][IO.Directory]::CreateDirectory($dir) }
        $isolated = @{
            LOCALAPPDATA = $local; APPDATA = $app; USERPROFILE = $profileDir; HOME = $profileDir
            GIT_CONFIG_GLOBAL = (Join-Path $root 'global.gitconfig'); GIT_CONFIG_NOSYSTEM = '1'
        }
        $orders = @(
            [pscustomobject]@{ Name = 'host order'; Path = "$($realDirs[0]);$($realDirs[1]);$noGitPath"; Expected = $realGits[0] },
            [pscustomobject]@{ Name = 'reversed order'; Path = "$($realDirs[1]);$($realDirs[0]);$noGitPath"; Expected = $realGits[1] }
        )
        foreach ($order in $orders) {
            foreach ($target in @('Test-HelloApprovalPreflight.ps1', 'Test-HelloApprovalDoctor.ps1')) {
                $result = Invoke-WithPath -PathValue $order.Path -Environment $isolated -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repoRoot "scripts\$target"), '-Json')
                $label = "$target reports the first real Git on PATH ($($order.Name))"
                try {
                    $present = @(Get-JsonFinding $result 'git.present')
                    $internal = @(Get-JsonFinding $result 'doctor.internal')
                    $bindingErrors = @($result.Output | Where-Object { $_ -match 'Cannot process argument transformation' })
                    if ($present.Count -eq 1 -and $present[0].severity -eq 'PASS' -and [string]$present[0].value -ceq $order.Expected -and $internal.Count -eq 0 -and $bindingErrors.Count -eq 0) {
                        Pass $label
                    } else {
                        Fail $label ("present={0} internal={1} bindingErrors={2}" -f (($present | ConvertTo-Json -Compress -Depth 4) -join ''), $internal.Count, $bindingErrors.Count)
                    }
                } catch {
                    Fail $label ("unparseable output rc={0}: {1}" -f $result.ExitCode, ($result.Output -join ' | '))
                }
            }
        }
    }

    # No usable Git keeps each caller's existing contract.
    $noGitEnvironment = @{
        LOCALAPPDATA = (Join-Path $root 'nogit-local'); APPDATA = (Join-Path $root 'nogit-roaming')
        USERPROFILE = (Join-Path $root 'nogit-profile'); HOME = (Join-Path $root 'nogit-profile')
        GIT_CONFIG_GLOBAL = (Join-Path $root 'nogit.gitconfig'); GIT_CONFIG_NOSYSTEM = '1'
    }
    foreach ($dir in @($noGitEnvironment.LOCALAPPDATA, $noGitEnvironment.APPDATA, $noGitEnvironment.USERPROFILE)) { [void][IO.Directory]::CreateDirectory($dir) }

    $preflight = Invoke-WithPath -PathValue $noGitPath -Environment $noGitEnvironment -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repoRoot 'scripts\Test-HelloApprovalPreflight.ps1'), '-Json')
    $preflightPresent = @(Get-JsonFinding $preflight 'git.present')
    if ($preflightPresent.Count -eq 1 -and $preflightPresent[0].severity -eq 'WARN') { Pass 'Preflight keeps WARN git.present without Git' }
    else { Fail 'Preflight keeps WARN git.present without Git' (($preflightPresent | ConvertTo-Json -Compress -Depth 4) -join '') }

    $doctor = Invoke-WithPath -PathValue $noGitPath -Environment $noGitEnvironment -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repoRoot 'scripts\Test-HelloApprovalDoctor.ps1'), '-Json')
    $doctorPresent = @(Get-JsonFinding $doctor 'git.present')
    if ($doctor.ExitCode -eq 2 -and $doctorPresent.Count -eq 1 -and $doctorPresent[0].severity -eq 'BLOCK') { Pass 'Doctor keeps BLOCK git.present without Git' }
    else { Fail 'Doctor keeps BLOCK git.present without Git' ("rc={0} present={1}" -f $doctor.ExitCode, (($doctorPresent | ConvertTo-Json -Compress -Depth 4) -join '')) }

    $installer = Invoke-WithPath -PathValue $noGitPath -Environment $noGitEnvironment -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repoRoot 'scripts\Install-HelloApprovalGitConfig.ps1'), '-WhatIf')
    if ($installer.ExitCode -ne 0 -and (($installer.Output -join ' ') -match 'Git was not found in PATH')) { Pass 'Git config installer keeps its no-Git refusal' }
    else { Fail 'Git config installer keeps its no-Git refusal' ("rc={0} output={1}" -f $installer.ExitCode, ($installer.Output -join ' | ')) }

    $uninstall = Invoke-WithPath -PathValue $noGitPath -Environment $noGitEnvironment -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repoRoot 'scripts\Uninstall-HelloApproval.ps1'), '-WhatIf')
    if ($uninstall.ExitCode -ne 0 -and (($uninstall.Output -join ' ') -match 'Git executable is required for conservative Git cleanup')) { Pass 'Uninstall keeps its no-Git refusal' }
    else { Fail 'Uninstall keeps its no-Git refusal' ("rc={0} output={1}" -f $uninstall.ExitCode, ($uninstall.Output -join ' | ')) }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1}" -f $script:Passed, $script:Failed)
    if ($script:Failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
