#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalLauncherBundleContract.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$cleanupScript = Join-Path $repoRoot 'scripts\Uninstall-HelloApproval.ps1'
$sourceLauncher = Join-Path $repoRoot 'scripts\Start-HelloApprovalAgent.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
Import-Module $sourceModule -Force -ErrorAction Stop

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $cleanupScript,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -ne 0) {
    throw "Cleanup parser errors: $($errors -join ' | ')"
}

foreach ($name in @('Assert-LauncherCacheSurface')) {
    $node = $ast.Find({
        param($candidate)
        $candidate -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $candidate.Name -ceq $name
    }, $true)
    if ($null -eq $node) {
        throw "Could not extract production function: $name"
    }
    Invoke-Expression $node.Extent.Text
}

$passed = 0
$failed = 0

function Pass([string]$Name) {
    $script:passed++
    Write-Host "PASS  $Name"
}

function Fail([string]$Name,[string]$Message) {
    $script:failed++
    Write-Host "FAIL  $Name - $Message"
}

function New-CacheRoot {
    param([string]$Root)
    $cache = Join-Path $Root 'launcher'
    [void][IO.Directory]::CreateDirectory($cache)
    return $cache
}

function Add-LauncherDirectory {
    param(
        [string]$CacheRoot,
        [switch]$IncludeModule,
        [switch]$TamperModule
    )

    $launcherHash = Get-HelloApprovalFileSha256 -Path $sourceLauncher
    $dir = Join-Path $CacheRoot $launcherHash
    [void][IO.Directory]::CreateDirectory($dir)

    Copy-Item -LiteralPath $sourceLauncher -Destination (Join-Path $dir 'Start-HelloApprovalAgent.ps1')
    if ($IncludeModule) {
        $modulePath = Join-Path $dir 'HelloApproval.Validation.psm1'
        Copy-Item -LiteralPath $sourceModule -Destination $modulePath
        if ($TamperModule) {
            [IO.File]::AppendAllText($modulePath,[Environment]::NewLine + '# tampered')
        }
    }

    return $dir
}

function Add-PreviousGenerationDirectory {
    # An earlier bundle generation: different module bytes and a launcher whose single pin names them.
    param([string]$CacheRoot)

    $utf8 = [Text.UTF8Encoding]::new($false)
    $stage = Join-Path (Split-Path -Parent $CacheRoot) 'previous-generation'
    [void][IO.Directory]::CreateDirectory($stage)
    $module = Join-Path $stage 'HelloApproval.Validation.psm1'
    [IO.File]::WriteAllText($module, ([IO.File]::ReadAllText($sourceModule) + "# previous-generation bundle test fixture`n"), $utf8)
    $pinPattern = "(?m)^\`$ValidationModuleSha256 = '[a-f0-9]{64}'$"
    $launcherText = [IO.File]::ReadAllText($sourceLauncher)
    if ([regex]::Matches($launcherText, $pinPattern).Count -ne 1) { throw 'Launcher must contain exactly one validation-module pin.' }
    $launcher = Join-Path $stage 'Start-HelloApprovalAgent.ps1'
    [IO.File]::WriteAllText($launcher, [regex]::Replace($launcherText, $pinPattern, ("`$ValidationModuleSha256 = '{0}'" -f (Get-HelloApprovalFileSha256 -Path $module))), $utf8)

    $dir = Join-Path $CacheRoot (Get-HelloApprovalFileSha256 -Path $launcher)
    [void][IO.Directory]::CreateDirectory($dir)
    Copy-Item -LiteralPath $launcher -Destination (Join-Path $dir 'Start-HelloApprovalAgent.ps1')
    Copy-Item -LiteralPath $module -Destination (Join-Path $dir 'HelloApproval.Validation.psm1')
    return $dir
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-launcher-bundle-contract-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $v1 = New-CacheRoot -Root (Join-Path $root 'v1')
    [void](Add-LauncherDirectory -CacheRoot $v1)
    try {
        Assert-LauncherCacheSurface -LauncherRoot $v1 -TrustedBase $root
        Pass 'cleanup accepts legacy v1 one-file launcher cache'
    } catch {
        Fail 'cleanup accepts legacy v1 one-file launcher cache' $_.Exception.Message
    }

    $v2 = New-CacheRoot -Root (Join-Path $root 'v2')
    [void](Add-LauncherDirectory -CacheRoot $v2 -IncludeModule)
    try {
        Assert-LauncherCacheSurface -LauncherRoot $v2 -TrustedBase $root
        Pass 'cleanup accepts valid v2 launcher bundle'
    } catch {
        Fail 'cleanup accepts valid v2 launcher bundle' $_.Exception.Message
    }

    $tampered = New-CacheRoot -Root (Join-Path $root 'tampered')
    [void](Add-LauncherDirectory -CacheRoot $tampered -IncludeModule -TamperModule)
    try {
        Assert-LauncherCacheSurface -LauncherRoot $tampered -TrustedBase $root
        Fail 'cleanup rejects tampered v2 validation module' 'expected throw'
    } catch {
        if ($_.Exception.Message -match 'validation module does not match launcher pin') {
            Pass 'cleanup rejects tampered v2 validation module'
        } else {
            Fail 'cleanup rejects tampered v2 validation module' $_.Exception.Message
        }
    }

    # The repository launcher pins exactly the committed validation-module bytes.
    $pinMatches = [regex]::Matches([IO.File]::ReadAllText($sourceLauncher), "(?m)^\`$ValidationModuleSha256 = '([a-f0-9]{64})'$")
    $moduleHash = Get-HelloApprovalFileSha256 -Path $sourceModule
    if ($pinMatches.Count -eq 1 -and $pinMatches[0].Groups[1].Value -ceq $moduleHash) {
        Pass 'repository launcher pins the current validation-module SHA-256'
    } else {
        Fail 'repository launcher pins the current validation-module SHA-256' ("pins={0} module={1}" -f $pinMatches.Count,$moduleHash)
    }

    # Upgrades retain earlier digest directories for rollback; cleanup must accept a cache holding
    # several valid generations and still refuse a tampered retained one.
    $generations = New-CacheRoot -Root (Join-Path $root 'generations')
    [void](Add-LauncherDirectory -CacheRoot $generations -IncludeModule)
    $previousDir = Add-PreviousGenerationDirectory -CacheRoot $generations
    try {
        Assert-LauncherCacheSurface -LauncherRoot $generations -TrustedBase $root
        Pass 'cleanup accepts current and retained previous-generation bundles together'
    } catch {
        Fail 'cleanup accepts current and retained previous-generation bundles together' $_.Exception.Message
    }

    [IO.File]::AppendAllText((Join-Path $previousDir 'HelloApproval.Validation.psm1'), "# tampered`n")
    try {
        Assert-LauncherCacheSurface -LauncherRoot $generations -TrustedBase $root
        Fail 'cleanup rejects a tampered retained previous-generation bundle' 'expected throw'
    } catch {
        if ($_.Exception.Message -match 'validation module does not match launcher pin') {
            Pass 'cleanup rejects a tampered retained previous-generation bundle'
        } else {
            Fail 'cleanup rejects a tampered retained previous-generation bundle' $_.Exception.Message
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1}" -f $passed,$failed)
    if ($failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
