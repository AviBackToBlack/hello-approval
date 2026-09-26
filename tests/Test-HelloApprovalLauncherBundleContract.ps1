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

foreach ($name in @('Get-FileSha256','Assert-RealDirectory','Assert-LauncherCacheSurface')) {
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

    $launcherHash = Get-FileSha256 -Path $sourceLauncher
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

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-launcher-bundle-contract-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $v1 = New-CacheRoot -Root (Join-Path $root 'v1')
    [void](Add-LauncherDirectory -CacheRoot $v1)
    try {
        Assert-LauncherCacheSurface -LauncherRoot $v1
        Pass 'cleanup accepts legacy v1 one-file launcher cache'
    } catch {
        Fail 'cleanup accepts legacy v1 one-file launcher cache' $_.Exception.Message
    }

    $v2 = New-CacheRoot -Root (Join-Path $root 'v2')
    [void](Add-LauncherDirectory -CacheRoot $v2 -IncludeModule)
    try {
        Assert-LauncherCacheSurface -LauncherRoot $v2
        Pass 'cleanup accepts valid v2 launcher bundle'
    } catch {
        Fail 'cleanup accepts valid v2 launcher bundle' $_.Exception.Message
    }

    $tampered = New-CacheRoot -Root (Join-Path $root 'tampered')
    [void](Add-LauncherDirectory -CacheRoot $tampered -IncludeModule -TamperModule)
    try {
        Assert-LauncherCacheSurface -LauncherRoot $tampered
        Fail 'cleanup rejects tampered v2 validation module' 'expected throw'
    } catch {
        if ($_.Exception.Message -match 'validation module does not match launcher pin') {
            Pass 'cleanup rejects tampered v2 validation module'
        } else {
            Fail 'cleanup rejects tampered v2 validation module' $_.Exception.Message
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1}" -f $passed,$failed)
    if ($failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
