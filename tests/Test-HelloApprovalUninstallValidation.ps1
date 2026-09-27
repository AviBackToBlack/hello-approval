#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Test-HelloApprovalUninstallValidation.ps1 supports Windows only.' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceUninstall = Join-Path $repoRoot 'scripts\Uninstall-HelloApproval.ps1'
$sourceScheduledTaskUninstall = Join-Path $repoRoot 'scripts\Uninstall-HelloApprovalScheduledTask.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$script:Passed = 0
$script:Failed = 0
$script:FixtureJunctions = @()

function Pass([string]$Name) { $script:Passed++; Write-Host "PASS  $Name" }
function Fail([string]$Name,[string]$Message) { $script:Failed++; Write-Host "FAIL  $Name - $Message" }

function Get-FileSha256Local([string]$Path) {
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function New-Junction {
    param([string]$Link,[string]$Target)
    [void][IO.Directory]::CreateDirectory($Target)
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Link))
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = @(& cmd.exe /d /c mklink /J "$Link" "$Target" 2>&1 | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if($rc -ne 0){ throw "mklink failed: $($out -join ' | ')" }
    $script:FixtureJunctions += $Link
}

function Remove-FixtureJunctions {
    foreach($link in @($script:FixtureJunctions | Sort-Object Length -Descending)) {
        if(-not (Test-Path -LiteralPath $link)){ continue }
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & cmd.exe /d /c rmdir "$link" 2>$null | Out-Null
        } finally {
            $ErrorActionPreference = $saved
        }
    }
}

function New-Fixture {
    param(
        [string]$Root,
        [switch]$BinCaseMismatch,
        [switch]$FileCaseMismatch,
        [switch]$ProjectRootThroughJunction,
        [switch]$RuntimeParentThroughJunction,
        [switch]$LauncherAppThroughJunction,
        [switch]$GitRootThroughJunction,
        [switch]$IncludeOwnedGit,
        [switch]$MalformedUnusedName,
        [switch]$RuntimeMissing,
        [switch]$ValidationModuleMissing,
        [switch]$IncludeLauncher
    )

    $tool = Join-Path $Root 'tool'
    $scripts = Join-Path $tool 'scripts'
    $lib = Join-Path $tool 'lib'
    $prov = Join-Path $tool 'provenance'
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)
    [void][IO.Directory]::CreateDirectory($prov)
    Copy-Item -LiteralPath $sourceUninstall -Destination (Join-Path $scripts 'Uninstall-HelloApproval.ps1') -Force
    Copy-Item -LiteralPath $sourceScheduledTaskUninstall -Destination (Join-Path $scripts 'Uninstall-HelloApprovalScheduledTask.ps1') -Force
    if(-not $ValidationModuleMissing){
        Copy-Item -LiteralPath $sourceModule -Destination (Join-Path $lib 'HelloApproval.Validation.psm1') -Force
    }

    $local = Join-Path $Root 'local'
    $appData = Join-Path $Root 'roaming'
    $profile = Join-Path $Root 'profile'
    [void][IO.Directory]::CreateDirectory($local)
    [void][IO.Directory]::CreateDirectory($appData)
    [void][IO.Directory]::CreateDirectory($profile)

    $logicalProject = Join-Path $local 'hello-approval'
    if($ProjectRootThroughJunction){
        $projectTarget = Join-Path $Root 'project-redirect'
        New-Junction -Link $logicalProject -Target $projectTarget
        $physicalProject = $projectTarget
    } else {
        [void][IO.Directory]::CreateDirectory($logicalProject)
        $physicalProject = $logicalProject
    }

    if($RuntimeParentThroughJunction){
        $runtimeLogical = Join-Path $physicalProject 'runtime'
        $runtimeTarget = Join-Path $Root 'runtime-redirect'
        New-Junction -Link $runtimeLogical -Target $runtimeTarget
        $runtimeBasePhysical = Join-Path $runtimeTarget 'sshenc'
    } else {
        $runtimeBasePhysical = Join-Path (Join-Path $physicalProject 'runtime') 'sshenc'
    }

    $runtimeRoot = Join-Path $runtimeBasePhysical 'v-test'
    $binName = if($BinCaseMismatch){'Bin'}else{'bin'}
    $bin = Join-Path $runtimeRoot $binName
    [void][IO.Directory]::CreateDirectory($bin)

    $sshencName = if($FileCaseMismatch){'SSHENC.EXE'}else{'sshenc.exe'}
    $agentName = if($FileCaseMismatch){'SSHENC-AGENT.EXE'}else{'sshenc-agent.exe'}
    $sshenc = Join-Path $bin $sshencName
    $agent = Join-Path $bin $agentName
    [IO.File]::WriteAllBytes($sshenc,[byte[]](1,2,3,4,5))
    [IO.File]::WriteAllBytes($agent,[byte[]](6,7,8,9))

    $unusedName = if($MalformedUnusedName){'..\unused.exe'}else{'unused.exe'}
    $pin = [ordered]@{
        schema='hello-approval/upstream-pin/v1'
        upstream=[ordered]@{release_tag='v-test'}
        files=@(
            [ordered]@{
                name='sshenc.exe'
                size_bytes=[int64](Get-Item -LiteralPath $sshenc).Length
                sha256=Get-FileSha256Local -Path $sshenc
                policy=[ordered]@{disposition='required'}
            },
            [ordered]@{
                name='sshenc-agent.exe'
                size_bytes=[int64](Get-Item -LiteralPath $agent).Length
                sha256=Get-FileSha256Local -Path $agent
                policy=[ordered]@{disposition='required'}
            },
            [ordered]@{
                name=$unusedName
                size_bytes=[int64]0
                sha256=('0'*64)
                policy=[ordered]@{disposition='unused'}
            }
        )
        installation_policy=[ordered]@{
            target_architecture='x86_64-pc-windows-msvc'
            allowed_distribution='zip-manual-placement'
            installed_files=@('sshenc.exe','sshenc-agent.exe')
        }
    }
    [IO.File]::WriteAllText((Join-Path $prov 'sshenc-v0.6.101.json'),($pin|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))

    if($RuntimeMissing){ Remove-Item -LiteralPath $runtimeRoot -Recurse -Force }

    $launcherRoot = $null
    if($LauncherAppThroughJunction){
        $appLogical = Join-Path $physicalProject 'app'
        $appTarget = Join-Path $Root 'app-redirect'
        New-Junction -Link $appLogical -Target $appTarget
        $launcherRoot = Join-Path $appTarget 'launcher'
    } elseif($IncludeLauncher){
        $launcherRoot = Join-Path (Join-Path $physicalProject 'app') 'launcher'
    }

    if($IncludeLauncher){
        [void][IO.Directory]::CreateDirectory($launcherRoot)
        $launcherBytes = [Text.Encoding]::UTF8.GetBytes("Write-Host 'synthetic launcher'`r`n")
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $launcherHash = ([BitConverter]::ToString($sha.ComputeHash($launcherBytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
        $digestDir = Join-Path $launcherRoot $launcherHash
        [void][IO.Directory]::CreateDirectory($digestDir)
        [IO.File]::WriteAllBytes((Join-Path $digestDir 'Start-HelloApprovalAgent.ps1'),$launcherBytes)
    }


    $gitRootPhysical = $null
    if($GitRootThroughJunction){
        $gitLogical = Join-Path $physicalProject 'git'
        $gitTarget = Join-Path $Root 'git-redirect'
        New-Junction -Link $gitLogical -Target $gitTarget
        $gitRootPhysical = $gitTarget
    } elseif($IncludeOwnedGit){
        $gitRootPhysical = Join-Path $physicalProject 'git'
        [void][IO.Directory]::CreateDirectory($gitRootPhysical)
    }

    if($IncludeOwnedGit){
        $signingText = "[hello-approval]`r`n`tschema = hello-approval/ha-1.4/v1`r`n"
        $verificationText = "[hello-approval]`r`n`tschema = hello-approval/ha-1.5/v1`r`n"
        [IO.File]::WriteAllText((Join-Path $gitRootPhysical 'signing.gitconfig'),$signingText,[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $gitRootPhysical 'verification.gitconfig'),$verificationText,[Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $gitRootPhysical 'allowed_signers'),"# hello-approval/ha-1.5/v1`r`n",[Text.UTF8Encoding]::new($false))
    }

    $globalGit = Join-Path $Root 'global.gitconfig'
    [IO.File]::WriteAllText($globalGit,'',[Text.UTF8Encoding]::new($false))

    return [pscustomobject]@{
        Uninstall=Join-Path $scripts 'Uninstall-HelloApproval.ps1'
        LocalAppData=$local
        AppData=$appData
        UserProfile=$profile
        GlobalGit=$globalGit
    }
}

function Invoke-UninstallWhatIf {
    param(
        $Fixture,
        [switch]$RemoveRuntime,
        [switch]$RemoveLauncherCache
    )

    $names = @('LOCALAPPDATA','APPDATA','USERPROFILE','HOME','GIT_CONFIG_GLOBAL','GIT_CONFIG_NOSYSTEM')
    $old = @{}
    foreach($name in $names){ $old[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
    try {
        $env:LOCALAPPDATA = $Fixture.LocalAppData
        $env:APPDATA = $Fixture.AppData
        $env:USERPROFILE = $Fixture.UserProfile
        $env:HOME = $Fixture.UserProfile
        $env:GIT_CONFIG_GLOBAL = $Fixture.GlobalGit
        $env:GIT_CONFIG_NOSYSTEM = '1'

        $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$Fixture.Uninstall,'-WhatIf')
        if($RemoveRuntime){ $args += '-RemoveRuntime' }
        if($RemoveLauncherCache){ $args += '-RemoveLauncherCache' }

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $out = @(& $ps51 @args 2>&1 | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }
        return [pscustomobject]@{ExitCode=$rc;Output=@($out)}
    } finally {
        foreach($name in $names){
            if($null -eq $old[$name]){ Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
            else { [Environment]::SetEnvironmentVariable($name,[string]$old[$name],'Process') }
        }
    }
}

function Describe-Result($Result) {
    return "rc=$($Result.ExitCode) output=$($Result.Output -join ' | ')"
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-uninstall-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $cases = @(
        [pscustomobject]@{Name='exact owned Git/trust files';Args=@{IncludeOwnedGit=$true};Mode='default';Kind='accept'},
        [pscustomobject]@{Name='owned Git directory junction';Args=@{IncludeOwnedGit=$true;GitRootThroughJunction=$true};Mode='default';Kind='ancestry-delta'},
        [pscustomobject]@{Name='absent owned Git files below project-root junction';Args=@{ProjectRootThroughJunction=$true};Mode='default';Kind='ancestry-delta'},
        [pscustomobject]@{Name='absent owned Git files at Git-directory junction';Args=@{GitRootThroughJunction=$true};Mode='default';Kind='ancestry-delta'},
        [pscustomobject]@{Name='exact runtime';Args=@{};Mode='runtime';Kind='accept'},
        [pscustomobject]@{Name='missing runtime';Args=@{RuntimeMissing=$true};Mode='runtime';Kind='accept'},
        [pscustomobject]@{Name='missing validation module';Args=@{ValidationModuleMissing=$true};Mode='runtime';Kind='module-migration'},
        [pscustomobject]@{Name='Bin case-only directory mismatch';Args=@{BinCaseMismatch=$true};Mode='runtime';Kind='reject'},
        [pscustomobject]@{Name='runtime file case-only mismatch';Args=@{FileCaseMismatch=$true};Mode='runtime';Kind='reject'},
        [pscustomobject]@{Name='hello-approval project-root junction';Args=@{ProjectRootThroughJunction=$true};Mode='runtime';Kind='ancestry-delta'},
        [pscustomobject]@{Name='runtime parent junction';Args=@{RuntimeParentThroughJunction=$true};Mode='runtime';Kind='ancestry-delta'},
        [pscustomobject]@{Name='missing runtime below runtime-parent junction';Args=@{RuntimeParentThroughJunction=$true;RuntimeMissing=$true};Mode='runtime';Kind='ancestry-delta'},
        [pscustomobject]@{Name='malformed unused pin leaf name';Args=@{MalformedUnusedName=$true};Mode='runtime';Kind='pin-delta'},
        [pscustomobject]@{Name='exact launcher cache';Args=@{IncludeLauncher=$true};Mode='launcher';Kind='accept'},
        [pscustomobject]@{Name='launcher app-directory junction';Args=@{IncludeLauncher=$true;LauncherAppThroughJunction=$true};Mode='launcher';Kind='ancestry-delta'},
        [pscustomobject]@{Name='missing launcher below app-directory junction';Args=@{LauncherAppThroughJunction=$true};Mode='launcher';Kind='ancestry-delta'}
    )

    foreach($case in $cases){
        $fixtureRoot = Join-Path $root ($case.Name -replace '[^A-Za-z0-9]+','-')
        $fixtureArgs = $case.Args
        $fixture = New-Fixture -Root $fixtureRoot @fixtureArgs
        if($case.Mode -eq 'runtime'){
            $result = Invoke-UninstallWhatIf -Fixture $fixture -RemoveRuntime
        } elseif($case.Mode -eq 'launcher') {
            $result = Invoke-UninstallWhatIf -Fixture $fixture -RemoveLauncherCache
        } else {
            $result = Invoke-UninstallWhatIf -Fixture $fixture
        }

        switch($case.Kind){
            'accept' {
                if($result.ExitCode -eq 0){ Pass "$($case.Name) remains accepted under -WhatIf" }
                else { Fail "$($case.Name) remains accepted under -WhatIf" (Describe-Result $result) }
            }
            'reject' {
                if($result.ExitCode -ne 0){ Pass "$($case.Name) remains rejected before mutation" }
                else { Fail "$($case.Name) remains rejected before mutation" 'expected non-zero exit' }
            }
            'module-migration' {
                if($ExpectedPhase1){
                    if($result.ExitCode -eq 0){ Pass 'Phase1 uninstall does not require shared validation module' }
                    else { Fail 'Phase1 uninstall does not require shared validation module' (Describe-Result $result) }
                } else {
                    if($result.ExitCode -ne 0){ Pass 'hardened uninstall requires shared validation module before mutation' }
                    else { Fail 'hardened uninstall requires shared validation module before mutation' 'expected non-zero exit' }
                }
            }
            'ancestry-delta' {
                if($ExpectedPhase1){
                    if($result.ExitCode -eq 0){ Pass "Phase1 uninstall accepts $($case.Name)" }
                    else { Fail "Phase1 uninstall accepts $($case.Name)" (Describe-Result $result) }
                } else {
                    if($result.ExitCode -ne 0){ Pass "hardened uninstall rejects $($case.Name) before mutation" }
                    else { Fail "hardened uninstall rejects $($case.Name) before mutation" 'expected non-zero exit' }
                }
            }
            'pin-delta' {
                if($ExpectedPhase1){
                    if($result.ExitCode -eq 0){ Pass 'Phase1 uninstall accepts malformed unused pin leaf name' }
                    else { Fail 'Phase1 uninstall accepts malformed unused pin leaf name' (Describe-Result $result) }
                } else {
                    if($result.ExitCode -ne 0){ Pass 'hardened uninstall rejects malformed unused pin leaf name before mutation' }
                    else { Fail 'hardened uninstall rejects malformed unused pin leaf name before mutation' 'expected non-zero exit' }
                }
            }
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if($script:Failed -ne 0){ exit 1 }
    exit 0
} finally {
    Remove-FixtureJunctions
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
