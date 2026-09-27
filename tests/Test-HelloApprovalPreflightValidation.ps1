#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Test-HelloApprovalPreflightValidation.ps1 supports Windows only.' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourcePreflight = Join-Path $repoRoot 'scripts\Test-HelloApprovalPreflight.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$script:Passed = 0
$script:Failed = 0

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
    $saved=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $out=@(& cmd.exe /d /c mklink /J "$Link" "$Target" 2>&1 | ForEach-Object {[string]$_})
        $rc=$LASTEXITCODE
    } finally { $ErrorActionPreference=$saved }
    if($rc -ne 0){throw "mklink failed: $($out -join ' | ')"}
}

function New-Fixture {
    param(
        [string]$Root,
        [switch]$BinCaseMismatch,
        [switch]$FileCaseMismatch,
        [switch]$ProjectRootThroughJunction,
        [switch]$MalformedUnusedName
    )

    $tool=Join-Path $Root 'tool'
    $scripts=Join-Path $tool 'scripts'
    $lib=Join-Path $tool 'lib'
    $prov=Join-Path $tool 'provenance'
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)
    [void][IO.Directory]::CreateDirectory($prov)
    Copy-Item $sourcePreflight (Join-Path $scripts 'Test-HelloApprovalPreflight.ps1') -Force
    Copy-Item $sourceModule (Join-Path $lib 'HelloApproval.Validation.psm1') -Force

    $local=Join-Path $Root 'local'
    $app=Join-Path $Root 'roaming'
    $profile=Join-Path $Root 'profile'
    [void][IO.Directory]::CreateDirectory($local)
    [void][IO.Directory]::CreateDirectory($app)
    [void][IO.Directory]::CreateDirectory($profile)

    $logicalProject=Join-Path $local 'hello-approval'
    if($ProjectRootThroughJunction){
        $projectTarget=Join-Path $Root 'project-redirect'
        New-Junction -Link $logicalProject -Target $projectTarget
        $physicalProject=$projectTarget
    } else {
        [void][IO.Directory]::CreateDirectory($logicalProject)
        $physicalProject=$logicalProject
    }

    $runtimeBase=Join-Path (Join-Path $physicalProject 'runtime') 'sshenc'
    $runtimeRoot=Join-Path $runtimeBase 'v-test'
    $binName=if($BinCaseMismatch){'Bin'}else{'bin'}
    $bin=Join-Path $runtimeRoot $binName
    [void][IO.Directory]::CreateDirectory($bin)

    $sshencName=if($FileCaseMismatch){'SSHENC.EXE'}else{'sshenc.exe'}
    $agentName=if($FileCaseMismatch){'SSHENC-AGENT.EXE'}else{'sshenc-agent.exe'}
    $sshenc=Join-Path $bin $sshencName
    $agent=Join-Path $bin $agentName
    [IO.File]::WriteAllBytes($sshenc,[byte[]](1,2,3,4,5))
    [IO.File]::WriteAllBytes($agent,[byte[]](9,8,7,6))

    $unusedName=if($MalformedUnusedName){'..\unused.exe'}else{'unused.exe'}
    $pin=[ordered]@{
        schema='hello-approval/upstream-pin/v1'
        upstream=[ordered]@{release_tag='v-test'}
        files=@(
            [ordered]@{
                name='sshenc.exe'
                size_bytes=[int64](Get-Item $sshenc).Length
                sha256=Get-FileSha256Local $sshenc
                policy=[ordered]@{disposition='required'}
            },
            [ordered]@{
                name='sshenc-agent.exe'
                size_bytes=[int64](Get-Item $agent).Length
                sha256=Get-FileSha256Local $agent
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

    return [pscustomobject]@{
        Preflight=Join-Path $scripts 'Test-HelloApprovalPreflight.ps1'
        LocalAppData=$local
        AppData=$app
        UserProfile=$profile
    }
}

function Invoke-Preflight {
    param($Fixture)

    $oldLocal=$env:LOCALAPPDATA
    $oldApp=$env:APPDATA
    $oldProfile=$env:USERPROFILE
    $oldHome=$env:HOME
    $oldSocket=$env:SSHENC_AGENT_SOCKET
    $oldAuth=$env:SSH_AUTH_SOCK
    $oldGitSsh=$env:GIT_SSH_COMMAND
    try {
        $env:LOCALAPPDATA=$Fixture.LocalAppData
        $env:APPDATA=$Fixture.AppData
        $env:USERPROFILE=$Fixture.UserProfile
        $env:HOME=$Fixture.UserProfile
        Remove-Item Env:SSHENC_AGENT_SOCKET -ErrorAction SilentlyContinue
        Remove-Item Env:SSH_AUTH_SOCK -ErrorAction SilentlyContinue
        Remove-Item Env:GIT_SSH_COMMAND -ErrorAction SilentlyContinue

        $saved=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $out=@(& $ps51 -NoProfile -ExecutionPolicy Bypass -File $Fixture.Preflight -Json 2>$null | ForEach-Object {[string]$_})
            $rc=$LASTEXITCODE
        } finally {$ErrorActionPreference=$saved}

        $json=($out -join [Environment]::NewLine) | ConvertFrom-Json
        return [pscustomobject]@{ExitCode=$rc;Json=$json;Raw=@($out)}
    } finally {
        $env:LOCALAPPDATA=$oldLocal
        $env:APPDATA=$oldApp
        $env:USERPROFILE=$oldProfile
        if($null -eq $oldHome){Remove-Item Env:HOME -ErrorAction SilentlyContinue}else{$env:HOME=$oldHome}
        if($null -eq $oldSocket){Remove-Item Env:SSHENC_AGENT_SOCKET -ErrorAction SilentlyContinue}else{$env:SSHENC_AGENT_SOCKET=$oldSocket}
        if($null -eq $oldAuth){Remove-Item Env:SSH_AUTH_SOCK -ErrorAction SilentlyContinue}else{$env:SSH_AUTH_SOCK=$oldAuth}
        if($null -eq $oldGitSsh){Remove-Item Env:GIT_SSH_COMMAND -ErrorAction SilentlyContinue}else{$env:GIT_SSH_COMMAND=$oldGitSsh}
    }
}

function Has-RuntimeBlock($Result) {
    return @($Result.Json.findings | Where-Object {
        $_.severity -eq 'BLOCK' -and $_.check -like 'runtime.*'
    }).Count -gt 0
}

function Has-PinPolicyBlock($Result) {
    return @($Result.Json.findings | Where-Object {
        $_.severity -eq 'BLOCK' -and $_.check -like 'pin.*'
    }).Count -gt 0
}

$root=Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-preflight-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $cases=@(
        [pscustomobject]@{Name='exact runtime';Args=@{};Kind='exact'},
        [pscustomobject]@{Name='Bin case-only directory mismatch';Args=@{BinCaseMismatch=$true};Kind='runtime-delta'},
        [pscustomobject]@{Name='runtime file case-only mismatch';Args=@{FileCaseMismatch=$true};Kind='runtime-delta'},
        [pscustomobject]@{Name='hello-approval project-root junction';Args=@{ProjectRootThroughJunction=$true};Kind='runtime-delta'},
        [pscustomobject]@{Name='malformed unused pin leaf name';Args=@{MalformedUnusedName=$true};Kind='pin-delta'}
    )

    foreach($case in $cases){
        $fixtureRoot=Join-Path $root ($case.Name -replace '[^A-Za-z0-9]+','-')
        $fixtureArgs=$case.Args
        $fixture=New-Fixture -Root $fixtureRoot @fixtureArgs
        $result=Invoke-Preflight -Fixture $fixture

        if($case.Kind -eq 'exact'){
            if(-not (Has-RuntimeBlock $result) -and -not (Has-PinPolicyBlock $result)){
                Pass 'exact runtime/pin surface has no runtime or pin BLOCK findings'
            } else {
                Fail 'exact runtime/pin surface has no runtime or pin BLOCK findings' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
            }
            continue
        }

        if($case.Kind -eq 'runtime-delta'){
            if($ExpectedPhase1){
                if(-not (Has-RuntimeBlock $result)){
                    Pass ("Phase1 baseline accepts {0}" -f $case.Name)
                } else {
                    Fail ("Phase1 baseline accepts {0}" -f $case.Name) (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                }
            } else {
                if(Has-RuntimeBlock $result){
                    Pass ("hardened preflight rejects {0} with structured runtime BLOCK" -f $case.Name)
                } else {
                    Fail ("hardened preflight rejects {0} with structured runtime BLOCK" -f $case.Name) (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                }
            }
            continue
        }

        if($case.Kind -eq 'pin-delta'){
            if($ExpectedPhase1){
                if(-not (Has-PinPolicyBlock $result)){
                    Pass ("Phase1 baseline accepts {0}" -f $case.Name)
                } else {
                    Fail ("Phase1 baseline accepts {0}" -f $case.Name) (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                }
            } else {
                if(Has-PinPolicyBlock $result){
                    Pass ("hardened preflight rejects {0} with structured pin BLOCK" -f $case.Name)
                } else {
                    Fail ("hardened preflight rejects {0} with structured pin BLOCK" -f $case.Name) (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                }
            }
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if($script:Failed -ne 0){exit 1}
    exit 0
} finally {
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}
