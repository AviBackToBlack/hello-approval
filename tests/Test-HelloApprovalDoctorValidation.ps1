#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Test-HelloApprovalDoctorValidation.ps1 supports Windows only.' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceScripts = Join-Path $repoRoot 'scripts'
$sourceLib = Join-Path $repoRoot 'lib'
$sourceProvenance = Join-Path $repoRoot 'provenance'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$keyType = 'sk-ecdsa-sha2-nistp256@openssh.com'
$principal = 'synthetic@example.invalid'

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
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = @(& cmd.exe /d /c mklink /J "$Link" "$Target" 2>&1 | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if($rc -ne 0){ throw "mklink failed: $($out -join ' | ')" }
}

function New-Fixture {
    param(
        [string]$Root,
        [switch]$BinCaseMismatch,
        [switch]$FileCaseMismatch,
        [switch]$ProjectRootThroughJunction,
        [switch]$PublicKeyThroughJunction,
        [switch]$MalformedUnusedName,
        [switch]$RuntimeMissing
    )

    $tool = Join-Path $Root 'tool'
    $scripts = Join-Path $tool 'scripts'
    $lib = Join-Path $tool 'lib'
    $prov = Join-Path $tool 'provenance'
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)
    [void][IO.Directory]::CreateDirectory($prov)
    Copy-Item -Path (Join-Path $sourceScripts '*') -Destination $scripts -Recurse -Force
    Copy-Item -Path (Join-Path $sourceLib '*') -Destination $lib -Recurse -Force
    Copy-Item -Path (Join-Path $sourceProvenance '*') -Destination $prov -Recurse -Force

    $local = Join-Path $Root 'local'
    $app = Join-Path $Root 'roaming'
    $profile = Join-Path $Root 'profile'
    [void][IO.Directory]::CreateDirectory($local)
    [void][IO.Directory]::CreateDirectory($app)
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

    $gitRoot = Join-Path $physicalProject 'git'
    [void][IO.Directory]::CreateDirectory($gitRoot)
    $allowed = Join-Path $gitRoot 'allowed_signers'
    $trustText = '# hello-approval/ha-1.5/v1' + [Environment]::NewLine +
        $principal + ' namespaces="git" ' + $keyType + ' AAAATESTKEY' + [Environment]::NewLine
    [IO.File]::WriteAllText($allowed,$trustText,[Text.UTF8Encoding]::new($false))

    foreach($fragment in @(
        [pscustomobject]@{Name='signing.gitconfig';Schema='hello-approval/ha-1.4/v1'},
        [pscustomobject]@{Name='verification.gitconfig';Schema='hello-approval/ha-1.5/v1'}
    )){
        $text = '[hello-approval]' + [Environment]::NewLine + '    schema = ' + $fragment.Schema + [Environment]::NewLine
        [IO.File]::WriteAllText((Join-Path $gitRoot $fragment.Name),$text,[Text.UTF8Encoding]::new($false))
    }

    $sshDir = Join-Path $profile '.ssh'
    if($PublicKeyThroughJunction){
        $sshTarget = Join-Path $Root 'ssh-redirect'
        New-Junction -Link $sshDir -Target $sshTarget
        $publicKey = Join-Path $sshTarget 'github-signing.pub'
    } else {
        [void][IO.Directory]::CreateDirectory($sshDir)
        $publicKey = Join-Path $sshDir 'github-signing.pub'
    }
    [IO.File]::WriteAllText($publicKey,($keyType + ' AAAATESTKEY synthetic'),[Text.UTF8Encoding]::new($false))

    $runtimeBase = Join-Path (Join-Path $physicalProject 'runtime') 'sshenc'
    $runtimeRoot = Join-Path $runtimeBase 'v-test'
    $binName = if($BinCaseMismatch){'Bin'}else{'bin'}
    $bin = Join-Path $runtimeRoot $binName
    [void][IO.Directory]::CreateDirectory($bin)

    $sshencName = if($FileCaseMismatch){'SSHENC.EXE'}else{'sshenc.exe'}
    $agentName = if($FileCaseMismatch){'SSHENC-AGENT.EXE'}else{'sshenc-agent.exe'}
    $sshenc = Join-Path $bin $sshencName
    $agent = Join-Path $bin $agentName
    $stubExe = Join-Path (Join-Path $env:SystemRoot 'System32') 'tree.com'
    if(-not (Test-Path -LiteralPath $stubExe -PathType Leaf)){
        throw "Synthetic Doctor fixture requires Windows tree.com: $stubExe"
    }
    Copy-Item -LiteralPath $stubExe -Destination $sshenc -Force
    Copy-Item -LiteralPath $stubExe -Destination $agent -Force

    $unusedName = if($MalformedUnusedName){'..\unused.exe'}else{'unused.exe'}
    $pin = [ordered]@{
        schema='hello-approval/upstream-pin/v1'
        upstream=[ordered]@{release_tag='v-test'}
        files=@(
            [ordered]@{
                name='sshenc.exe'
                size_bytes=[int64](Get-Item -LiteralPath $sshenc).Length
                sha256=Get-FileSha256Local $sshenc
                policy=[ordered]@{disposition='required'}
            },
            [ordered]@{
                name='sshenc-agent.exe'
                size_bytes=[int64](Get-Item -LiteralPath $agent).Length
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

    if($RuntimeMissing){
        Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
    }

    return [pscustomobject]@{
        Doctor = Join-Path $scripts 'Test-HelloApprovalDoctor.ps1'
        LocalAppData = $local
        AppData = $app
        UserProfile = $profile
        GlobalConfig = Join-Path $Root 'global.gitconfig'
    }
}

function Invoke-Doctor {
    param($Fixture)

    $oldLocal=$env:LOCALAPPDATA
    $oldApp=$env:APPDATA
    $oldProfile=$env:USERPROFILE
    $oldHome=$env:HOME
    $oldGlobal=$env:GIT_CONFIG_GLOBAL
    $oldNoSystem=$env:GIT_CONFIG_NOSYSTEM
    try {
        $env:LOCALAPPDATA=$Fixture.LocalAppData
        $env:APPDATA=$Fixture.AppData
        $env:USERPROFILE=$Fixture.UserProfile
        $env:HOME=$Fixture.UserProfile
        $env:GIT_CONFIG_GLOBAL=$Fixture.GlobalConfig
        $env:GIT_CONFIG_NOSYSTEM='1'

        $saved=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $out=@(& $ps51 -NoProfile -ExecutionPolicy Bypass -File $Fixture.Doctor -Json 2>$null | ForEach-Object {[string]$_})
            $rc=$LASTEXITCODE
        } finally {
            $ErrorActionPreference=$saved
        }

        $jsonStart = -1
        $jsonEnd = -1
        for($i=0; $i -lt $out.Count; $i++){
            if($jsonStart -lt 0 -and $out[$i].TrimStart().StartsWith('{')){ $jsonStart=$i }
            if($out[$i].TrimEnd().EndsWith('}')){ $jsonEnd=$i }
        }
        if($jsonStart -lt 0 -or $jsonEnd -lt $jsonStart){
            throw "Doctor JSON object was not found in stdout: $($out -join ' | ')"
        }
        $jsonText = @($out[$jsonStart..$jsonEnd]) -join [Environment]::NewLine
        $json = $jsonText | ConvertFrom-Json
        $noise = @()
        if($jsonStart -gt 0){ $noise += @($out[0..($jsonStart-1)]) }
        if($jsonEnd -lt ($out.Count-1)){ $noise += @($out[($jsonEnd+1)..($out.Count-1)]) }
        return [pscustomobject]@{ExitCode=$rc;Json=$json;Raw=@($out);Noise=@($noise)}
    } finally {
        $env:LOCALAPPDATA=$oldLocal
        $env:APPDATA=$oldApp
        $env:USERPROFILE=$oldProfile
        if($null -eq $oldHome){Remove-Item Env:HOME -ErrorAction SilentlyContinue}else{$env:HOME=$oldHome}
        if($null -eq $oldGlobal){Remove-Item Env:GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue}else{$env:GIT_CONFIG_GLOBAL=$oldGlobal}
        if($null -eq $oldNoSystem){Remove-Item Env:GIT_CONFIG_NOSYSTEM -ErrorAction SilentlyContinue}else{$env:GIT_CONFIG_NOSYSTEM=$oldNoSystem}
    }
}

function Has-Finding($Result,[string]$Severity,[string]$Check) {
    return @($Result.Json.findings | Where-Object {
        $_.severity -eq $Severity -and $_.check -eq $Check
    }).Count -gt 0
}

function Has-BlockMatching($Result,[string]$Pattern) {
    return @($Result.Json.findings | Where-Object {
        $_.severity -eq 'BLOCK' -and $_.check -like $Pattern
    }).Count -gt 0
}

function Has-DoctorInternal($Result) {
    return Has-Finding $Result 'BLOCK' 'doctor.internal'
}

$root=Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-doctor-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $cases=@(
        [pscustomobject]@{Name='exact direct surfaces';Args=@{};Kind='exact'},
        [pscustomobject]@{Name='missing runtime';Args=@{RuntimeMissing=$true};Kind='missing-runtime'},
        [pscustomobject]@{Name='Bin case-only directory mismatch';Args=@{BinCaseMismatch=$true};Kind='runtime-delta'},
        [pscustomobject]@{Name='runtime file case-only mismatch';Args=@{FileCaseMismatch=$true};Kind='runtime-delta'},
        [pscustomobject]@{Name='hello-approval project-root junction';Args=@{ProjectRootThroughJunction=$true};Kind='project-junction'},
        [pscustomobject]@{Name='signing public key through .ssh junction';Args=@{PublicKeyThroughJunction=$true};Kind='public-key-junction'},
        [pscustomobject]@{Name='malformed unused pin leaf name';Args=@{MalformedUnusedName=$true};Kind='pin-delta'}
    )

    foreach($case in $cases){
        $fixtureRoot=Join-Path $root ($case.Name -replace '[^A-Za-z0-9]+','-')
        $fixtureArgs=$case.Args
        $fixture=New-Fixture -Root $fixtureRoot @fixtureArgs
        $result=Invoke-Doctor -Fixture $fixture

        if(Has-DoctorInternal $result){
            Fail $case.Name ('doctor.internal was emitted: ' + (($result.Json.findings | Where-Object {$_.check -eq 'doctor.internal'} | ConvertTo-Json -Depth 8) -join ''))
            continue
        }

        switch($case.Kind){
            'exact' {
                if((Has-Finding $result 'PASS' 'runtime.sshenc.exe') -and
                   (Has-Finding $result 'PASS' 'trust.ownership') -and
                   (Has-Finding $result 'PASS' 'credential.public-key')){
                    Pass 'exact direct runtime/trust/public-key surfaces retain PASS findings'
                } else {
                    Fail 'exact direct runtime/trust/public-key surfaces retain PASS findings' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                }
            }
            'missing-runtime' {
                if((Has-Finding $result 'BLOCK' 'runtime.sshenc.exe') -and
                   (Has-Finding $result 'BLOCK' 'sshenc.config.path')){
                    Pass 'missing runtime remains directly BLOCKED without Doctor internal failure'
                } else {
                    Fail 'missing runtime remains directly BLOCKED without Doctor internal failure' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                }
            }
            'runtime-delta' {
                if($ExpectedPhase1){
                    if(Has-Finding $result 'PASS' 'runtime.sshenc.exe'){
                        Pass ("Phase1 Doctor directly accepts {0}" -f $case.Name)
                    } else {
                        Fail ("Phase1 Doctor directly accepts {0}" -f $case.Name) (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
                } else {
                    if(Has-BlockMatching $result 'runtime.*'){
                        Pass ("hardened Doctor rejects {0} with runtime BLOCK" -f $case.Name)
                    } else {
                        Fail ("hardened Doctor rejects {0} with runtime BLOCK" -f $case.Name) (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
                }
            }
            'project-junction' {
                if($ExpectedPhase1){
                    if((Has-Finding $result 'PASS' 'runtime.sshenc.exe') -and (Has-Finding $result 'PASS' 'trust.ownership')){
                        Pass 'Phase1 Doctor directly accepts hello-approval project-root junction'
                    } else {
                        Fail 'Phase1 Doctor directly accepts hello-approval project-root junction' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
                } else {
                    if((Has-BlockMatching $result 'runtime.*') -or (Has-BlockMatching $result 'trust.*') -or (Has-Finding $result 'BLOCK' 'project.root')){
                        Pass 'hardened Doctor rejects hello-approval project-root junction'
                    } else {
                        Fail 'hardened Doctor rejects hello-approval project-root junction' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
                }
            }
            'public-key-junction' {
                if($ExpectedPhase1){
                    if(Has-Finding $result 'PASS' 'credential.public-key'){
                        Pass 'Phase1 Doctor directly accepts signing public key through .ssh junction'
                    } else {
                        Fail 'Phase1 Doctor directly accepts signing public key through .ssh junction' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
                } else {
                    if(Has-Finding $result 'BLOCK' 'credential.public-key'){
                        Pass 'hardened Doctor rejects signing public key through .ssh junction'
                    } else {
                        Fail 'hardened Doctor rejects signing public key through .ssh junction' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
                }
            }
            'pin-delta' {
                if($ExpectedPhase1){
                    if((Has-Finding $result 'PASS' 'runtime.sshenc.exe') -and -not (Has-BlockMatching $result 'pin.*')){
                        Pass 'Phase1 Doctor directly accepts malformed unused pin leaf name'
                    } else {
                        Fail 'Phase1 Doctor directly accepts malformed unused pin leaf name' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
                } else {
                    if(Has-BlockMatching $result 'pin.*'){
                        Pass 'hardened Doctor rejects malformed unused pin leaf name with pin BLOCK'
                    } else {
                        Fail 'hardened Doctor rejects malformed unused pin leaf name with pin BLOCK' (($result.Json.findings | ConvertTo-Json -Depth 8) -join '')
                    }
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
