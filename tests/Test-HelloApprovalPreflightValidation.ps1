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
        [switch]$MalformedUnusedName,
        [switch]$RuntimeMissing,
        [switch]$ValidationModuleMissing,
        [switch]$PinMissing,
        [switch]$MalformedSystemGitConfig,
        [switch]$MalformedGlobalGitConfig
    )

    $tool=Join-Path $Root 'tool'
    $scripts=Join-Path $tool 'scripts'
    $lib=Join-Path $tool 'lib'
    $prov=Join-Path $tool 'provenance'
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)
    [void][IO.Directory]::CreateDirectory($prov)
    Copy-Item $sourcePreflight (Join-Path $scripts 'Test-HelloApprovalPreflight.ps1') -Force
    if(-not $ValidationModuleMissing){
        Copy-Item $sourceModule (Join-Path $lib 'HelloApproval.Validation.psm1') -Force
    }

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

    $stubExe = Join-Path (Join-Path $env:SystemRoot 'System32') 'tree.com'
    if(-not (Test-Path -LiteralPath $stubExe -PathType Leaf)){
        throw "Synthetic preflight fixture requires Windows tree.com: $stubExe"
    }
    Copy-Item -LiteralPath $stubExe -Destination $sshenc -Force
    Copy-Item -LiteralPath $stubExe -Destination $agent -Force

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
    if(-not $PinMissing){
        [IO.File]::WriteAllText((Join-Path $prov 'sshenc-v0.6.101.json'),($pin|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
    }
    if($RuntimeMissing){
        Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
    }

    $systemGitConfig=$null
    if($MalformedSystemGitConfig){
        $systemGitConfig=Join-Path $Root 'system.gitconfig'
        [IO.File]::WriteAllText($systemGitConfig,"[core`n    broken = ",[Text.UTF8Encoding]::new($false))
    }
    if($MalformedGlobalGitConfig){
        [IO.File]::WriteAllText((Join-Path $profile '.gitconfig'),"[core`n    broken = ",[Text.UTF8Encoding]::new($false))
    }

    return [pscustomobject]@{
        SystemGitConfig=$systemGitConfig
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
    $gitSourceNames=@(@('XDG_CONFIG_HOME','GIT_CONFIG_SYSTEM','GIT_CONFIG_GLOBAL') + @(Get-ChildItem Env: | Where-Object { $_.Name -eq 'GIT_CONFIG' -or $_.Name -like 'GIT_CONFIG_*' } | ForEach-Object { $_.Name }) | Select-Object -Unique)
    $oldGitSources=@{}
    foreach($name in $gitSourceNames){ $oldGitSources[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
    try {
        # Fixture files must be the only Git config sources in play. GIT_CONFIG_NOSYSTEM would not keep the host
        # system file out of explicit --system reads, so the system scope is always pinned: to the fixture file
        # when one is supplied, otherwise to an absent fixture path (Git treats a missing file as empty).
        foreach($name in $gitSourceNames){ [Environment]::SetEnvironmentVariable($name,$null,'Process') }
        $env:GIT_CONFIG_SYSTEM=if($null -ne $Fixture.SystemGitConfig){$Fixture.SystemGitConfig}else{Join-Path $Fixture.UserProfile 'absent-system.gitconfig'}
        $env:GIT_CONFIG_GLOBAL=Join-Path $Fixture.UserProfile '.gitconfig'
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
        foreach($name in $gitSourceNames){ [Environment]::SetEnvironmentVariable($name,$oldGitSources[$name],'Process') }
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

function Is-StructuredBlockedResult($Result) {
    return (
        $Result.ExitCode -eq 2 -and
        [string]$Result.Json.schema -ceq 'hello-approval/preflight/v1' -and
        [bool]$Result.Json.blocked
    )
}

function Is-StructuredCleanResult($Result) {
    return (
        $Result.ExitCode -eq 0 -and
        [string]$Result.Json.schema -ceq 'hello-approval/preflight/v1' -and
        -not [bool]$Result.Json.blocked
    )
}

$root=Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-preflight-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $cases=@(
        [pscustomobject]@{Name='exact runtime';Args=@{};Kind='exact'},
        [pscustomobject]@{Name='missing runtime';Args=@{RuntimeMissing=$true};Kind='missing'},
        [pscustomobject]@{Name='missing validation module';Args=@{ValidationModuleMissing=$true};Kind='module-migration'},
        [pscustomobject]@{Name='missing provenance pin';Args=@{PinMissing=$true};Kind='required-structured-block'},
        [pscustomobject]@{Name='unreadable system Git config';Args=@{MalformedSystemGitConfig=$true};Kind='git-scope-unreadable';Scope='system'},
        [pscustomobject]@{Name='unreadable global Git config';Args=@{MalformedGlobalGitConfig=$true};Kind='git-scope-unreadable';Scope='global'},
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
            if((Is-StructuredCleanResult $result) -and -not (Has-RuntimeBlock $result) -and -not (Has-PinPolicyBlock $result)){
                Pass 'exact runtime/pin surface returns structured clean preflight result'
            } else {
                Fail 'exact runtime/pin surface returns structured clean preflight result' ("rc={0} blocked={1} findings={2}" -f $result.ExitCode,$result.Json.blocked,(($result.Json.findings | ConvertTo-Json -Depth 8) -join ''))
            }
            continue
        }

        if($case.Kind -eq 'missing'){
            $runtimeInfo = @($result.Json.findings | Where-Object {
                $_.severity -eq 'INFO' -and $_.check -eq 'runtime.surface'
            }).Count -eq 1
            if((Is-StructuredCleanResult $result) -and $runtimeInfo -and -not (Has-RuntimeBlock $result)){
                Pass 'missing runtime remains structured clean preflight INFO'
            } else {
                Fail 'missing runtime remains structured clean preflight INFO' ("rc={0} blocked={1} findings={2}" -f $result.ExitCode,$result.Json.blocked,(($result.Json.findings | ConvertTo-Json -Depth 8) -join ''))
            }
            continue
        }

        if($case.Kind -eq 'module-migration'){
            if($ExpectedPhase1){
                if(Is-StructuredCleanResult $result){
                    Pass 'Phase1 baseline does not require shared validation module'
                } else {
                    Fail 'Phase1 baseline does not require shared validation module' ("rc={0} blocked={1} findings={2}" -f $result.ExitCode,$result.Json.blocked,(($result.Json.findings | ConvertTo-Json -Depth 8) -join ''))
                }
            } else {
                if(Is-StructuredBlockedResult $result){
                    Pass 'hardened preflight requires shared validation module with structured BLOCK'
                } else {
                    Fail 'hardened preflight requires shared validation module with structured BLOCK' ("rc={0} blocked={1} findings={2}" -f $result.ExitCode,$result.Json.blocked,(($result.Json.findings | ConvertTo-Json -Depth 8) -join ''))
                }
            }
            continue
        }

        if($case.Kind -eq 'required-structured-block'){
            if(Is-StructuredBlockedResult $result){
                Pass ("{0} returns structured BLOCK result" -f $case.Name)
            } else {
                Fail ("{0} returns structured BLOCK result" -f $case.Name) ("rc={0} blocked={1} findings={2}" -f $result.ExitCode,$result.Json.blocked,(($result.Json.findings | ConvertTo-Json -Depth 8) -join ''))
            }
            continue
        }

        if($case.Kind -eq 'git-scope-unreadable'){
            if(@($result.Json.findings | Where-Object { $_.check -eq 'git.present' -and $_.severity -eq 'WARN' }).Count -gt 0){
                Write-Host ('SKIP  {0} requires Git on PATH' -f $case.Name)
                continue
            }
            # A malformed file in any scope makes every git config read fatal, so completeness is
            # asserted across both scopes and the BLOCK must name the actual offending file.
            $gitKeys=@('core.sshCommand','gpg.format','gpg.ssh.program','gpg.ssh.allowedSignersFile','user.signingkey','commit.gpgsign','tag.gpgsign','user.name','user.email')
            $brokenLeaf=if($case.Scope -eq 'system'){'system.gitconfig'}else{'.gitconfig'}
            $readable=@($result.Json.findings | Where-Object { $_.severity -eq 'BLOCK' -and $_.check -like 'git.*.readable' })
            $namesFile=@($readable | Where-Object { [string]$_.value -match [regex]::Escape($brokenLeaf) }).Count -eq $readable.Count
            $complete=$true
            foreach($scope in @('system','global')){
                $scopeBlocked=@($readable | Where-Object { $_.check -eq ('git.{0}.readable' -f $scope) }).Count -gt 0
                foreach($k in $gitKeys){
                    $keyFindings=@($result.Json.findings | Where-Object { $_.check -eq ('git.{0}.{1}' -f $scope,$k) })
                    if($keyFindings.Count -ne 1){ $complete=$false; continue }
                    if($scopeBlocked -and -not ($keyFindings[0].severity -eq 'INFO' -and [string]$keyFindings[0].message -match 'not evaluated')){ $complete=$false }
                }
            }
            $hasError=$null -ne $result.Json.PSObject.Properties['error']
            if((Is-StructuredBlockedResult $result) -and $readable.Count -ge 1 -and $namesFile -and $complete -and -not $hasError){
                Pass ('{0} keeps BLOCK, names the broken file, and accounts for every Git probe' -f $case.Name)
            } else {
                Fail ('{0} keeps BLOCK, names the broken file, and accounts for every Git probe' -f $case.Name) ('rc={0} blocked={1} readable={2} namesFile={3} complete={4} error={5}' -f $result.ExitCode,$result.Json.blocked,$readable.Count,$namesFile,$complete,$hasError)
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
                if((Has-RuntimeBlock $result) -and (Is-StructuredBlockedResult $result)){
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
                if((Has-PinPolicyBlock $result) -and (Is-StructuredBlockedResult $result)){
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
