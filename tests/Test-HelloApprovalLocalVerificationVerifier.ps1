#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Test-HelloApprovalLocalVerificationVerifier.ps1 supports Windows only.' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceVerifier = Join-Path $repoRoot 'scripts\Test-HelloApprovalLocalVerification.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$sshKeygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
$principal = 'synthetic@example.invalid'

$script:Passed = 0
$script:Failed = 0

$repoRoutingEnvironmentNames = @(
    'GIT_DIR',
    'GIT_WORK_TREE',
    'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    'GIT_COMMON_DIR',
    'GIT_CEILING_DIRECTORIES',
    'GIT_NAMESPACE'
)
$oldRepoRoutingEnvironment = @{}
foreach ($name in $repoRoutingEnvironmentNames) {
    $entry = Get-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
    if ($null -ne $entry) {
        $oldRepoRoutingEnvironment[$name] = $entry.Value
    }
    Remove-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
}

$oldHarnessGitConfigEnvironment = @{}
foreach ($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -eq 'GIT_CONFIG' -or $_.Name -like 'GIT_CONFIG_*' })) {
    $oldHarnessGitConfigEnvironment[$entry.Name] = $entry.Value
    Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
}
$oldHarnessXdg = $env:XDG_CONFIG_HOME
$oldHarnessTemplate = $env:GIT_TEMPLATE_DIR
Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue
Remove-Item Env:GIT_TEMPLATE_DIR -ErrorAction SilentlyContinue

$harnessGitEnvironmentRoot = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-local-verifier-git-env-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($harnessGitEnvironmentRoot)
$env:GIT_CONFIG_GLOBAL = Join-Path $harnessGitEnvironmentRoot 'empty-global.gitconfig'
$env:GIT_CONFIG_NOSYSTEM = '1'

function Pass([string]$Name) { $script:Passed++; Write-Host "PASS  $Name" }
function Fail([string]$Name,[string]$Message) { $script:Failed++; Write-Host "FAIL  $Name - $Message" }

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

function New-SyntheticRepo {
    param([string]$Root)
    $mini=Join-Path $Root 'tool'
    $scripts=Join-Path $mini 'scripts'
    $lib=Join-Path $mini 'lib'
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)
    Copy-Item $sourceVerifier (Join-Path $scripts 'Test-HelloApprovalLocalVerification.ps1') -Force
    Copy-Item $sourceModule (Join-Path $lib 'HelloApproval.Validation.psm1') -Force
    return (Join-Path $scripts 'Test-HelloApprovalLocalVerification.ps1')
}

function New-Fixture {
    param(
        [string]$Root,
        [switch]$ProjectRootThroughJunction,
        [switch]$GitRootThroughJunction,
        [switch]$PublicKeyThroughJunction
    )

    $verifier=New-SyntheticRepo -Root $Root
    $local=Join-Path $Root 'local'
    $profile=Join-Path $Root 'profile'
    [void][IO.Directory]::CreateDirectory($local)
    [void][IO.Directory]::CreateDirectory($profile)

    $keyBase=Join-Path $Root 'signing'
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $sshKeygen
    $psi.Arguments = '-q -t ed25519 -N "" -C synthetic -f "' + $keyBase + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($psi)
    $process.WaitForExit()
    if($process.ExitCode -ne 0){throw 'synthetic ssh-keygen failed'}
    $process.Dispose()
    $publicSource=$keyBase + '.pub'
    $pubParts=@(([IO.File]::ReadAllText($publicSource).Trim()) -split '\s+')
    if($pubParts.Count -lt 2){throw 'synthetic public key parse failed'}

    $sshDir=Join-Path $profile '.ssh'
    if($PublicKeyThroughJunction){
        $sshTarget=Join-Path $Root 'ssh-redirect'
        New-Junction -Link $sshDir -Target $sshTarget
        $publicKey=Join-Path $sshTarget 'github-signing.pub'
    } else {
        [void][IO.Directory]::CreateDirectory($sshDir)
        $publicKey=Join-Path $sshDir 'github-signing.pub'
    }
    [IO.File]::WriteAllText($publicKey,($pubParts[0]+' '+$pubParts[1]+' synthetic'),[Text.UTF8Encoding]::new($false))

    $logicalProject=Join-Path $local 'hello-approval'
    if($ProjectRootThroughJunction){
        $projectTarget=Join-Path $Root 'project-redirect'
        New-Junction -Link $logicalProject -Target $projectTarget
        $physicalGit=Join-Path $projectTarget 'git'
    } else {
        [void][IO.Directory]::CreateDirectory($logicalProject)
        if($GitRootThroughJunction){
            $gitTarget=Join-Path $Root 'git-redirect'
            New-Junction -Link (Join-Path $logicalProject 'git') -Target $gitTarget
            $physicalGit=$gitTarget
        } else {
            $physicalGit=Join-Path $logicalProject 'git'
        }
    }
    [void][IO.Directory]::CreateDirectory($physicalGit)

    $logicalTrust=Join-Path (Join-Path $logicalProject 'git') 'allowed_signers'
    $physicalTrust=Join-Path $physicalGit 'allowed_signers'
    $trustText="# hello-approval/ha-1.5/v1`n$principal namespaces=`"git`" $($pubParts[0]) $($pubParts[1])`n"
    [IO.File]::WriteAllText($physicalTrust,$trustText,[Text.UTF8Encoding]::new($false))

    $signedRepo=Join-Path $Root 'signed-repo'
    $emptyTemplate = Join-Path $Root 'empty-git-template'
    [void][IO.Directory]::CreateDirectory($emptyTemplate)
    git init --template=$emptyTemplate $signedRepo | Out-Null
    git -C $signedRepo config user.name Synthetic
    git -C $signedRepo config user.email synthetic@example.invalid
    git -C $signedRepo config gpg.format ssh
    git -C $signedRepo config user.signingkey $keyBase
    git -C $signedRepo config commit.gpgsign true
    git -C $signedRepo config gpg.ssh.allowedSignersFile $logicalTrust
    [IO.File]::WriteAllText((Join-Path $signedRepo 'a.txt'),'synthetic',[Text.UTF8Encoding]::new($false))
    git -C $signedRepo add a.txt
    git -C $signedRepo commit -m 'synthetic signed commit' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'synthetic signed commit failed'}

    return [pscustomobject]@{
        Verifier=$verifier
        LocalAppData=$local
        UserProfile=$profile
        GlobalConfig=Join-Path $Root 'global.gitconfig'
        Repo=$signedRepo
    }
}

function Invoke-Verifier {
    param(
        $Fixture,
        [hashtable]$AmbientGitEnvironment = @{},
        [string]$Commit = 'HEAD',
        [switch]$InProcess
    )

    $oldLocal=$env:LOCALAPPDATA
    $oldProfile=$env:USERPROFILE
    $oldHome=$env:HOME
    $oldXdg=$env:XDG_CONFIG_HOME
    $oldGitConfigEnvironment=@{}
    foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -eq 'GIT_CONFIG' -or $_.Name -like 'GIT_CONFIG_*' })){
        $oldGitConfigEnvironment[$entry.Name]=$entry.Value
    }
    $oldAmbientGitEnvironment=@{}
    foreach($name in $AmbientGitEnvironment.Keys){
        $entry=Get-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
        $oldAmbientGitEnvironment[$name]=[pscustomobject]@{
            Present=($null -ne $entry)
            Value=$(if($null -ne $entry){$entry.Value}else{$null})
        }
    }
    try {
        foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -eq 'GIT_CONFIG' -or $_.Name -like 'GIT_CONFIG_*' })){
            Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
        }
        Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue
        $env:LOCALAPPDATA=$Fixture.LocalAppData
        $env:USERPROFILE=$Fixture.UserProfile
        $env:HOME=$Fixture.UserProfile
        $env:GIT_CONFIG_GLOBAL=$Fixture.GlobalConfig
        $env:GIT_CONFIG_NOSYSTEM='1'
        foreach($name in $AmbientGitEnvironment.Keys){
            Set-Item -LiteralPath ("Env:{0}" -f $name) -Value ([string]$AmbientGitEnvironment[$name])
        }
        $saved=$ErrorActionPreference
        $environmentRestored=$null
        try {
            $ErrorActionPreference='Continue'
            if($InProcess){
                try {
                    $out=@(& $Fixture.Verifier -Repo $Fixture.Repo -Commit $Commit -ExpectedPrincipal $principal *>&1 | ForEach-Object {[string]$_})
                    $rc=0
                } catch {
                    $rc=1
                    $out=@([string]$_)
                }
                $environmentRestored=$true
                foreach($name in $AmbientGitEnvironment.Keys){
                    $entry=Get-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
                    if($null -eq $entry -or [string]$entry.Value -cne [string]$AmbientGitEnvironment[$name]){
                        $environmentRestored=$false
                        break
                    }
                }
            } else {
                $out=@(& $ps51 -NoProfile -ExecutionPolicy Bypass -File $Fixture.Verifier -Repo $Fixture.Repo -Commit $Commit -ExpectedPrincipal $principal 2>&1 | ForEach-Object {[string]$_})
                $rc=$LASTEXITCODE
            }
        } finally {$ErrorActionPreference=$saved}
        return [pscustomobject]@{ExitCode=$rc;Output=@($out);EnvironmentRestored=$environmentRestored}
    } finally {
        foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -eq 'GIT_CONFIG' -or $_.Name -like 'GIT_CONFIG_*' })){
            Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
        }
        foreach($name in $oldGitConfigEnvironment.Keys){
            Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $oldGitConfigEnvironment[$name]
        }
        foreach($name in $AmbientGitEnvironment.Keys){
            Remove-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
            $old=$oldAmbientGitEnvironment[$name]
            if($old.Present){
                Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $old.Value
            }
        }
        $env:LOCALAPPDATA=$oldLocal
        $env:USERPROFILE=$oldProfile
        if($null -eq $oldHome){Remove-Item Env:HOME -ErrorAction SilentlyContinue}else{$env:HOME=$oldHome}
        if($null -eq $oldXdg){Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue}else{$env:XDG_CONFIG_HOME=$oldXdg}
    }
}

function New-VictimRepo {
    param([string]$Root)

    $victim=Join-Path $Root 'victim-repo'
    $emptyTemplate=Join-Path $Root 'victim-empty-git-template'
    [void][IO.Directory]::CreateDirectory($emptyTemplate)
    git init --template=$emptyTemplate $victim | Out-Null
    git -C $victim config user.name Victim
    git -C $victim config user.email victim@example.invalid
    [IO.File]::WriteAllText((Join-Path $victim 'victim.txt'),'victim',[Text.UTF8Encoding]::new($false))
    git -C $victim add victim.txt
    git -C $victim commit --no-gpg-sign -m 'victim commit' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'victim commit failed'}
    return $victim
}

$root=Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-local-verifier-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $cases=@(
        [pscustomobject]@{Name='exact trusted paths';Args=@{}},
        [pscustomobject]@{Name='hello-approval project-root junction';Args=@{ProjectRootThroughJunction=$true}},
        [pscustomobject]@{Name='project Git directory junction';Args=@{GitRootThroughJunction=$true}},
        [pscustomobject]@{Name='signing public key through .ssh junction';Args=@{PublicKeyThroughJunction=$true}}
    )

    foreach($case in $cases){
        $fixtureRoot = Join-Path $root ($case.Name -replace '[^A-Za-z0-9]+','-')
        $fixtureArgs = $case.Args
        $fixture = New-Fixture -Root $fixtureRoot @fixtureArgs
        $result=Invoke-Verifier -Fixture $fixture

        if($case.Name -eq 'exact trusted paths'){
            if($result.ExitCode -eq 0 -and (($result.Output -join ' | ') -match 'HA-1.5 LOCAL VERIFICATION: PASS')){
                Pass 'exact trusted paths verify a real synthetic SSH-signed commit'
            } else {
                Fail 'exact trusted paths verify a real synthetic SSH-signed commit' ("rc={0} output={1}" -f $result.ExitCode,($result.Output -join ' | '))
            }
            continue
        }

        if($ExpectedPhase1){
            if($result.ExitCode -eq 0){
                Pass ("Phase1 baseline accepts {0}" -f $case.Name)
            } else {
                Fail ("Phase1 baseline accepts {0}" -f $case.Name) ($result.Output -join ' | ')
            }
        } else {
            if($result.ExitCode -ne 0 -and (($result.Output -join ' | ') -match 'reparse point')){
                Pass ("hardened verifier rejects {0}" -f $case.Name)
            } else {
                Fail ("hardened verifier rejects {0}" -f $case.Name) ("rc={0} output={1}" -f $result.ExitCode,($result.Output -join ' | '))
            }
        }
    }

    $routingRoot=Join-Path $root 'repository-routing'
    $routingFixture=New-Fixture -Root $routingRoot
    $victimRepo=New-VictimRepo -Root $routingRoot
    $victimGitDir=Join-Path $victimRepo '.git'
    $fullRoutingEnvironment=@{
        GIT_DIR=$victimGitDir
        GIT_WORK_TREE=$victimRepo
        GIT_INDEX_FILE=Join-Path $victimGitDir 'index'
        GIT_OBJECT_DIRECTORY=Join-Path $victimGitDir 'objects'
        GIT_ALTERNATE_OBJECT_DIRECTORIES=Join-Path $victimGitDir 'objects'
        GIT_COMMON_DIR=$victimGitDir
        GIT_CEILING_DIRECTORIES=$victimRepo
        GIT_NAMESPACE='hello-approval-victim'
    }
    $routingCases=@(
        [pscustomobject]@{Name='poisoned GIT_DIR';Environment=@{GIT_DIR=$victimGitDir}},
        [pscustomobject]@{Name='poisoned GIT_WORK_TREE';Environment=@{GIT_WORK_TREE=$victimRepo}},
        [pscustomobject]@{Name='poisoned GIT_DIR + GIT_WORK_TREE';Environment=@{GIT_DIR=$victimGitDir;GIT_WORK_TREE=$victimRepo}},
        [pscustomobject]@{Name='poisoned full repository-routing set';Environment=$fullRoutingEnvironment}
    )
    foreach($case in $routingCases){
        $result=Invoke-Verifier -Fixture $routingFixture -AmbientGitEnvironment $case.Environment
        if($result.ExitCode -eq 0 -and (($result.Output -join ' | ') -match 'HA-1.5 LOCAL VERIFICATION: PASS')){
            Pass ('production verifier isolates {0}' -f $case.Name)
        } else {
            Fail ('production verifier isolates {0}' -f $case.Name) ('rc={0} output={1}' -f $result.ExitCode,($result.Output -join ' | '))
        }
    }

    $inProcessResult=Invoke-Verifier -Fixture $routingFixture -AmbientGitEnvironment $fullRoutingEnvironment -InProcess
    if($inProcessResult.ExitCode -eq 0 -and $inProcessResult.EnvironmentRestored){
        Pass 'production verifier restores caller repository-routing environment byte-for-byte'
    } else {
        Fail 'production verifier restores caller repository-routing environment byte-for-byte' ('rc={0} restored={1} output={2}' -f $inProcessResult.ExitCode,$inProcessResult.EnvironmentRestored,($inProcessResult.Output -join ' | '))
    }

    $failedInProcessResult=Invoke-Verifier -Fixture $routingFixture -AmbientGitEnvironment $fullRoutingEnvironment -InProcess -Commit 'hello-approval-definitely-missing-commit'
    if($failedInProcessResult.ExitCode -ne 0 -and $failedInProcessResult.EnvironmentRestored){
        Pass 'production verifier restores caller repository-routing environment after verification failure'
    } else {
        Fail 'production verifier restores caller repository-routing environment after verification failure' ('rc={0} restored={1} output={2}' -f $failedInProcessResult.ExitCode,$failedInProcessResult.EnvironmentRestored,($failedInProcessResult.Output -join ' | '))
    }
    $failedSubprocessResult=Invoke-Verifier -Fixture $routingFixture -Commit 'hello-approval-definitely-missing-commit'
    if($failedSubprocessResult.ExitCode -ne 0 -and (($failedSubprocessResult.Output -join ' | ') -match 'hello-approval-definitely-missing-commit')){
        Pass 'subprocess verifier honors explicit -Commit value'
    } else {
        Fail 'subprocess verifier honors explicit -Commit value' ('rc={0} output={1}' -f $failedSubprocessResult.ExitCode,($failedSubprocessResult.Output -join ' | '))
    }

    $configInjectionRoot=Join-Path $root 'command-scope-config-injection'
    $configInjectionFixture=New-Fixture -Root $configInjectionRoot
    git -C $configInjectionFixture.Repo config --unset gpg.format
    if($LASTEXITCODE -ne 0){throw 'failed to remove fixture gpg.format'}
    git -C $configInjectionFixture.Repo config --unset gpg.ssh.allowedSignersFile
    if($LASTEXITCODE -ne 0){throw 'failed to remove fixture allowedSignersFile'}
    $injectedAllowedSigners=(Join-Path (Join-Path $configInjectionFixture.LocalAppData 'hello-approval\git') 'allowed_signers') -replace '\\','/'
    $countInjection=@{
        GIT_CONFIG_COUNT='2'
        GIT_CONFIG_KEY_0='gpg.format'
        GIT_CONFIG_VALUE_0='ssh'
        GIT_CONFIG_KEY_1='gpg.ssh.allowedSignersFile'
        GIT_CONFIG_VALUE_1=$injectedAllowedSigners
    }
    $parametersInjection=@{
        GIT_CONFIG_PARAMETERS=("'gpg.format'='ssh' 'gpg.ssh.allowedSignersFile'='{0}'" -f $injectedAllowedSigners)
    }
    git config --file $configInjectionFixture.GlobalConfig gpg.ssh.allowedSignersFile $injectedAllowedSigners
    if($LASTEXITCODE -ne 0){throw 'failed to write fixture global allowedSignersFile'}
    $fileInjectionConfig=Join-Path $configInjectionRoot 'ambient-override.gitconfig'
    [IO.File]::WriteAllText(
        $fileInjectionConfig,
        "[gpg]`n    format = ssh`n[gpg `"ssh`"]`n    allowedSignersFile = $injectedAllowedSigners`n",
        [Text.UTF8Encoding]::new($false)
    )
    $fileInjection=@{GIT_CONFIG=$fileInjectionConfig}
    foreach($case in @(
        [pscustomobject]@{Name='GIT_CONFIG_COUNT/KEY/VALUE';Environment=$countInjection},
        [pscustomobject]@{Name='GIT_CONFIG_PARAMETERS';Environment=$parametersInjection},
        [pscustomobject]@{Name='GIT_CONFIG file override';Environment=$fileInjection}
    )){
        $result=Invoke-Verifier -Fixture $configInjectionFixture -AmbientGitEnvironment $case.Environment
        if($result.ExitCode -ne 0 -and (($result.Output -join ' | ') -match 'Effective gpg.format is not ssh')){
            Pass ('production verifier ignores ambient {0} Git config override/injection' -f $case.Name)
        } else {
            Fail ('production verifier ignores ambient {0} Git config override/injection' -f $case.Name) ('rc={0} output={1}' -f $result.ExitCode,($result.Output -join ' | '))
        }
    }

    $configRestoreResult=Invoke-Verifier -Fixture $configInjectionFixture -AmbientGitEnvironment $countInjection -InProcess
    if($configRestoreResult.ExitCode -ne 0 -and $configRestoreResult.EnvironmentRestored){
        Pass 'production verifier restores caller Git config injection environment after rejection'
    } else {
        Fail 'production verifier restores caller Git config injection environment after rejection' ('rc={0} restored={1} output={2}' -f $configRestoreResult.ExitCode,$configRestoreResult.EnvironmentRestored,($configRestoreResult.Output -join ' | '))
    }
    $fileConfigRestoreResult=Invoke-Verifier -Fixture $configInjectionFixture -AmbientGitEnvironment $fileInjection -InProcess
    if($fileConfigRestoreResult.ExitCode -ne 0 -and $fileConfigRestoreResult.EnvironmentRestored){
        Pass 'production verifier restores caller GIT_CONFIG environment after rejection'
    } else {
        Fail 'production verifier restores caller GIT_CONFIG environment after rejection' ('rc={0} restored={1} output={2}' -f $fileConfigRestoreResult.ExitCode,$fileConfigRestoreResult.EnvironmentRestored,($fileConfigRestoreResult.Output -join ' | '))
    }

    git config --file $configInjectionFixture.GlobalConfig gpg.format ssh
    if($LASTEXITCODE -ne 0){throw 'failed to write fixture global gpg.format'}
    $globalSourceResult=Invoke-Verifier -Fixture $configInjectionFixture
    if($globalSourceResult.ExitCode -eq 0 -and (($globalSourceResult.Output -join ' | ') -match 'HA-1.5 LOCAL VERIFICATION: PASS')){
        Pass 'production verifier preserves GIT_CONFIG_GLOBAL as a legitimate config source selector'
    } else {
        Fail 'production verifier preserves GIT_CONFIG_GLOBAL as a legitimate config source selector' ('rc={0} output={1}' -f $globalSourceResult.ExitCode,($globalSourceResult.Output -join ' | '))
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if($script:Failed -ne 0){exit 1}
    exit 0
} finally {
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($name in $repoRoutingEnvironmentNames) {
        Remove-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
    }
    foreach ($name in $oldRepoRoutingEnvironment.Keys) {
        Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $oldRepoRoutingEnvironment[$name]
    }

    foreach ($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -eq 'GIT_CONFIG' -or $_.Name -like 'GIT_CONFIG_*' })) {
        Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
    }
    foreach ($name in $oldHarnessGitConfigEnvironment.Keys) {
        Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $oldHarnessGitConfigEnvironment[$name]
    }
    if ($null -eq $oldHarnessXdg) {
        Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue
    } else {
        $env:XDG_CONFIG_HOME = $oldHarnessXdg
    }
    if ($null -eq $oldHarnessTemplate) {
        Remove-Item Env:GIT_TEMPLATE_DIR -ErrorAction SilentlyContinue
    } else {
        $env:GIT_TEMPLATE_DIR = $oldHarnessTemplate
    }
    Remove-Item $harnessGitEnvironmentRoot -Recurse -Force -ErrorAction SilentlyContinue
}
