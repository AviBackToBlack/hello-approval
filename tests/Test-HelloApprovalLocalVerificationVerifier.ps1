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
foreach ($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })) {
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
        Commit=[string](git -C $signedRepo rev-parse HEAD)
    }
}

function New-UnsignedRepo {
    param([string]$Root)

    $repo=Join-Path $Root 'routing-poison-repo'
    $emptyTemplate=Join-Path $Root 'routing-poison-empty-template'
    [void][IO.Directory]::CreateDirectory($emptyTemplate)
    git init --template=$emptyTemplate $repo | Out-Null
    git -C $repo config user.name Synthetic
    git -C $repo config user.email synthetic@example.invalid
    [IO.File]::WriteAllText((Join-Path $repo 'poison.txt'),'routing poison',[Text.UTF8Encoding]::new($false))
    git -C $repo add poison.txt
    git -C $repo -c commit.gpgsign=false commit -m 'unsigned routing poison' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'unsigned routing-poison commit failed'}
    return $repo
}

function Invoke-Verifier {
    param($Fixture)

    $oldLocal=$env:LOCALAPPDATA
    $oldProfile=$env:USERPROFILE
    $oldHome=$env:HOME
    $oldXdg=$env:XDG_CONFIG_HOME
    $oldGitConfigEnvironment=@{}
    foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })){
        $oldGitConfigEnvironment[$entry.Name]=$entry.Value
    }
    try {
        foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })){
            Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
        }
        Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue
        $env:LOCALAPPDATA=$Fixture.LocalAppData
        $env:USERPROFILE=$Fixture.UserProfile
        $env:HOME=$Fixture.UserProfile
        $env:GIT_CONFIG_GLOBAL=$Fixture.GlobalConfig
        $env:GIT_CONFIG_NOSYSTEM='1'
        $saved=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $out=@(& $ps51 -NoProfile -ExecutionPolicy Bypass -File $Fixture.Verifier -Repo $Fixture.Repo -Commit HEAD -ExpectedPrincipal $principal 2>&1 | ForEach-Object {[string]$_})
            $rc=$LASTEXITCODE
        } finally {$ErrorActionPreference=$saved}
        return [pscustomobject]@{ExitCode=$rc;Output=@($out)}
    } finally {
        foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })){
            Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
        }
        foreach($name in $oldGitConfigEnvironment.Keys){
            Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $oldGitConfigEnvironment[$name]
        }
        $env:LOCALAPPDATA=$oldLocal
        $env:USERPROFILE=$oldProfile
        if($null -eq $oldHome){Remove-Item Env:HOME -ErrorAction SilentlyContinue}else{$env:HOME=$oldHome}
        if($null -eq $oldXdg){Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue}else{$env:XDG_CONFIG_HOME=$oldXdg}
    }
}

function Invoke-VerifierInCurrentProcess {
    param($Fixture)

    $oldLocal=$env:LOCALAPPDATA
    $oldProfile=$env:USERPROFILE
    $oldHome=$env:HOME
    $oldXdg=$env:XDG_CONFIG_HOME
    $oldGitConfigEnvironment=@{}
    foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })){
        $oldGitConfigEnvironment[$entry.Name]=$entry.Value
    }
    try {
        foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })){
            Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
        }
        Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue
        $env:LOCALAPPDATA=$Fixture.LocalAppData
        $env:USERPROFILE=$Fixture.UserProfile
        $env:HOME=$Fixture.UserProfile
        $env:GIT_CONFIG_GLOBAL=$Fixture.GlobalConfig
        $env:GIT_CONFIG_NOSYSTEM='1'
        & $Fixture.Verifier -Repo $Fixture.Repo -Commit HEAD -ExpectedPrincipal $principal *> $null
    } finally {
        foreach($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })){
            Remove-Item -LiteralPath ("Env:{0}" -f $entry.Name) -ErrorAction SilentlyContinue
        }
        foreach($name in $oldGitConfigEnvironment.Keys){
            Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $oldGitConfigEnvironment[$name]
        }
        $env:LOCALAPPDATA=$oldLocal
        $env:USERPROFILE=$oldProfile
        if($null -eq $oldHome){Remove-Item Env:HOME -ErrorAction SilentlyContinue}else{$env:HOME=$oldHome}
        if($null -eq $oldXdg){Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue}else{$env:XDG_CONFIG_HOME=$oldXdg}
    }
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

            $poisonRepo=New-UnsignedRepo -Root $fixtureRoot
            $oldGitDir=$env:GIT_DIR
            try {
                $env:GIT_DIR=Join-Path $poisonRepo '.git'
                $poisonedGitDirResult=Invoke-Verifier -Fixture $fixture
            } finally {
                if($null -eq $oldGitDir){Remove-Item Env:GIT_DIR -ErrorAction SilentlyContinue}else{$env:GIT_DIR=$oldGitDir}
            }
            if($poisonedGitDirResult.ExitCode -eq 0 -and (($poisonedGitDirResult.Output -join ' | ') -match [regex]::Escape($fixture.Commit.Trim()))){
                Pass 'explicit Repo remains authoritative with poisoned GIT_DIR'
            } else {
                Fail 'explicit Repo remains authoritative with poisoned GIT_DIR' ("rc={0} output={1}" -f $poisonedGitDirResult.ExitCode,($poisonedGitDirResult.Output -join ' | '))
            }

            $oldGitWorkTree=$env:GIT_WORK_TREE
            try {
                $env:GIT_WORK_TREE=$poisonRepo
                $poisonedWorkTreeResult=Invoke-Verifier -Fixture $fixture
            } finally {
                if($null -eq $oldGitWorkTree){Remove-Item Env:GIT_WORK_TREE -ErrorAction SilentlyContinue}else{$env:GIT_WORK_TREE=$oldGitWorkTree}
            }
            if($poisonedWorkTreeResult.ExitCode -eq 0 -and (($poisonedWorkTreeResult.Output -join ' | ') -match [regex]::Escape($fixture.Commit.Trim()))){
                Pass 'explicit Repo remains authoritative with poisoned GIT_WORK_TREE'
            } else {
                Fail 'explicit Repo remains authoritative with poisoned GIT_WORK_TREE' ("rc={0} output={1}" -f $poisonedWorkTreeResult.ExitCode,($poisonedWorkTreeResult.Output -join ' | '))
            }

            $sentinelValues=@{}
            foreach($name in $repoRoutingEnvironmentNames){
                $sentinelValues[$name]="hello-approval-sentinel-$name"
                Set-Item -LiteralPath ("Env:{0}" -f $name) -Value $sentinelValues[$name]
            }
            $sameProcessError=$null
            try {
                try {
                    Invoke-VerifierInCurrentProcess -Fixture $fixture
                } catch {
                    $sameProcessError=$_.Exception.Message
                }
                $changed=@()
                foreach($name in $repoRoutingEnvironmentNames){
                    $actual=(Get-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue).Value
                    if($actual -cne $sentinelValues[$name]){
                        $changed += ("{0}='{1}'" -f $name,$actual)
                    }
                }
                if($null -eq $sameProcessError -and $changed.Count -eq 0){
                    Pass 'repository-routing environment is restored after same-process verification'
                } else {
                    Fail 'repository-routing environment is restored after same-process verification' ("error={0} changed={1}" -f $sameProcessError,($changed -join ', '))
                }
            } finally {
                foreach($name in $repoRoutingEnvironmentNames){
                    Remove-Item -LiteralPath ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
                }
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

    foreach ($entry in @(Get-ChildItem Env: | Where-Object { $_.Name -like 'GIT_CONFIG_*' })) {
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
