#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalGitConfigInstaller.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceInstaller = Join-Path $repoRoot 'scripts\Install-HelloApprovalGitConfig.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$keyType = 'sk-ecdsa-sha2-nistp256@openssh.com'

$script:Passed = 0
$script:Failed = 0

function Pass([string]$Name) {
    $script:Passed++
    Write-Host "PASS  $Name"
}

function Fail([string]$Name,[string]$Message) {
    $script:Failed++
    Write-Host "FAIL  $Name - $Message"
}

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

function Test-SameFilePathValue {
    param(
        [Parameter(Mandatory = $true)][string]$ConfiguredValue,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    try {
        $configuredWindows = $ConfiguredValue.Replace([char]'/', [IO.Path]::DirectorySeparatorChar)
        $configuredFull = (Get-Item -LiteralPath $configuredWindows -Force -ErrorAction Stop).FullName
        $expectedFull = (Get-Item -LiteralPath $ExpectedPath -Force -ErrorAction Stop).FullName
        return [string]::Equals($configuredFull, $expectedFull, [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function New-SyntheticRepo {
    param([string]$Root)

    $mini = Join-Path $Root 'repo'
    $scripts = Join-Path $mini 'scripts'
    $lib = Join-Path $mini 'lib'
    $provenance = Join-Path $mini 'provenance'
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)
    [void][IO.Directory]::CreateDirectory($provenance)

    Copy-Item -LiteralPath $sourceInstaller -Destination (Join-Path $scripts 'Install-HelloApprovalGitConfig.ps1') -Force
    Copy-Item -LiteralPath $sourceModule -Destination (Join-Path $lib 'HelloApproval.Validation.psm1') -Force

    return [pscustomobject]@{
        Repo = $mini
        Installer = Join-Path $scripts 'Install-HelloApprovalGitConfig.ps1'
        PinPath = Join-Path $provenance 'sshenc-v0.6.101.json'
    }
}

function New-Junction {
    param([string]$Link,[string]$Target)

    [void][IO.Directory]::CreateDirectory($Target)
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Link))

    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& cmd.exe /d /c mklink /J "$Link" "$Target" 2>&1 | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($rc -ne 0) {
        throw "Could not create junction '$Link' -> '$Target': $($output -join ' | ')"
    }
}

function New-SyntheticFixture {
    param(
        [string]$Root,
        [switch]$RuntimeThroughJunction,
        [switch]$PublicKeyThroughJunction,
        [switch]$UnknownUnusedDisposition
    )

    $repo = New-SyntheticRepo -Root $Root
    $local = Join-Path $Root 'local'
    $profile = Join-Path $Root 'profile'
    [void][IO.Directory]::CreateDirectory($local)
    [void][IO.Directory]::CreateDirectory($profile)

    $projectRoot = Join-Path $local 'hello-approval'
    [void][IO.Directory]::CreateDirectory($projectRoot)

    if ($RuntimeThroughJunction) {
        $redirect = Join-Path $Root 'runtime-redirect'
        $runtimeLink = Join-Path $projectRoot 'runtime'
        New-Junction -Link $runtimeLink -Target $redirect
        $runtimeBase = Join-Path $redirect 'sshenc'
    } else {
        $runtimeBase = Join-Path (Join-Path $projectRoot 'runtime') 'sshenc'
    }

    $runtimeRoot = Join-Path $runtimeBase 'v-test'
    $bin = Join-Path $runtimeRoot 'bin'
    [void][IO.Directory]::CreateDirectory($bin)
    $sshenc = Join-Path $bin 'sshenc.exe'
    $agent = Join-Path $bin 'sshenc-agent.exe'
    [IO.File]::WriteAllBytes($sshenc,[byte[]](1,2,3,4,5))
    [IO.File]::WriteAllBytes($agent,[byte[]](9,8,7,6))

    if ($PublicKeyThroughJunction) {
        $sshTarget = Join-Path $Root 'ssh-redirect'
        $sshDir = Join-Path $profile '.ssh'
        New-Junction -Link $sshDir -Target $sshTarget
        $keyPath = Join-Path $sshTarget 'github-signing.pub'
    } else {
        $sshDir = Join-Path $profile '.ssh'
        [void][IO.Directory]::CreateDirectory($sshDir)
        $keyPath = Join-Path $sshDir 'github-signing.pub'
    }
    [IO.File]::WriteAllText($keyPath,($keyType + ' AAAATESTKEY synthetic'),[Text.UTF8Encoding]::new($false))

    $unusedDisposition = if ($UnknownUnusedDisposition) { 'mystery' } else { 'unused' }
    $pin = [ordered]@{
        schema = 'hello-approval/upstream-pin/v1'
        upstream = [ordered]@{ release_tag='v-test' }
        files = @(
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
                name='unused.exe'
                size_bytes=[int64]0
                sha256=('0' * 64)
                policy=[ordered]@{disposition=$unusedDisposition}
            }
        )
        installation_policy = [ordered]@{
            target_architecture='x86_64-pc-windows-msvc'
            allowed_distribution='zip-manual-placement'
            installed_files=@('sshenc.exe','sshenc-agent.exe')
        }
    }
    [IO.File]::WriteAllText($repo.PinPath,($pin | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))

    return [pscustomobject]@{
        Installer = $repo.Installer
        LocalAppData = $local
        UserProfile = $profile
        GlobalConfig = Join-Path $Root 'global.gitconfig'
    }
}

function Invoke-Installer {
    param(
        $Fixture,
        [switch]$WhatIf
    )

    $oldLocal = $env:LOCALAPPDATA
    $oldProfile = $env:USERPROFILE
    $oldHome = $env:HOME
    $oldGlobal = $env:GIT_CONFIG_GLOBAL
    $oldNoSystem = $env:GIT_CONFIG_NOSYSTEM

    try {
        $env:LOCALAPPDATA = $Fixture.LocalAppData
        $env:USERPROFILE = $Fixture.UserProfile
        $env:HOME = $Fixture.UserProfile
        $env:GIT_CONFIG_GLOBAL = $Fixture.GlobalConfig
        $env:GIT_CONFIG_NOSYSTEM = '1'

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $arguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$Fixture.Installer)
            if ($WhatIf) { $arguments += '-WhatIf' }
            $output = @(& $ps51 @arguments 2>&1 | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }

        return [pscustomobject]@{
            ExitCode = $rc
            Output = @($output)
        }
    } finally {
        $env:LOCALAPPDATA = $oldLocal
        $env:USERPROFILE = $oldProfile
        if ($null -eq $oldHome) { Remove-Item Env:HOME -ErrorAction SilentlyContinue } else { $env:HOME = $oldHome }
        if ($null -eq $oldGlobal) { Remove-Item Env:GIT_CONFIG_GLOBAL -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_GLOBAL = $oldGlobal }
        if ($null -eq $oldNoSystem) { Remove-Item Env:GIT_CONFIG_NOSYSTEM -ErrorAction SilentlyContinue } else { $env:GIT_CONFIG_NOSYSTEM = $oldNoSystem }
    }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-git-config-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $exact = New-SyntheticFixture -Root (Join-Path $root 'exact')
    $exactResult = Invoke-Installer -Fixture $exact -WhatIf
    if ($exactResult.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $exact.GlobalConfig)) {
        Pass 'exact fixture reaches Git config WhatIf gate without mutation'
    } else {
        Fail 'exact fixture reaches Git config WhatIf gate without mutation' ("rc={0} globalExists={1} output={2}" -f $exactResult.ExitCode,(Test-Path -LiteralPath $exact.GlobalConfig),($exactResult.Output -join ' | '))
    }

    if (-not $ExpectedPhase1) {
        $write = New-SyntheticFixture -Root (Join-Path $root 'write')
        $writeFirst = Invoke-Installer -Fixture $write
        $writeSecond = Invoke-Installer -Fixture $write

        $ownedConfig = Join-Path (Join-Path (Join-Path $write.LocalAppData 'hello-approval') 'git') 'signing.gitconfig'
        $runtimeProgram = Join-Path (Join-Path (Join-Path (Join-Path (Join-Path $write.LocalAppData 'hello-approval') 'runtime') 'sshenc') 'v-test') 'binsshenc.exe'
        $publicKey = Join-Path (Join-Path $write.UserProfile '.ssh') 'github-signing.pub'

        $schema = @(git config --file $ownedConfig --get-all hello-approval.schema)
        $format = @(git config --file $ownedConfig --get-all gpg.format)
        $program = @(git config --file $ownedConfig --get-all gpg.ssh.program)
        $signingKey = @(git config --file $ownedConfig --get-all user.signingkey)
        $includes = @(git config --file $write.GlobalConfig --get-all include.path)
        $staging = @(Get-ChildItem -LiteralPath (Split-Path -Parent $ownedConfig) -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '.signing.gitconfig.staging.*' })

        $writeOk = (
            $writeFirst.ExitCode -eq 0 -and
            $writeSecond.ExitCode -eq 0 -and
            $schema.Count -eq 1 -and $schema[0] -ceq 'hello-approval/ha-1.4/v1' -and
            $format.Count -eq 1 -and $format[0] -ceq 'ssh' -and
            $program.Count -eq 1 -and (Test-SameFilePathValue -ConfiguredValue $program[0] -ExpectedPath $runtimeProgram) -and
            $signingKey.Count -eq 1 -and (Test-SameFilePathValue -ConfiguredValue $signingKey[0] -ExpectedPath $publicKey) -and
            $includes.Count -eq 1 -and (Test-SameFilePathValue -ConfiguredValue $includes[0] -ExpectedPath $ownedConfig) -and
            $staging.Count -eq 0
        )

        if ($writeOk) {
            Pass 'isolated Git config write path installs exact fragment/include and reruns idempotently'
        } else {
            Fail 'isolated Git config write path installs exact fragment/include and reruns idempotently' (
                "first={0} second={1} schema={2} format={3} program={4} key={5} includes={6} staging={7} firstOutput={8} secondOutput={9}" -f
                $writeFirst.ExitCode,$writeSecond.ExitCode,($schema -join ';'),($format -join ';'),($program -join ';'),($signingKey -join ';'),($includes -join ';'),$staging.Count,($writeFirst.Output -join ' | '),($writeSecond.Output -join ' | ')
            )
        }
    }

    $runtimeJunction = New-SyntheticFixture -Root (Join-Path $root 'runtime-junction') -RuntimeThroughJunction
    $runtimeResult = Invoke-Installer -Fixture $runtimeJunction -WhatIf
    if ($ExpectedPhase1) {
        if ($runtimeResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts runtime through intermediate junction'
        } else {
            Fail 'Phase1 baseline accepts runtime through intermediate junction' ($runtimeResult.Output -join ' | ')
        }
    } else {
        if ($runtimeResult.ExitCode -ne 0 -and (($runtimeResult.Output -join ' | ') -match 'reparse point')) {
            Pass 'hardened installer rejects runtime through intermediate junction'
        } else {
            Fail 'hardened installer rejects runtime through intermediate junction' ("rc={0} output={1}" -f $runtimeResult.ExitCode,($runtimeResult.Output -join ' | '))
        }
    }

    $keyJunction = New-SyntheticFixture -Root (Join-Path $root 'key-junction') -PublicKeyThroughJunction
    $keyResult = Invoke-Installer -Fixture $keyJunction -WhatIf
    if ($ExpectedPhase1) {
        if ($keyResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts signing public key through .ssh junction'
        } else {
            Fail 'Phase1 baseline accepts signing public key through .ssh junction' ($keyResult.Output -join ' | ')
        }
    } else {
        if ($keyResult.ExitCode -ne 0 -and (($keyResult.Output -join ' | ') -match 'reparse point')) {
            Pass 'hardened installer rejects signing public key through .ssh junction'
        } else {
            Fail 'hardened installer rejects signing public key through .ssh junction' ("rc={0} output={1}" -f $keyResult.ExitCode,($keyResult.Output -join ' | '))
        }
    }

    $badPin = New-SyntheticFixture -Root (Join-Path $root 'bad-pin') -UnknownUnusedDisposition
    $badPinResult = Invoke-Installer -Fixture $badPin -WhatIf
    if ($ExpectedPhase1) {
        if ($badPinResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts unknown disposition on unused pin record'
        } else {
            Fail 'Phase1 baseline accepts unknown disposition on unused pin record' ($badPinResult.Output -join ' | ')
        }
    } else {
        if ($badPinResult.ExitCode -ne 0 -and (($badPinResult.Output -join ' | ') -match 'Unsupported file policy disposition')) {
            Pass 'hardened installer rejects unknown disposition on unused pin record'
        } else {
            Fail 'hardened installer rejects unknown disposition on unused pin record' ("rc={0} output={1}" -f $badPinResult.ExitCode,($badPinResult.Output -join ' | '))
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if ($script:Failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
