#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalLocalVerificationInstaller.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceInstaller = Join-Path $repoRoot 'scripts\Install-HelloApprovalLocalVerification.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$principal = '54722547+AviBackToBlack@users.noreply.github.com'
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
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)

    Copy-Item -LiteralPath $sourceInstaller -Destination (Join-Path $scripts 'Install-HelloApprovalLocalVerification.ps1') -Force
    Copy-Item -LiteralPath $sourceModule -Destination (Join-Path $lib 'HelloApproval.Validation.psm1') -Force

    return (Join-Path $scripts 'Install-HelloApprovalLocalVerification.ps1')
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

function New-Fixture {
    param(
        [string]$Root,
        [switch]$PublicKeyThroughJunction,
        [switch]$GitRootThroughJunction,
        [switch]$TrustFileReparseLeaf,
        [switch]$VerificationConfigReparseLeaf
    )

    $installer = New-SyntheticRepo -Root $Root
    $local = Join-Path $Root 'local'
    $profile = Join-Path $Root 'profile'
    [void][IO.Directory]::CreateDirectory($local)
    [void][IO.Directory]::CreateDirectory($profile)

    $projectRoot = Join-Path $local 'hello-approval'
    [void][IO.Directory]::CreateDirectory($projectRoot)

    if ($GitRootThroughJunction) {
        New-Junction -Link (Join-Path $projectRoot 'git') -Target (Join-Path $Root 'git-redirect')
    } elseif ($TrustFileReparseLeaf) {
        $gitDir = Join-Path $projectRoot 'git'
        [void][IO.Directory]::CreateDirectory($gitDir)
        New-Junction -Link (Join-Path $gitDir 'allowed_signers') -Target (Join-Path $Root 'trust-redirect')
    } elseif ($VerificationConfigReparseLeaf) {
        $gitDir = Join-Path $projectRoot 'git'
        [void][IO.Directory]::CreateDirectory($gitDir)
        New-Junction -Link (Join-Path $gitDir 'verification.gitconfig') -Target (Join-Path $Root 'verification-config-redirect')
    }

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

    [IO.File]::WriteAllText(
        $keyPath,
        ($keyType + ' AAAATESTKEY synthetic'),
        [Text.UTF8Encoding]::new($false)
    )

    return [pscustomobject]@{
        Installer = $installer
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

        $arguments = @(
            '-NoProfile',
            '-ExecutionPolicy','Bypass',
            '-File',$Fixture.Installer,
            '-Principal',$principal
        )
        if ($WhatIf) { $arguments += '-WhatIf' }

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
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

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-local-verification-installer-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $exact = New-Fixture -Root (Join-Path $root 'exact')
    $exactResult = Invoke-Installer -Fixture $exact -WhatIf
    if ($exactResult.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $exact.GlobalConfig)) {
        Pass 'exact fixture reaches local-verification WhatIf gate without mutation'
    } else {
        Fail 'exact fixture reaches local-verification WhatIf gate without mutation' ("rc={0} globalExists={1} output={2}" -f $exactResult.ExitCode,(Test-Path -LiteralPath $exact.GlobalConfig),($exactResult.Output -join ' | '))
    }

    if (-not $ExpectedPhase1) {
        $write = New-Fixture -Root (Join-Path $root 'write')
        $writeFirst = Invoke-Installer -Fixture $write
        $writeSecond = Invoke-Installer -Fixture $write

        $gitRoot = Join-Path (Join-Path $write.LocalAppData 'hello-approval') 'git'
        $trustFile = Join-Path $gitRoot 'allowed_signers'
        $verificationConfig = Join-Path $gitRoot 'verification.gitconfig'

        $trustLines = @(Get-Content -LiteralPath $trustFile -ErrorAction SilentlyContinue)
        $schema = @(git config --file $verificationConfig --get-all hello-approval.schema)
        $allowed = @(git config --file $verificationConfig --get-all gpg.ssh.allowedSignersFile)
        $includes = @(git config --file $write.GlobalConfig --get-all include.path)
        $staging = @(Get-ChildItem -LiteralPath $gitRoot -Force -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -like '.allowed_signers.staging.*' -or $_.Name -like '.verification.gitconfig.staging.*'
        })

        $trustOwned = (
            $trustLines.Count -eq 2 -and
            $trustLines[0] -ceq '# hello-approval/ha-1.5/v1' -and
            $trustLines[1] -ceq ($principal + ' namespaces="git" ' + $keyType + ' AAAATESTKEY')
        )
        $writeOk = (
            $writeFirst.ExitCode -eq 0 -and
            $writeSecond.ExitCode -eq 0 -and
            $trustOwned -and
            $schema.Count -eq 1 -and $schema[0] -ceq 'hello-approval/ha-1.5/v1' -and
            $allowed.Count -eq 1 -and (Test-SameFilePathValue -ConfiguredValue $allowed[0] -ExpectedPath $trustFile) -and
            $includes.Count -eq 1 -and (Test-SameFilePathValue -ConfiguredValue $includes[0] -ExpectedPath $verificationConfig) -and
            $staging.Count -eq 0
        )

        if ($writeOk) {
            Pass 'isolated local-verification write path installs exact trust/config and reruns idempotently'
        } else {
            Fail 'isolated local-verification write path installs exact trust/config and reruns idempotently' (
                "first={0} second={1} trustOwned={2} schema={3} allowed={4} includes={5} staging={6} firstOutput={7} secondOutput={8}" -f
                $writeFirst.ExitCode,$writeSecond.ExitCode,$trustOwned,($schema -join ';'),($allowed -join ';'),($includes -join ';'),$staging.Count,($writeFirst.Output -join ' | '),($writeSecond.Output -join ' | ')
            )
        }
    }

    $keyJunction = New-Fixture -Root (Join-Path $root 'key-junction') -PublicKeyThroughJunction
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

    if (-not $ExpectedPhase1) {
        $gitJunction = New-Fixture -Root (Join-Path $root 'git-junction') -GitRootThroughJunction
        $gitJunctionResult = Invoke-Installer -Fixture $gitJunction -WhatIf
        if ($gitJunctionResult.ExitCode -ne 0 -and (($gitJunctionResult.Output -join ' | ') -match 'reparse point')) {
            Pass 'hardened installer rejects project Git directory junction'
        } else {
            Fail 'hardened installer rejects project Git directory junction' ("rc={0} output={1}" -f $gitJunctionResult.ExitCode,($gitJunctionResult.Output -join ' | '))
        }

        $trustLeaf = New-Fixture -Root (Join-Path $root 'trust-leaf-reparse') -TrustFileReparseLeaf
        $trustLeafResult = Invoke-Installer -Fixture $trustLeaf -WhatIf
        if ($trustLeafResult.ExitCode -ne 0 -and (($trustLeafResult.Output -join ' | ') -match 'reparse point')) {
            Pass 'hardened installer rejects allowed_signers reparse leaf'
        } else {
            Fail 'hardened installer rejects allowed_signers reparse leaf' ("rc={0} output={1}" -f $trustLeafResult.ExitCode,($trustLeafResult.Output -join ' | '))
        }

        $configLeaf = New-Fixture -Root (Join-Path $root 'verification-config-leaf-reparse') -VerificationConfigReparseLeaf
        $configLeafResult = Invoke-Installer -Fixture $configLeaf -WhatIf
        if ($configLeafResult.ExitCode -ne 0 -and (($configLeafResult.Output -join ' | ') -match 'reparse point')) {
            Pass 'hardened installer rejects verification Git-config reparse leaf'
        } else {
            Fail 'hardened installer rejects verification Git-config reparse leaf' ("rc={0} output={1}" -f $configLeafResult.ExitCode,($configLeafResult.Output -join ' | '))
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if ($script:Failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
