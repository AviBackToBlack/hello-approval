#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalScheduledTaskInstaller.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceInstaller = Join-Path $repoRoot 'scripts\Install-HelloApprovalScheduledTask.ps1'
$sourceLauncher = Join-Path $repoRoot 'scripts\Start-HelloApprovalAgent.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$taskName = 'hello-approval Git Signing Agent'

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

function Compile-TestExe {
    param(
        [string]$OutputPath,
        [string]$SourceText
    )

    $sourcePath = [IO.Path]::ChangeExtension($OutputPath,'.cs')
    [IO.File]::WriteAllText($sourcePath,$SourceText,[Text.UTF8Encoding]::new($false))

    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
        $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
    }
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
        throw 'Could not find .NET Framework csc.exe for synthetic test PE generation.'
    }

    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $csc /nologo /target:exe "/out:$OutputPath" $sourcePath 2>&1 | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($rc -ne 0 -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "Synthetic PE compilation failed: $($output -join ' | ')"
    }
    Remove-Item -LiteralPath $sourcePath -Force
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

    Copy-Item -LiteralPath $sourceInstaller -Destination (Join-Path $scripts 'Install-HelloApprovalScheduledTask.ps1') -Force
    Copy-Item -LiteralPath $sourceLauncher -Destination (Join-Path $scripts 'Start-HelloApprovalAgent.ps1') -Force
    Copy-Item -LiteralPath $sourceModule -Destination (Join-Path $lib 'HelloApproval.Validation.psm1') -Force

    return [pscustomobject]@{
        Repo = $mini
        Installer = Join-Path $scripts 'Install-HelloApprovalScheduledTask.ps1'
        PinPath = Join-Path $provenance 'sshenc-v0.6.101.json'
    }
}

function New-SyntheticRuntime {
    param(
        [string]$LocalAppData,
        [string]$PinPath,
        [string]$ConfigPath,
        [switch]$RuntimeThroughJunction,
        [switch]$UnknownUnusedDisposition
    )

    [void][IO.Directory]::CreateDirectory($LocalAppData)
    $projectRoot = Join-Path $LocalAppData 'hello-approval'
    [void][IO.Directory]::CreateDirectory($projectRoot)

    if ($RuntimeThroughJunction) {
        $redirect = Join-Path (Split-Path -Parent $LocalAppData) ('redirect-' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($redirect)
        $runtimeLink = Join-Path $projectRoot 'runtime'

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& cmd.exe /d /c mklink /J "$runtimeLink" "$redirect" 2>&1 | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }
        if ($rc -ne 0) {
            throw "Could not create runtime junction fixture: $($output -join ' | ')"
        }
        $runtimeBase = Join-Path $redirect 'sshenc'
    } else {
        $runtimeBase = Join-Path (Join-Path $projectRoot 'runtime') 'sshenc'
    }

    $runtimeRoot = Join-Path $runtimeBase 'v-test'
    $bin = Join-Path $runtimeRoot 'bin'
    [void][IO.Directory]::CreateDirectory($bin)

    $sshenc = Join-Path $bin 'sshenc.exe'
    $agent = Join-Path $bin 'sshenc-agent.exe'

    $sshencSource = @'
using System;
public static class Program {
    public static int Main(string[] args) {
        if (args.Length == 2 && args[0] == "config" && args[1] == "path") {
            Console.WriteLine(Environment.GetEnvironmentVariable("HELLO_APPROVAL_TEST_CONFIG_PATH"));
            return 0;
        }
        if (args.Length == 2 && args[0] == "config" && args[1] == "show") {
            Console.WriteLine(@"socket_path = '\\.\pipe\sshenc-github-signing'");
            Console.WriteLine("allowed_labels = [\"github-signing\"]");
            Console.WriteLine("prompt_policy = \"always\"");
            return 0;
        }
        return 2;
    }
}
'@
    $agentSource = @'
public static class Program {
    public static int Main(string[] args) { return 0; }
}
'@

    Compile-TestExe -OutputPath $sshenc -SourceText $sshencSource
    Compile-TestExe -OutputPath $agent -SourceText $agentSource

    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $ConfigPath))
    [IO.File]::WriteAllText($ConfigPath,'synthetic-config',[Text.UTF8Encoding]::new($false))

    $unusedDisposition = if ($UnknownUnusedDisposition) { 'mystery' } else { 'unused' }
    $pin = [ordered]@{
        schema = 'hello-approval/upstream-pin/v1'
        upstream = [ordered]@{ release_tag = 'v-test' }
        files = @(
            [ordered]@{
                name='sshenc.exe'
                size_bytes=[int64](Get-Item -LiteralPath $sshenc).Length
                sha256=Get-FileSha256Local -Path $sshenc
                policy=[ordered]@{ disposition='required' }
            },
            [ordered]@{
                name='sshenc-agent.exe'
                size_bytes=[int64](Get-Item -LiteralPath $agent).Length
                sha256=Get-FileSha256Local -Path $agent
                policy=[ordered]@{ disposition='required' }
            },
            [ordered]@{
                name='unused.exe'
                size_bytes=[int64]0
                sha256=('0' * 64)
                policy=[ordered]@{ disposition=$unusedDisposition }
            }
        )
        installation_policy = [ordered]@{
            target_architecture='x86_64-pc-windows-msvc'
            allowed_distribution='zip-manual-placement'
            installed_files=@('sshenc.exe','sshenc-agent.exe')
        }
    }

    [IO.File]::WriteAllText(
        $PinPath,
        ($pin | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false)
    )

    return [pscustomobject]@{
        RuntimeRoot=$runtimeRoot
        Bin=$bin
        ProjectRoot=$projectRoot
        RedirectRoot=if($RuntimeThroughJunction){$redirect}else{$null}
    }
}

function Invoke-InstallerWhatIf {
    param(
        [string]$Installer,
        [string]$LocalAppData,
        [string]$ConfigPath
    )

    $oldLocal = $env:LOCALAPPDATA
    $oldConfig = $env:HELLO_APPROVAL_TEST_CONFIG_PATH
    try {
        $env:LOCALAPPDATA = $LocalAppData
        $env:HELLO_APPROVAL_TEST_CONFIG_PATH = $ConfigPath

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $ps51 -NoProfile -ExecutionPolicy Bypass -File $Installer -WhatIf 2>&1 | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }

        return [pscustomobject]@{
            ExitCode=$rc
            Output=@($output)
        }
    } finally {
        $env:LOCALAPPDATA = $oldLocal
        if ($null -eq $oldConfig) {
            Remove-Item Env:HELLO_APPROVAL_TEST_CONFIG_PATH -ErrorAction SilentlyContinue
        } else {
            $env:HELLO_APPROVAL_TEST_CONFIG_PATH = $oldConfig
        }
    }
}

$existingTask = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    throw "Test precondition failed: Scheduled Task already exists: \$taskName"
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-task-installer-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    # Exact fixture.
    $exactRoot = Join-Path $root 'exact'
    [void][IO.Directory]::CreateDirectory($exactRoot)
    $exactRepo = New-SyntheticRepo -Root $exactRoot
    $exactLocal = Join-Path $exactRoot 'local'
    $exactConfig = Join-Path $exactRoot 'config\config.toml'
    $exactRuntime = New-SyntheticRuntime -LocalAppData $exactLocal -PinPath $exactRepo.PinPath -ConfigPath $exactConfig
    $exact = Invoke-InstallerWhatIf -Installer $exactRepo.Installer -LocalAppData $exactLocal -ConfigPath $exactConfig
    $launcherRoot = Join-Path (Join-Path (Join-Path $exactLocal 'hello-approval') 'app') 'launcher'
    if ($exact.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $launcherRoot)) {
        Pass 'exact runtime reaches Scheduled Task WhatIf gate without filesystem mutation'
    } else {
        Fail 'exact runtime reaches Scheduled Task WhatIf gate without filesystem mutation' ("rc={0} launcherRoot={1} output={2}" -f $exact.ExitCode,(Test-Path -LiteralPath $launcherRoot),($exact.Output -join ' | '))
    }

    # Exact-case behavior is already strict in Phase 1 and must remain strict.
    Rename-Item -LiteralPath (Join-Path $exactRuntime.Bin 'sshenc.exe') -NewName 'sshenc.tmp'
    Rename-Item -LiteralPath (Join-Path $exactRuntime.Bin 'sshenc.tmp') -NewName 'SSHENC.EXE'
    $caseResult = Invoke-InstallerWhatIf -Installer $exactRepo.Installer -LocalAppData $exactLocal -ConfigPath $exactConfig
    if ($caseResult.ExitCode -ne 0) {
        Pass 'case-only runtime drift is rejected'
    } else {
        Fail 'case-only runtime drift is rejected' 'installer unexpectedly returned success'
    }

    # Ancestry delta: Phase 1 does not inspect the intermediate runtime junction.
    $junctionRoot = Join-Path $root 'junction'
    [void][IO.Directory]::CreateDirectory($junctionRoot)
    $junctionRepo = New-SyntheticRepo -Root $junctionRoot
    $junctionLocal = Join-Path $junctionRoot 'local'
    $junctionConfig = Join-Path $junctionRoot 'config\config.toml'
    $junctionRuntime = New-SyntheticRuntime -LocalAppData $junctionLocal -PinPath $junctionRepo.PinPath -ConfigPath $junctionConfig -RuntimeThroughJunction
    $junctionResult = Invoke-InstallerWhatIf -Installer $junctionRepo.Installer -LocalAppData $junctionLocal -ConfigPath $junctionConfig

    if ($ExpectedPhase1) {
        if ($junctionResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts runtime through intermediate junction'
        } else {
            Fail 'Phase1 baseline accepts runtime through intermediate junction' ($junctionResult.Output -join ' | ')
        }
    } else {
        if ($junctionResult.ExitCode -ne 0 -and (($junctionResult.Output -join ' | ') -match 'reparse point')) {
            Pass 'hardened installer rejects runtime intermediate junction'
        } else {
            Fail 'hardened installer rejects runtime intermediate junction' ("rc={0} output={1}" -f $junctionResult.ExitCode,($junctionResult.Output -join ' | '))
        }
    }

    # Malformed-pin delta: unknown disposition on an uninstalled/unused record.
    $pinRoot = Join-Path $root 'malformed'
    [void][IO.Directory]::CreateDirectory($pinRoot)
    $pinRepo = New-SyntheticRepo -Root $pinRoot
    $pinLocal = Join-Path $pinRoot 'local'
    $pinConfig = Join-Path $pinRoot 'config\config.toml'
    [void](New-SyntheticRuntime -LocalAppData $pinLocal -PinPath $pinRepo.PinPath -ConfigPath $pinConfig -UnknownUnusedDisposition)
    $pinResult = Invoke-InstallerWhatIf -Installer $pinRepo.Installer -LocalAppData $pinLocal -ConfigPath $pinConfig

    if ($ExpectedPhase1) {
        if ($pinResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts unknown disposition on unused pin record'
        } else {
            Fail 'Phase1 baseline accepts unknown disposition on unused pin record' ($pinResult.Output -join ' | ')
        }
    } else {
        if ($pinResult.ExitCode -ne 0 -and (($pinResult.Output -join ' | ') -match 'Unsupported file policy disposition')) {
            Pass 'hardened installer rejects unknown pin disposition'
        } else {
            Fail 'hardened installer rejects unknown pin disposition' ("rc={0} output={1}" -f $pinResult.ExitCode,($pinResult.Output -join ' | '))
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if ($script:Failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
