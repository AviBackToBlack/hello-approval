#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalAgentLauncherValidation.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceLauncher = Join-Path $repoRoot 'scripts\Start-HelloApprovalAgent.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$socketPath = '\\.\pipe\hello-approval-validation-test'

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

function Compile-TestAgent {
    param([string]$OutputPath)

    $sourcePath = [IO.Path]::ChangeExtension($OutputPath,'.cs')
    $source = @'
using System;
public static class Program {
    public static int Main(string[] args) {
        Console.WriteLine("synthetic-agent-stdout");
        Console.Error.WriteLine("synthetic-agent-stderr");
        return 0;
    }
}
'@
    [IO.File]::WriteAllText($sourcePath,$source,[Text.UTF8Encoding]::new($false))

    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
        $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
    }
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
        throw 'Could not find .NET Framework csc.exe for synthetic test agent.'
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
        throw "Synthetic agent compilation failed: $($output -join ' | ')"
    }
    Remove-Item -LiteralPath $sourcePath -Force
}

function New-SyntheticRepo {
    param([string]$Root)

    $mini = Join-Path $Root 'repo'
    $scripts = Join-Path $mini 'scripts'
    $lib = Join-Path $mini 'lib'
    [void][IO.Directory]::CreateDirectory($scripts)
    [void][IO.Directory]::CreateDirectory($lib)

    Copy-Item -LiteralPath $sourceLauncher -Destination (Join-Path $scripts 'Start-HelloApprovalAgent.ps1') -Force
    Copy-Item -LiteralPath $sourceModule -Destination (Join-Path $lib 'HelloApproval.Validation.psm1') -Force

    return (Join-Path $scripts 'Start-HelloApprovalAgent.ps1')
}

function New-Junction {
    param(
        [string]$Link,
        [string]$Target,
        [switch]$DoNotCreateTarget
    )

    if (-not $DoNotCreateTarget) {
        [void][IO.Directory]::CreateDirectory($Target)
    }
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

function Invoke-Launcher {
    param(
        [string]$Launcher,
        [string]$Agent,
        [string]$Config,
        [string]$LocalAppData,
        [string]$LogDirectory
    )

    [void][IO.Directory]::CreateDirectory($LocalAppData)
    $oldLocal = $env:LOCALAPPDATA
    try {
        $env:LOCALAPPDATA = $LocalAppData
        $arguments = @(
            '-NoProfile',
            '-ExecutionPolicy','Bypass',
            '-File',$Launcher,
            '-AgentPath',$Agent,
            '-ConfigPath',$Config,
            '-SocketPath',$socketPath,
            '-LogDirectory',$LogDirectory
        )

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
    }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-launcher-validation-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $launcher = New-SyntheticRepo -Root $root

    $tools = Join-Path $root 'tools'
    [void][IO.Directory]::CreateDirectory($tools)
    $agent = Join-Path $tools 'sshenc-agent.exe'
    Compile-TestAgent -OutputPath $agent

    $config = Join-Path $root 'config\config.toml'
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $config))
    [IO.File]::WriteAllText($config,'synthetic-config',[Text.UTF8Encoding]::new($false))

    $normalLocal = Join-Path $root 'normal-local'
    $normalProject = Join-Path $normalLocal 'hello-approval'
    $normalLogs = Join-Path (Join-Path $normalProject 'logs') 'nested'
    $normal = Invoke-Launcher -Launcher $launcher -Agent $agent -Config $config -LocalAppData $normalLocal -LogDirectory $normalLogs

    $launcherLog = Join-Path $normalLogs 'launcher.log'
    $stdoutLog = Join-Path $normalLogs 'agent.stdout.log'
    $stderrLog = Join-Path $normalLogs 'agent.stderr.log'
    $operationLog = Join-Path $normalLogs 'sshenc-operations.jsonl'
    $normalOk = (
        $normal.ExitCode -eq 0 -and
        (Test-Path -LiteralPath $launcherLog -PathType Leaf) -and
        (Test-Path -LiteralPath $stdoutLog -PathType Leaf) -and
        (Test-Path -LiteralPath $stderrLog -PathType Leaf) -and
        (Test-Path -LiteralPath $operationLog -PathType Leaf) -and
        ((Get-Content -LiteralPath $launcherLog -Raw) -match 'START') -and
        ((Get-Content -LiteralPath $launcherLog -Raw) -match 'EXIT code=0') -and
        ((Get-Content -LiteralPath $stdoutLog -Raw) -match 'synthetic-agent-stdout') -and
        ((Get-Content -LiteralPath $stderrLog -Raw) -match 'synthetic-agent-stderr')
    )
    if ($normalOk) {
        Pass 'nested project log path launches synthetic agent and writes validated logs'
    } else {
        Fail 'nested project log path launches synthetic agent and writes validated logs' ("rc={0} output={1}" -f $normal.ExitCode,($normal.Output -join ' | '))
    }

    $equalLocal = Join-Path $root 'equal-local'
    $equalProject = Join-Path $equalLocal 'hello-approval'
    $equal = Invoke-Launcher -Launcher $launcher -Agent $agent -Config $config -LocalAppData $equalLocal -LogDirectory $equalProject
    if ($equal.ExitCode -eq 125 -and (($equal.Output -join ' | ') -match 'must stay under the project-owned root')) {
        Pass 'project root itself is rejected as explicit LogDirectory'
    } else {
        Fail 'project root itself is rejected as explicit LogDirectory' ("rc={0} output={1}" -f $equal.ExitCode,($equal.Output -join ' | '))
    }

    $outsideLocal = Join-Path $root 'outside-local'
    $outsideLogs = Join-Path $root 'outside-logs'
    $outside = Invoke-Launcher -Launcher $launcher -Agent $agent -Config $config -LocalAppData $outsideLocal -LogDirectory $outsideLogs
    if ($outside.ExitCode -eq 125 -and (($outside.Output -join ' | ') -match 'must stay under the project-owned root')) {
        Pass 'outside LogDirectory is rejected'
    } else {
        Fail 'outside LogDirectory is rejected' ("rc={0} output={1}" -f $outside.ExitCode,($outside.Output -join ' | '))
    }

    $projectJunctionLocal = Join-Path $root 'project-junction-local'
    [void][IO.Directory]::CreateDirectory($projectJunctionLocal)
    $projectJunction = Join-Path $projectJunctionLocal 'hello-approval'
    New-Junction -Link $projectJunction -Target (Join-Path $root 'project-junction-target')
    $projectJunctionResult = Invoke-Launcher -Launcher $launcher -Agent $agent -Config $config -LocalAppData $projectJunctionLocal -LogDirectory (Join-Path $projectJunction 'logs')
    if ($projectJunctionResult.ExitCode -eq 125 -and (($projectJunctionResult.Output -join ' | ') -match 'reparse point')) {
        Pass 'project-root junction is rejected'
    } else {
        Fail 'project-root junction is rejected' ("rc={0} output={1}" -f $projectJunctionResult.ExitCode,($projectJunctionResult.Output -join ' | '))
    }

    $logsJunctionLocal = Join-Path $root 'logs-junction-local'
    $logsProject = Join-Path $logsJunctionLocal 'hello-approval'
    [void][IO.Directory]::CreateDirectory($logsProject)
    $logsJunction = Join-Path $logsProject 'logs'
    New-Junction -Link $logsJunction -Target (Join-Path $root 'logs-junction-target')
    $logsJunctionResult = Invoke-Launcher -Launcher $launcher -Agent $agent -Config $config -LocalAppData $logsJunctionLocal -LogDirectory (Join-Path $logsJunction 'nested')
    if ($logsJunctionResult.ExitCode -eq 125 -and (($logsJunctionResult.Output -join ' | ') -match 'reparse point')) {
        Pass 'descendant log-directory junction is rejected'
    } else {
        Fail 'descendant log-directory junction is rejected' ("rc={0} output={1}" -f $logsJunctionResult.ExitCode,($logsJunctionResult.Output -join ' | '))
    }

    $danglingLocal = Join-Path $root 'dangling-local'
    $danglingProject = Join-Path $danglingLocal 'hello-approval'
    [void][IO.Directory]::CreateDirectory($danglingProject)
    $danglingLogs = Join-Path $danglingProject 'logs'
    New-Junction -Link $danglingLogs -Target (Join-Path $root 'dangling-target-does-not-exist') -DoNotCreateTarget
    $danglingResult = Invoke-Launcher -Launcher $launcher -Agent $agent -Config $config -LocalAppData $danglingLocal -LogDirectory (Join-Path $danglingLogs 'nested')
    if ($danglingResult.ExitCode -eq 125 -and (($danglingResult.Output -join ' | ') -match 'reparse point')) {
        Pass 'dangling log-directory junction is rejected'
    } else {
        Fail 'dangling log-directory junction is rejected' ("rc={0} output={1}" -f $danglingResult.ExitCode,($danglingResult.Output -join ' | '))
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1}" -f $script:Passed,$script:Failed)
    if ($script:Failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
