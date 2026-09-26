#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$StartNow
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'hello-approval Git Signing Agent'
$TaskPath = '\'
$TaskMarker = 'hello-approval/ha-1.3/v1'
$SocketPath = '\\.\pipe\sshenc-github-signing'

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash($stream)
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Assert-RegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    if (-not [System.IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose path must be absolute: $Path"
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "$Purpose is missing: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Purpose must be a real non-reparse file: $full"
    }
    return $full
}

function Ensure-TrustedProjectDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $Path -ExpectedType Directory -AllowMissing)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($Path)
    }
    [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $Path -ExpectedType Directory)
}

function Assert-EffectiveConfig {
    param([Parameter(Mandatory = $true)][string]$SshencPath)

    $lines = @(& $SshencPath config show 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned sshenc.exe config show failed with exit $LASTEXITCODE."
    }

    $values = @{}
    foreach ($line in $lines) {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            $values[$parts[0].Trim()] = $parts[1].Trim()
        }
    }

    foreach ($requiredKey in @('socket_path', 'allowed_labels', 'prompt_policy')) {
        if (-not $values.ContainsKey($requiredKey)) {
            throw "Effective sshenc config is missing required key '$requiredKey'."
        }
    }

    $socketValue = [string]$values['socket_path']
    if ($socketValue.Length -lt 2 -or $socketValue[0] -ne "'" -or $socketValue[$socketValue.Length - 1] -ne "'") {
        throw "Effective sshenc socket_path is not in the expected canonical literal form: $socketValue"
    }
    $effectiveSocket = $socketValue.Substring(1, $socketValue.Length - 2)
    if ($effectiveSocket -ne $SocketPath) {
        throw "Effective sshenc socket_path must be '$SocketPath', got '$effectiveSocket'."
    }

    $labelsValue = [string]$values['allowed_labels']
    if ($labelsValue -ne '["github-signing"]') {
        throw "Effective sshenc allowed_labels must contain exactly github-signing, got '$($values['allowed_labels'])'."
    }

    $promptValue = [string]$values['prompt_policy']
    if ($promptValue -ne '"always"') {
        throw "Effective sshenc prompt_policy must be always, got '$promptValue'."
    }
}

function Quote-WindowsArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $slashes++
            continue
        }
        if ($ch -eq '"') {
            [void]$builder.Append(('\' * (($slashes * 2) + 1)))
            [void]$builder.Append('"')
            $slashes = 0
            continue
        }
        if ($slashes -gt 0) {
            [void]$builder.Append(('\' * $slashes))
            $slashes = 0
        }
        [void]$builder.Append($ch)
    }
    if ($slashes -gt 0) {
        [void]$builder.Append(('\' * ($slashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-TaskXml {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [xml](Export-ScheduledTask -TaskName $Name -TaskPath $TaskPath)
}

function New-TaskNamespaceManager {
    param([Parameter(Mandatory = $true)][xml]$Xml)
    $ns = New-Object Xml.XmlNamespaceManager($Xml.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    Write-Output -NoEnumerate $ns
}

function Get-XmlText {
    param(
        [Parameter(Mandatory = $true)][xml]$Xml,
        [Parameter(Mandatory = $true)][Xml.XmlNamespaceManager]$Ns,
        [Parameter(Mandatory = $true)][string]$XPath
    )
    $node = $Xml.SelectSingleNode($XPath, $Ns)
    if ($null -eq $node) { return $null }
    return [string]$node.InnerText
}

function Assert-OwnedTask {
    param([Parameter(Mandatory = $true)][xml]$Xml)
    $ns = New-TaskNamespaceManager -Xml $Xml
    $description = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:RegistrationInfo/t:Description'
    if ($description -ne $TaskMarker) {
        throw "Refusing to replace foreign task '$TaskPath$TaskName'; ownership marker is '$description'."
    }
}

function Test-TaskMatchesDesired {
    param(
        [Parameter(Mandatory = $true)][xml]$Xml,
        [Parameter(Mandatory = $true)][string]$ExpectedSid,
        [Parameter(Mandatory = $true)][string]$ExpectedUser,
        [Parameter(Mandatory = $true)][string]$ExpectedPowerShell,
        [Parameter(Mandatory = $true)][string]$ExpectedArguments,
        [Parameter(Mandatory = $true)][string]$ExpectedWorkingDirectory
    )

    $ns = New-TaskNamespaceManager -Xml $Xml
    $actionChildren = @($Xml.SelectNodes('/t:Task/t:Actions/*', $ns))
    $actionNodes = @($Xml.SelectNodes('/t:Task/t:Actions/t:Exec', $ns))
    $triggerChildren = @($Xml.SelectNodes('/t:Task/t:Triggers/*', $ns))
    $triggerNodes = @($Xml.SelectNodes('/t:Task/t:Triggers/t:LogonTrigger', $ns))
    $principalNodes = @($Xml.SelectNodes('/t:Task/t:Principals/t:Principal', $ns))
    if ($actionChildren.Count -ne 1 -or $actionNodes.Count -ne 1 -or
        $triggerChildren.Count -ne 1 -or $triggerNodes.Count -ne 1 -or
        $principalNodes.Count -ne 1) { return $false }

    $runLevel = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Principals/t:Principal/t:RunLevel'
    $taskEnabled = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:Enabled'
    $triggerEnabled = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Triggers/t:LogonTrigger/t:Enabled'
    $hidden = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:Hidden'
    $checks = @(
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:RegistrationInfo/t:Description') -eq $TaskMarker),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Principals/t:Principal/t:UserId') -eq $ExpectedSid),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Principals/t:Principal/t:LogonType') -eq 'InteractiveToken'),
        (($null -eq $runLevel) -or $runLevel -eq 'LeastPrivilege'),
        (($null -eq $taskEnabled) -or $taskEnabled -eq 'true'),
        (($null -eq $triggerEnabled) -or $triggerEnabled -eq 'true'),
        (($null -eq $hidden) -or $hidden -eq 'false'),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Triggers/t:LogonTrigger/t:UserId') -eq $ExpectedUser),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Actions/t:Exec/t:Command') -ieq $ExpectedPowerShell),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Actions/t:Exec/t:Arguments') -eq $ExpectedArguments),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Actions/t:Exec/t:WorkingDirectory') -ieq $ExpectedWorkingDirectory),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:MultipleInstancesPolicy') -eq 'IgnoreNew'),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:ExecutionTimeLimit') -eq 'PT0S'),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:RestartOnFailure/t:Count') -eq '3'),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:RestartOnFailure/t:Interval') -eq 'PT1M'),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:DisallowStartIfOnBatteries') -eq 'false'),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:StopIfGoingOnBatteries') -eq 'false')
    )
    return -not ($checks -contains $false)
}

function Test-DedicatedPipePresent {
    $pipeLeaf = ($SocketPath -replace '^\\\\\.\\pipe\\', '')
    return @([IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [IO.Path]::GetFileName($_) } | Where-Object { $_ -ieq $pipeLeaf }).Count -gt 0
}

function Wait-TaskNotRunning {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$RequirePipeFree
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $task = Get-ScheduledTask -TaskName $Name -TaskPath $TaskPath -ErrorAction Stop
        $pipePresent = Test-DedicatedPipePresent
        if ($task.State -ne 'Running' -and (-not $RequirePipeFree -or -not $pipePresent)) { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for task to stop$(if ($RequirePipeFree) { ' and dedicated pipe to become free' }): $TaskPath$Name"
}

function Assert-DedicatedPipeFree {
    if (Test-DedicatedPipePresent) {
        throw "Dedicated signing pipe is already occupied before task start: $SocketPath"
    }
}

function Wait-TaskRunningAndPipe {
    param([Parameter(Mandatory = $true)][string]$Name)

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $stableSince = $null
    do {
        $task = Get-ScheduledTask -TaskName $Name -TaskPath $TaskPath -ErrorAction Stop
        $pipePresent = Test-DedicatedPipePresent
        if ($task.State -eq 'Running' -and $pipePresent) {
            if ($null -eq $stableSince) { $stableSince = [DateTime]::UtcNow }
            if (([DateTime]::UtcNow - $stableSince).TotalMilliseconds -ge 600) { return }
        } else {
            $stableSince = $null
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)

    $info = Get-ScheduledTaskInfo -TaskName $Name -TaskPath $TaskPath -ErrorAction SilentlyContinue
    $resultText = if ($null -eq $info) { 'unknown' } else { '0x{0:X8}' -f ([uint32]$info.LastTaskResult) }
    throw "Task did not remain Running with dedicated pipe for 600 ms within 10 seconds (state=$($task.State), lastResult=$resultText)."
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Install-HelloApprovalScheduledTask.ps1 supports Windows only.'
}
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is not available.'
}
if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
    throw 'SystemRoot is not available.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$validationModulePath = Join-Path (Join-Path $repoRoot 'lib') 'HelloApproval.Validation.psm1'
if (-not (Test-Path -LiteralPath $validationModulePath -PathType Leaf)) {
    throw "Shared validation module is missing: $validationModulePath"
}
Import-Module $validationModulePath -Force -ErrorAction Stop

$pinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'
$sourceLauncher = Join-Path $PSScriptRoot 'Start-HelloApprovalAgent.ps1'
$pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
[void](Assert-HelloApprovalPinPolicy -Pin $pin)

if ($pin.installation_policy.target_architecture -ne 'x86_64-pc-windows-msvc') {
    throw "Unsupported pinned target architecture: $($pin.installation_policy.target_architecture)"
}
if ($pin.installation_policy.allowed_distribution -ne 'zip-manual-placement') {
    throw "Unsupported pinned distribution policy: $($pin.installation_policy.allowed_distribution)"
}

$releaseTag = [string]$pin.upstream.release_tag
$runtimeBase = Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA 'hello-approval') 'runtime') 'sshenc'
$runtimeRoot = Join-Path $runtimeBase $releaseTag
$runtimeValidation = Assert-HelloApprovalPinnedRuntime -RuntimeRoot $runtimeRoot -Pin $pin -TrustedBase $env:LOCALAPPDATA
$runtimeBin = $runtimeValidation.BinPath
$sshencPath = Assert-RegularFile -Path (Join-Path $runtimeBin 'sshenc.exe') -Purpose 'Pinned sshenc.exe'
$agentPath = Assert-RegularFile -Path (Join-Path $runtimeBin 'sshenc-agent.exe') -Purpose 'Pinned sshenc-agent.exe'

$configOutput = @(& $sshencPath config path 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
if ($LASTEXITCODE -ne 0 -or $configOutput.Count -ne 1) {
    throw "Pinned sshenc.exe did not return exactly one config path (exit=$LASTEXITCODE, lines=$($configOutput.Count))."
}
$configPath = Assert-RegularFile -Path $configOutput[0] -Purpose 'sshenc config'
Assert-EffectiveConfig -SshencPath $sshencPath

$sourceLauncher = Assert-RegularFile -Path $sourceLauncher -Purpose 'Repository HA-1.2 launcher'
$sourceValidationModule = Assert-RegularFile -Path $validationModulePath -Purpose 'Repository hello-approval validation module'
$launcherHash = Get-FileSha256 -Path $sourceLauncher
$validationModuleHash = Get-FileSha256 -Path $sourceValidationModule
$launcherSource = Get-Content -LiteralPath $sourceLauncher -Raw
$validationPinMatches = [regex]::Matches($launcherSource, '(?m)^\$ValidationModuleSha256 = ''([a-f0-9]{64})''$')
if ($validationPinMatches.Count -ne 1 -or $validationPinMatches[0].Groups[1].Value -cne $validationModuleHash) {
    throw 'Repository launcher validation-module SHA-256 pin does not match lib/HelloApproval.Validation.psm1.'
}

$projectRoot = Join-Path $env:LOCALAPPDATA 'hello-approval'
$appRoot = Join-Path $projectRoot 'app'
$launcherRoot = Join-Path $appRoot 'launcher'
$launcherVersionRoot = Join-Path $launcherRoot $launcherHash
$installedLauncher = Join-Path $launcherVersionRoot 'Start-HelloApprovalAgent.ps1'
$installedValidationModule = Join-Path $launcherVersionRoot 'HelloApproval.Validation.psm1'

# Detect a same-name foreign task before making any hello-approval filesystem mutation.
$existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
$existingXmlText = $null
$wasRunning = $false
if ($null -ne $existingTask) {
    $existingXml = Get-TaskXml -Name $TaskName
    Assert-OwnedTask -Xml $existingXml
    $existingXmlText = $existingXml.OuterXml
    $wasRunning = $existingTask.State -eq 'Running'
}

[void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $projectRoot -ExpectedType Directory)
foreach ($existingParent in @($appRoot, $launcherRoot)) {
    [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $existingParent -ExpectedType Directory -AllowMissing)
}

[void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $launcherVersionRoot -ExpectedType Directory -AllowMissing)
if (Test-Path -LiteralPath $launcherVersionRoot) {
    [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $launcherVersionRoot -ExpectedType Directory)
    $items = @(Get-ChildItem -LiteralPath $launcherVersionRoot -Force)
    $names = @($items | ForEach-Object { $_.Name })
    $nonFiles = @($items | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
    if ($items.Count -ne 2 -or
        -not ($names -ccontains 'Start-HelloApprovalAgent.ps1') -or
        -not ($names -ccontains 'HelloApproval.Validation.psm1') -or
        $nonFiles.Count -ne 0) {
        throw "Installed launcher bundle surface is not exact: $launcherVersionRoot"
    }
    $existingHash = Get-FileSha256 -Path $installedLauncher
    $existingModuleHash = Get-FileSha256 -Path $installedValidationModule
    if ($existingHash -cne $launcherHash -or $existingModuleHash -cne $validationModuleHash) {
        throw "Installed launcher bundle contains mismatched bytes: $launcherVersionRoot"
    }
} elseif ($PSCmdlet.ShouldProcess($launcherVersionRoot, 'Install content-addressed HA-1.2 launcher')) {
    Ensure-TrustedProjectDirectory -Path $projectRoot
    Ensure-TrustedProjectDirectory -Path $appRoot
    Ensure-TrustedProjectDirectory -Path $launcherRoot
    $stagingRoot = Join-Path $launcherRoot ('.staging.{0}' -f [Guid]::NewGuid().ToString('N'))
    try {
        [void][System.IO.Directory]::CreateDirectory($stagingRoot)
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $stagingRoot -ExpectedType Directory)
        $stagingLauncher = Join-Path $stagingRoot 'Start-HelloApprovalAgent.ps1'
        $stagingValidationModule = Join-Path $stagingRoot 'HelloApproval.Validation.psm1'
        [System.IO.File]::Copy($sourceLauncher, $stagingLauncher, $false)
        [System.IO.File]::Copy($sourceValidationModule, $stagingValidationModule, $false)
        $stagedHash = Get-FileSha256 -Path $stagingLauncher
        $stagedModuleHash = Get-FileSha256 -Path $stagingValidationModule
        if ($stagedHash -cne $launcherHash -or $stagedModuleHash -cne $validationModuleHash) {
            throw 'Staged launcher bundle hash mismatch.'
        }
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $launcherVersionRoot -ExpectedType Directory -AllowMissing)
        [System.IO.Directory]::Move($stagingRoot, $launcherVersionRoot)
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $launcherVersionRoot -ExpectedType Directory)
    } catch {
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUser = $identity.Name
$currentSid = $identity.User.Value
$powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$powershellPath = Assert-RegularFile -Path $powershellPath -Purpose 'Windows PowerShell 5.1'

$actionArguments = @(
    '-NoProfile',
    '-NonInteractive',
    '-WindowStyle', 'Hidden',
    '-ExecutionPolicy', 'RemoteSigned',
    '-File', (Quote-WindowsArgument -Value $installedLauncher),
    '-AgentPath', (Quote-WindowsArgument -Value $agentPath),
    '-ConfigPath', (Quote-WindowsArgument -Value $configPath),
    '-SocketPath', (Quote-WindowsArgument -Value $SocketPath)
) -join ' '

$action = New-ScheduledTaskAction -Execute $powershellPath -Argument $actionArguments -WorkingDirectory $launcherVersionRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$needsRegistration = $true
if ($null -ne $existingTask) {
    $needsRegistration = -not (Test-TaskMatchesDesired -Xml $existingXml -ExpectedSid $currentSid -ExpectedUser $currentUser -ExpectedPowerShell $powershellPath -ExpectedArguments $actionArguments -ExpectedWorkingDirectory $launcherVersionRoot)
}

if ($needsRegistration) {
    if ($PSCmdlet.ShouldProcess("$TaskPath$TaskName", 'Register/update owned interactive Scheduled Task')) {
        try {
            if ($null -ne $existingTask -and $wasRunning) {
                Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
                Wait-TaskNotRunning -Name $TaskName -RequirePipeFree
            }
            Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $TaskMarker -Force | Out-Null
            $registeredXml = Get-TaskXml -Name $TaskName
            Assert-OwnedTask -Xml $registeredXml
            if (-not (Test-TaskMatchesDesired -Xml $registeredXml -ExpectedSid $currentSid -ExpectedUser $currentUser -ExpectedPowerShell $powershellPath -ExpectedArguments $actionArguments -ExpectedWorkingDirectory $launcherVersionRoot)) {
                throw 'Task Scheduler did not persist the requested HA-1.3 critical definition.'
            }
            if ($wasRunning -or $StartNow) {
                Assert-DedicatedPipeFree
                Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
                Wait-TaskRunningAndPipe -Name $TaskName
            }
        } catch {
            $originalError = $_
            if ($null -ne $existingXmlText) {
                try {
                    $failedTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
                    if ($null -ne $failedTask -and $failedTask.State -eq 'Running') {
                        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
                        Wait-TaskNotRunning -Name $TaskName -RequirePipeFree
                    }
                    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Xml $existingXmlText -Force | Out-Null
                    if ($wasRunning) {
                        Assert-DedicatedPipeFree
                        Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
                        Wait-TaskRunningAndPipe -Name $TaskName
                    }
                } catch {
                    Write-Warning "Failed to restore previous owned task after update failure: $($_.Exception.Message)"
                }
            } else {
                try {
                    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
                } catch {
                    Write-Warning "Failed to remove partially-created task after failure: $($_.Exception.Message)"
                }
            }
            throw $originalError
        }
    }
} elseif ($StartNow) {
    $currentTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    if ($currentTask.State -ne 'Running' -and $PSCmdlet.ShouldProcess("$TaskPath$TaskName", 'Start existing owned Scheduled Task')) {
        Assert-DedicatedPipeFree
        Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
        Wait-TaskRunningAndPipe -Name $TaskName
    } elseif ($currentTask.State -eq 'Running') {
        Wait-TaskRunningAndPipe -Name $TaskName
    }
}

if (-not $WhatIfPreference) {
    $finalTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
    $finalXml = Get-TaskXml -Name $TaskName
    Assert-OwnedTask -Xml $finalXml
    if (-not (Test-TaskMatchesDesired -Xml $finalXml -ExpectedSid $currentSid -ExpectedUser $currentUser -ExpectedPowerShell $powershellPath -ExpectedArguments $actionArguments -ExpectedWorkingDirectory $launcherVersionRoot)) {
        throw 'Registered task does not match the HA-1.3 critical definition.'
    }
    Write-Host "HA-1.3 Scheduled Task is installed and verified: $TaskPath$TaskName (state=$($finalTask.State))"
    Write-Host "Launcher: $installedLauncher"
}
