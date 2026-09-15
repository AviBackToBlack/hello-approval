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

function Assert-RealDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Purpose is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Purpose must be a real non-reparse directory: $Path"
    }
}

function Ensure-RealDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Assert-RealDirectory -Path $Path -Purpose 'Project directory'
        return
    }
    [void][System.IO.Directory]::CreateDirectory($Path)
    Assert-RealDirectory -Path $Path -Purpose 'New project directory'
}

function Assert-PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$FilePin
    )

    $resolved = Assert-RegularFile -Path $Path -Purpose $FilePin.name
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Length -ne [int64]$FilePin.size_bytes) {
        throw "Pinned size mismatch: $resolved"
    }
    $actual = Get-FileSha256 -Path $resolved
    if ($actual -ne ([string]$FilePin.sha256).ToLowerInvariant()) {
        throw "Pinned SHA-256 mismatch: $resolved"
    }
    return $resolved
}

function Assert-PinnedRuntimeSurface {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][object]$Pin
    )

    Assert-RealDirectory -Path $RuntimeRoot -Purpose 'Pinned runtime root'
    $rootItems = @(Get-ChildItem -LiteralPath $RuntimeRoot -Force)
    if ($rootItems.Count -ne 1 -or $rootItems[0].Name -ne 'bin' -or -not $rootItems[0].PSIsContainer -or ($rootItems[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Pinned runtime root surface must contain exactly one real bin directory: $RuntimeRoot"
    }

    $binPath = Join-Path $RuntimeRoot 'bin'
    $required = @($Pin.installation_policy.installed_files)
    $actualItems = @(Get-ChildItem -LiteralPath $binPath -Force)
    $actualNames = @($actualItems | ForEach-Object { $_.Name })
    $exactNames = $actualNames.Count -eq $required.Count
    if ($exactNames) {
        foreach ($requiredName in $required) {
            if (-not ($actualNames -ccontains $requiredName)) {
                $exactNames = $false
                break
            }
        }
    }
    $nonFiles = @($actualItems | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
    if (-not $exactNames -or $nonFiles.Count -ne 0) {
        throw "Pinned runtime bin surface differs from installation_policy.installed_files: $binPath"
    }

    foreach ($name in $required) {
        $filePin = $Pin.files | Where-Object { $_.name -eq $name -and $_.policy.disposition -eq 'required' } | Select-Object -First 1
        if ($null -eq $filePin) {
            throw "Required runtime file '$name' has no required provenance record."
        }
        [void](Assert-PinnedFile -Path (Join-Path $binPath $name) -FilePin $filePin)
    }
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

    $labelsValue = ([string]$values['allowed_labels']) -replace '\s', ''
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
    $actionNodes = @($Xml.SelectNodes('/t:Task/t:Actions/t:Exec', $ns))
    $triggerNodes = @($Xml.SelectNodes('/t:Task/t:Triggers/t:LogonTrigger', $ns))
    if ($actionNodes.Count -ne 1 -or $triggerNodes.Count -ne 1) { return $false }

    $runLevel = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Principals/t:Principal/t:RunLevel'
    $taskEnabled = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Settings/t:Enabled'
    $triggerEnabled = Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Triggers/t:LogonTrigger/t:Enabled'
    $checks = @(
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:RegistrationInfo/t:Description') -eq $TaskMarker),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Principals/t:Principal/t:UserId') -eq $ExpectedSid),
        ((Get-XmlText -Xml $Xml -Ns $ns -XPath '/t:Task/t:Principals/t:Principal/t:LogonType') -eq 'InteractiveToken'),
        (($null -eq $runLevel) -or $runLevel -eq 'LeastPrivilege'),
        (($null -eq $taskEnabled) -or $taskEnabled -eq 'true'),
        (($null -eq $triggerEnabled) -or $triggerEnabled -eq 'true'),
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
$pinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'
$sourceLauncher = Join-Path $PSScriptRoot 'Start-HelloApprovalAgent.ps1'
$pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
if ($pin.schema -ne 'hello-approval/upstream-pin/v1') {
    throw "Unsupported provenance pin schema: $($pin.schema)"
}
if ($pin.installation_policy.target_architecture -ne 'x86_64-pc-windows-msvc') {
    throw "Unsupported pinned target architecture: $($pin.installation_policy.target_architecture)"
}
if ($pin.installation_policy.allowed_distribution -ne 'zip-manual-placement') {
    throw "Unsupported pinned distribution policy: $($pin.installation_policy.allowed_distribution)"
}
$requiredByPolicy = @($pin.files | Where-Object { $_.policy.disposition -eq 'required' } | ForEach-Object { $_.name } | Sort-Object)
$installedByPolicy = @($pin.installation_policy.installed_files | Sort-Object)
if (@(Compare-Object -ReferenceObject $requiredByPolicy -DifferenceObject $installedByPolicy).Count -ne 0) {
    throw 'Pin inconsistency: installed_files must exactly match files with policy.disposition=required.'
}

$releaseTag = [string]$pin.upstream.release_tag
$runtimeRoot = Join-Path $env:LOCALAPPDATA ("hello-approval\runtime\sshenc\{0}" -f $releaseTag)
$runtimeBin = Join-Path $runtimeRoot 'bin'
Assert-PinnedRuntimeSurface -RuntimeRoot $runtimeRoot -Pin $pin
$sshencPath = Assert-RegularFile -Path (Join-Path $runtimeBin 'sshenc.exe') -Purpose 'Pinned sshenc.exe'
$agentPath = Assert-RegularFile -Path (Join-Path $runtimeBin 'sshenc-agent.exe') -Purpose 'Pinned sshenc-agent.exe'

$configOutput = @(& $sshencPath config path 2>&1 | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -ne '' })
if ($LASTEXITCODE -ne 0 -or $configOutput.Count -ne 1) {
    throw "Pinned sshenc.exe did not return exactly one config path (exit=$LASTEXITCODE, lines=$($configOutput.Count))."
}
$configPath = Assert-RegularFile -Path $configOutput[0] -Purpose 'sshenc config'
Assert-EffectiveConfig -SshencPath $sshencPath

$sourceLauncher = Assert-RegularFile -Path $sourceLauncher -Purpose 'Repository HA-1.2 launcher'
$launcherHash = Get-FileSha256 -Path $sourceLauncher
$projectRoot = Join-Path $env:LOCALAPPDATA 'hello-approval'
$appRoot = Join-Path $projectRoot 'app'
$launcherRoot = Join-Path $appRoot 'launcher'
$launcherVersionRoot = Join-Path $launcherRoot $launcherHash
$installedLauncher = Join-Path $launcherVersionRoot 'Start-HelloApprovalAgent.ps1'

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

Assert-RealDirectory -Path $projectRoot -Purpose 'hello-approval project root'
foreach ($existingParent in @($appRoot, $launcherRoot)) {
    if (Test-Path -LiteralPath $existingParent) {
        Assert-RealDirectory -Path $existingParent -Purpose 'Existing launcher parent directory'
    }
}

if (Test-Path -LiteralPath $launcherVersionRoot) {
    Assert-RealDirectory -Path $launcherVersionRoot -Purpose 'Installed launcher digest directory'
    $items = @(Get-ChildItem -LiteralPath $launcherVersionRoot -Force)
    if ($items.Count -ne 1 -or $items[0].Name -ne 'Start-HelloApprovalAgent.ps1' -or $items[0].PSIsContainer -or ($items[0].Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Installed launcher digest surface is not exact: $launcherVersionRoot"
    }
    $existingHash = Get-FileSha256 -Path $installedLauncher
    if ($existingHash -ne $launcherHash) {
        throw "Installed launcher digest path contains mismatched bytes: $installedLauncher"
    }
} elseif ($PSCmdlet.ShouldProcess($launcherVersionRoot, 'Install content-addressed HA-1.2 launcher')) {
    Ensure-RealDirectory -Path $projectRoot
    Ensure-RealDirectory -Path $appRoot
    Ensure-RealDirectory -Path $launcherRoot
    $stagingRoot = Join-Path $launcherRoot ('.staging.{0}' -f [Guid]::NewGuid().ToString('N'))
    try {
        [void][System.IO.Directory]::CreateDirectory($stagingRoot)
        $stagingLauncher = Join-Path $stagingRoot 'Start-HelloApprovalAgent.ps1'
        [System.IO.File]::Copy($sourceLauncher, $stagingLauncher, $false)
        $stagedHash = Get-FileSha256 -Path $stagingLauncher
        if ($stagedHash -ne $launcherHash) {
            throw 'Staged launcher hash mismatch.'
        }
        [System.IO.Directory]::Move($stagingRoot, $launcherVersionRoot)
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
