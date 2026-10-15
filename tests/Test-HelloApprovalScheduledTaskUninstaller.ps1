#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Test-HelloApprovalScheduledTaskUninstaller.ps1 supports Windows only.' }

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceUninstaller = Join-Path $repoRoot 'scripts\Uninstall-HelloApprovalScheduledTask.ps1'
$taskName = 'hello-approval Git Signing Agent'
$taskMarker = 'hello-approval/ha-1.3/v1'

$script:Passed = 0
$script:Failed = 0
$script:StubCallCount = 0
$script:WrongTargets = New-Object System.Collections.Generic.List[string]
function Pass([string]$Name) { $script:Passed++; Write-Host "PASS  $Name" }
function Fail([string]$Name,[string]$Message) { $script:Failed++; Write-Host "FAIL  $Name - $Message" }

# Defense in depth: every Task Scheduler call below is stubbed, but refuse to run beside a real install.
$existingTask = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    throw "Test precondition failed: Scheduled Task already exists: \$taskName"
}

function Invoke-UninstallerWithStubs {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Task,
        [switch]$WhatIf
    )

    $state = @{
        Exists = [bool]$Task['Exists']
        State = [string]$Task['State']
        Description = $Task['Description']
        HasDescription = [bool]$Task['HasDescription']
        StopCompletes = [bool]$Task['StopCompletes']
        Calls = New-Object System.Collections.Generic.List[string]
        WrongTargets = New-Object System.Collections.Generic.List[string]
        ExpectedName = $taskName
        ExpectedPath = '\'
    }

    $caught = $null
    $output = @()
    try {
        $output = @(& {
            param($UninstallerPath, $State, $UseWhatIf)

            function Add-StubCall([string]$Verb, [string]$Name, [string]$Path) {
                $State.Calls.Add($Verb)
                if ($Name -cne $State.ExpectedName -or $Path -cne $State.ExpectedPath) { $State.WrongTargets.Add("${Verb}:$Path$Name") }
            }

            function Get-ScheduledTask {
                [CmdletBinding()]
                param([string]$TaskName, [string]$TaskPath)
                Add-StubCall 'Get' $TaskName $TaskPath
                if (-not $State.Exists) { return $null }
                return [pscustomobject]@{ TaskName = $TaskName; TaskPath = $TaskPath; State = $State.State }
            }

            function Export-ScheduledTask {
                [CmdletBinding()]
                param([string]$TaskName, [string]$TaskPath)
                Add-StubCall 'Export' $TaskName $TaskPath
                $info = if ($State.HasDescription) {
                    '<RegistrationInfo><Description>' + [Security.SecurityElement]::Escape([string]$State.Description) + '</Description></RegistrationInfo>'
                } else {
                    '<RegistrationInfo />'
                }
                return '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + $info + '</Task>'
            }

            function Stop-ScheduledTask {
                [CmdletBinding()]
                param([string]$TaskName, [string]$TaskPath)
                Add-StubCall 'Stop' $TaskName $TaskPath
                if ($State.StopCompletes) { $State.State = 'Ready' }
            }

            function Unregister-ScheduledTask {
                [CmdletBinding(SupportsShouldProcess = $true)]
                param([string]$TaskName, [string]$TaskPath)
                Add-StubCall 'Unregister' $TaskName $TaskPath
                $State.Exists = $false
            }

            if ($UseWhatIf) { & $UninstallerPath -WhatIf 6>&1 } else { & $UninstallerPath -Confirm:$false 6>&1 }
        } $sourceUninstaller $state ([bool]$WhatIf) | ForEach-Object { [string]$_ })
    } catch {
        $caught = [string]$_.Exception.Message
    }
    $script:StubCallCount += $state.Calls.Count
    foreach ($wrong in $state.WrongTargets) { $script:WrongTargets.Add($wrong) }

    return [pscustomobject]@{
        Calls = @($state.Calls)
        Error = $caught
        Output = ($output -join ' | ')
        FinalExists = $state.Exists
    }
}

function Describe($Result) {
    return ("calls=[{0}] error={1} output={2}" -f ($Result.Calls -join ','), $Result.Error, $Result.Output)
}

# Absent task: no-op, no mutation.
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $false }
if ($null -eq $r.Error -and ($r.Calls -join ',') -ceq 'Get' -and $r.Output -match 'is not installed') { Pass 'absent task is a no-op' }
else { Fail 'absent task is a no-op' (Describe $r) }

# Foreign marker: refuse before any stop/unregister.
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $true; State = 'Ready'; HasDescription = $true; Description = 'someone-else/v1' }
if ($r.Error -match 'Refusing to remove foreign task' -and -not ($r.Calls -contains 'Stop') -and -not ($r.Calls -contains 'Unregister') -and $r.FinalExists) { Pass 'foreign ownership marker is refused before mutation' }
else { Fail 'foreign ownership marker is refused before mutation' (Describe $r) }

# Missing description node: treated as foreign.
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $true; State = 'Ready'; HasDescription = $false }
if ($r.Error -match 'Refusing to remove foreign task' -and -not ($r.Calls -contains 'Unregister') -and $r.FinalExists) { Pass 'missing ownership marker is refused before mutation' }
else { Fail 'missing ownership marker is refused before mutation' (Describe $r) }

# Empty description: treated as foreign.
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $true; State = 'Ready'; HasDescription = $true; Description = '' }
if ($r.Error -match 'Refusing to remove foreign task' -and -not ($r.Calls -contains 'Unregister') -and $r.FinalExists) { Pass 'empty ownership marker is refused before mutation' }
else { Fail 'empty ownership marker is refused before mutation' (Describe $r) }

# Owned, not running: unregister without stop.
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $true; State = 'Ready'; HasDescription = $true; Description = $taskMarker }
if ($null -eq $r.Error -and -not ($r.Calls -contains 'Stop') -and ($r.Calls -contains 'Unregister') -and -not $r.FinalExists -and $r.Output -match 'Only the owned Scheduled Task was removed') { Pass 'owned idle task is unregistered without stop' }
else { Fail 'owned idle task is unregistered without stop' (Describe $r) }

# Owned, running: stop, wait until not running, then unregister (in that order).
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $true; State = 'Running'; HasDescription = $true; Description = $taskMarker; StopCompletes = $true }
$stopIndex = [array]::IndexOf([object[]]$r.Calls, 'Stop')
$unregisterIndex = [array]::IndexOf([object[]]$r.Calls, 'Unregister')
if ($null -eq $r.Error -and $stopIndex -ge 0 -and $unregisterIndex -gt $stopIndex -and -not $r.FinalExists) { Pass 'owned running task is stopped before unregistration' }
else { Fail 'owned running task is stopped before unregistration' (Describe $r) }

# Owned, running, never stops: time out and leave the task registered.
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $true; State = 'Running'; HasDescription = $true; Description = $taskMarker; StopCompletes = $false }
if ($r.Error -match 'Timed out waiting for task to stop' -and ($r.Calls -contains 'Stop') -and -not ($r.Calls -contains 'Unregister') -and $r.FinalExists) { Pass 'stop timeout fails closed without unregistering' }
else { Fail 'stop timeout fails closed without unregistering' (Describe $r) }

# -WhatIf on an owned running task: no stop, no unregister.
$r = Invoke-UninstallerWithStubs -Task @{ Exists = $true; State = 'Running'; HasDescription = $true; Description = $taskMarker; StopCompletes = $true } -WhatIf
if ($null -eq $r.Error -and -not ($r.Calls -contains 'Stop') -and -not ($r.Calls -contains 'Unregister') -and $r.FinalExists -and $r.Output -match 'left unchanged') { Pass '-WhatIf leaves an owned running task untouched' }
else { Fail '-WhatIf leaves an owned running task untouched' (Describe $r) }

# Every stubbed call must target the documented task identity (docs/SCHEDULED-TASK.md).
if ($script:StubCallCount -gt 0 -and $script:WrongTargets.Count -eq 0) { Pass ("all {0} stubbed calls target \{1}" -f $script:StubCallCount, $taskName) }
else { Fail 'all stubbed calls target the documented task' ("calls={0} wrong=[{1}]" -f $script:StubCallCount, ($script:WrongTargets -join ',')) }

# Stubs must have intercepted every Task Scheduler call: the real task must still be absent.
if ($null -eq (Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue)) { Pass 'no real Scheduled Task was created or touched' }
else { Fail 'no real Scheduled Task was created or touched' 'real task exists after run' }

Write-Host ''
Write-Host ("RESULT passed={0} failed={1}" -f $script:Passed, $script:Failed)
if ($script:Failed -ne 0) { exit 1 }
exit 0
