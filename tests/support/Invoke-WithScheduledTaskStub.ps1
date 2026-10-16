#requires -Version 5.1
# Test support (not a suite): runs a hello-approval script while a same-name Scheduled Task is
# simulated by in-scope stubs that shadow the ScheduledTasks cmdlets. Every mutating call is logged,
# so harnesses can prove what the target did or did not touch. Registration throws a sentinel,
# keeping the run at the registration boundary. No real Task Scheduler state is read or changed
# for the simulated task.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [Parameter(Mandatory = $true)][string]$CallLog,
    [AllowNull()][string]$Description,
    [switch]$NoDescription,
    [ValidateSet('Ready', 'Running', 'Disabled')][string]$State = 'Ready',
    [string[]]$Switches = @(),
    # Set for targets that end with an explicit `exit N` (Doctor). Otherwise, like `powershell -File`,
    # a normal completion exits 0 even if the last native command returned non-zero, and a terminating
    # error exits 1 through $ErrorActionPreference = 'Stop'.
    [switch]$UseScriptExitCode
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

foreach ($switchName in $Switches) {
    if ($switchName -cnotmatch '\A-[A-Za-z]+\z') { throw "Unsupported forwarded switch: $switchName" }
}

# Load the real ScheduledTasks module first. Otherwise its first builder call in the target
# (New-ScheduledTaskAction and friends) auto-imports it mid-run, and the real CDXML functions then win
# name resolution over the stubs below.
Import-Module ScheduledTasks -ErrorAction Stop

[IO.File]::WriteAllText($CallLog, '', [Text.UTF8Encoding]::new($false))
# Global, not $script:, scope: inside a stub called from the target, $script: resolves to the target's
# script scope, not this wrapper's.
$global:HelloApprovalTaskStubState = @{
    Exists = $true
    State = $State
    Description = $Description
    NoDescription = [bool]$NoDescription
    CallLog = $CallLog
}

function Add-StubCall([string]$Verb, [string]$TaskName, [string]$TaskPath) {
    [IO.File]::AppendAllText($global:HelloApprovalTaskStubState.CallLog, ("{0} {1}{2}`n" -f $Verb, $TaskPath, $TaskName), [Text.UTF8Encoding]::new($false))
}

function Get-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Get' $TaskName $TaskPath
    if (-not $global:HelloApprovalTaskStubState.Exists) { return $null }
    return [pscustomobject]@{ TaskName = $TaskName; TaskPath = $TaskPath; State = $global:HelloApprovalTaskStubState.State }
}

function Get-ScheduledTaskInfo {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'GetInfo' $TaskName $TaskPath
    return [pscustomobject]@{ TaskName = $TaskName; TaskPath = $TaskPath; LastTaskResult = 0; NumberOfMissedRuns = 0 }
}

function Export-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Export' $TaskName $TaskPath
    $info = if ($global:HelloApprovalTaskStubState.NoDescription) {
        '<RegistrationInfo />'
    } else {
        '<RegistrationInfo><Description>' + [Security.SecurityElement]::Escape([string]$global:HelloApprovalTaskStubState.Description) + '</Description></RegistrationInfo>'
    }
    return '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + $info +
        '<Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals>' +
        '<Actions Context="Author"><Exec><Command>C:\simulated\foreign.exe</Command></Exec></Actions></Task>'
}

function Stop-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Stop' $TaskName $TaskPath
    $global:HelloApprovalTaskStubState.State = 'Ready'
}

function Start-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Start' $TaskName $TaskPath
}

function Disable-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Disable' $TaskName $TaskPath
}

function Enable-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Enable' $TaskName $TaskPath
}

function Set-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Set' $TaskName $TaskPath
    throw 'HELLO_APPROVAL_TEST_REGISTRATION_BOUNDARY'
}

function Unregister-ScheduledTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$TaskName, [string]$TaskPath)
    Add-StubCall 'Unregister' $TaskName $TaskPath
    $global:HelloApprovalTaskStubState.Exists = $false
}

function Register-ScheduledTask {
    [CmdletBinding()]
    param([string]$TaskName, [string]$TaskPath, $Action, $Trigger, $Principal, $Settings, [string]$Description, $Xml, [switch]$Force)
    Add-StubCall 'Register' $TaskName $TaskPath
    throw 'HELLO_APPROVAL_TEST_REGISTRATION_BOUNDARY'
}

# Interlock: every stubbed Task Scheduler command (mutating and read-only) must resolve to a stub defined
# above, both now and after the real module's builders have been exercised, or the target is never run.
$stubbedCommands = @('Register-ScheduledTask', 'Unregister-ScheduledTask', 'Stop-ScheduledTask', 'Start-ScheduledTask', 'Disable-ScheduledTask', 'Enable-ScheduledTask', 'Set-ScheduledTask', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo', 'Export-ScheduledTask')
$null = New-ScheduledTaskAction -Execute 'cmd.exe'
foreach ($commandName in $stubbedCommands) {
    $resolved = Get-Command -Name $commandName -ErrorAction Stop
    if ($resolved.CommandType -ne 'Function' -or -not [string]::IsNullOrEmpty($resolved.Source)) {
        throw "Task Scheduler stub interlock: $commandName resolves to '$($resolved.Source)' instead of the test stub."
    }
}

$global:LASTEXITCODE = 0
$invocation = [scriptblock]::Create('& $Target ' + ($Switches -join ' '))
& $invocation
if ($UseScriptExitCode) { exit $global:LASTEXITCODE }
exit 0
