#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'hello-approval Git Signing Agent'
$TaskPath = '\'
$TaskMarker = 'hello-approval/ha-1.3/v1'

function Get-TaskXml {
    return [xml](Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath)
}

function Get-TaskDescription {
    param([Parameter(Mandatory = $true)][xml]$Xml)
    $ns = New-Object Xml.XmlNamespaceManager($Xml.NameTable)
    $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $node = $Xml.SelectSingleNode('/t:Task/t:RegistrationInfo/t:Description', $ns)
    if ($null -eq $node) { return $null }
    return [string]$node.InnerText
}

function Wait-TaskNotRunning {
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        if ($null -eq $task -or $task.State -ne 'Running') { return }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for task to stop: $TaskPath$TaskName"
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Uninstall-HelloApprovalScheduledTask.ps1 supports Windows only.'
}

$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($null -eq $task) {
    Write-Host "HA-1.3 Scheduled Task is not installed: $TaskPath$TaskName"
    return
}

$xml = Get-TaskXml
$description = Get-TaskDescription -Xml $xml
if ($description -ne $TaskMarker) {
    throw "Refusing to remove foreign task '$TaskPath$TaskName'; ownership marker is '$description'."
}

if ($PSCmdlet.ShouldProcess("$TaskPath$TaskName", 'Stop and unregister owned hello-approval Scheduled Task')) {
    if ($task.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
        Wait-TaskNotRunning
    }
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
}

Write-Host 'Only the owned Scheduled Task was removed. Runtime, config, credentials, Git/SSH settings, and content-addressed launcher cache were left unchanged.'
