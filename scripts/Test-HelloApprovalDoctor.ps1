#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Repo,
    [switch]$Json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'hello-approval Git Signing Agent'
$TaskPath = '\'
$TaskMarker = 'hello-approval/ha-1.3/v1'
$SocketPath = '\\.\pipe\sshenc-github-signing'
$SigningSchema = 'hello-approval/ha-1.4/v1'
$VerificationSchema = 'hello-approval/ha-1.5/v1'
$ExpectedKeyType = 'sk-ecdsa-sha2-nistp256@openssh.com'

$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS','INFO','WARN','BLOCK')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Message,
        $Value
    )

    $finding = [ordered]@{
        severity = $Severity
        check = $Check
        message = $Message
    }
    if ($PSBoundParameters.ContainsKey('Value')) {
        $finding.value = $Value
    }
    [void]$findings.Add([pscustomobject]$finding)
}

function Test-WindowsPathEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $leftNormalized = $Left -replace '\\','/'
    $rightNormalized = $Right -replace '\\','/'
    return [string]::Equals($leftNormalized, $rightNormalized, [StringComparison]::OrdinalIgnoreCase)
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Test-PinnedRuntimeFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Pin,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-Finding -Severity 'BLOCK' -Check "runtime.$Name" -Message 'Pinned runtime file is missing.' -Value $Path
        return $false
    }

    try {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Add-Finding -Severity 'BLOCK' -Check "runtime.$Name" -Message 'Pinned runtime executable must be a regular non-reparse file.' -Value $Path
            return $false
        }

        $record = @($Pin.files | Where-Object { $_.name -ceq $Name -and $_.policy.disposition -eq 'required' })
        if ($record.Count -ne 1) {
            Add-Finding -Severity 'BLOCK' -Check "runtime.$Name" -Message 'Provenance pin must contain exactly one required runtime record.' -Value $Name
            return $false
        }

        $expectedSize = [int64]$record[0].size_bytes
        $expectedHash = ([string]$record[0].sha256).ToLowerInvariant()
        $actualHash = Get-FileSha256 -Path $Path
        if ($item.Length -ne $expectedSize -or $actualHash -cne $expectedHash) {
            Add-Finding -Severity 'BLOCK' -Check "runtime.$Name" -Message 'Pinned runtime executable does not match provenance; refusing to execute it.' -Value ([pscustomobject]@{
                path = $Path
                expectedSize = $expectedSize
                actualSize = [int64]$item.Length
                expectedSha256 = $expectedHash
                actualSha256 = $actualHash
            })
            return $false
        }

        Add-Finding -Severity 'PASS' -Check "runtime.$Name" -Message 'Pinned runtime executable matches provenance and is safe to invoke for read-only inspection.' -Value $Path
        return $true
    } catch {
        Add-Finding -Severity 'BLOCK' -Check "runtime.$Name" -Message 'Could not validate pinned runtime executable provenance.' -Value $_.Exception.Message
        return $false
    }
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowExitOne,
        [switch]$IncludeStderr
    )

    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($IncludeStderr) {
            $output = @(& $Exe @Arguments 2>&1 | ForEach-Object { [string]$_ })
        } else {
            $output = @(& $Exe @Arguments 2>$null | ForEach-Object { [string]$_ })
        }
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }

    if ($rc -eq 0 -or ($AllowExitOne -and $rc -eq 1)) {
        return [pscustomobject]@{ ExitCode = $rc; Output = $output }
    }

    $detail = if ($output.Count -gt 0) { ' ' + ($output -join ' | ') } else { '' }
    throw "$Context failed with exit $rc.$detail"
}

function Invoke-ContractProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$Arguments = @()
    )

    $powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $powershellPath -PathType Leaf)) {
        Add-Finding -Severity 'BLOCK' -Check "contract.$Name" -Message 'Windows PowerShell 5.1 is missing.' -Value $powershellPath
        return
    }

    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$ScriptPath) + $Arguments + @('-WhatIf')
    try {
        $result = Invoke-Native -Exe $powershellPath -Arguments $args -Context "Read-only contract probe $Name" -IncludeStderr
        Add-Finding -Severity 'PASS' -Check "contract.$Name" -Message 'Existing installed state satisfies the installer read-only contract checks.' -Value (($result.Output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' | ')
    } catch {
        Add-Finding -Severity 'BLOCK' -Check "contract.$Name" -Message 'Installed state fails the corresponding installer read-only contract checks.' -Value $_.Exception.Message
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
    return [xml](Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath)
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
        $principalNodes.Count -ne 1) {
        return $false
    }

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
    try {
        $pipeLeaf = ($SocketPath -replace '^\\\\\.\\pipe\\', '')
        return @([IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [IO.Path]::GetFileName($_) } | Where-Object { $_ -ieq $pipeLeaf }).Count -gt 0
    } catch {
        Add-Finding -Severity 'WARN' -Check 'agent.pipe.enumeration' -Message 'Could not enumerate Windows named pipes.' -Value $_.Exception.Message
        return $false
    }
}

function Get-GitOne {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowAbsent
    )

    $result = Invoke-Native -Exe $Git -Arguments $Arguments -Context $Context -AllowExitOne
    if ($result.ExitCode -eq 1 -and $AllowAbsent) { return $null }
    if ($result.ExitCode -ne 0) { throw "$Context returned exit $($result.ExitCode)." }
    if ($result.Output.Count -ne 1) { throw "$Context returned $($result.Output.Count) lines; expected exactly one." }
    return [string]$result.Output[0]
}

function Get-GitAll {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $result = Invoke-Native -Exe $Git -Arguments $Arguments -Context $Context -AllowExitOne
    if ($result.ExitCode -eq 1) { return @() }
    if ($result.ExitCode -ne 0) { throw "$Context returned exit $($result.ExitCode)." }
    return @($result.Output)
}

function Test-RepoEffectiveGit {
    param(
        [Parameter(Mandatory = $true)][string]$Git,
        [Parameter(Mandatory = $true)][string]$RepoPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSshenc,
        [Parameter(Mandatory = $true)][string]$ExpectedPublicKey,
        [Parameter(Mandatory = $true)][string]$ExpectedAllowedSigners
    )

    try {
        $inside = Get-GitOne -Git $Git -Arguments @('-C',$RepoPath,'rev-parse','--is-inside-work-tree') -Context 'Check target repository'
        if ($inside -ne 'true') { throw "Target path is not a Git worktree: $RepoPath" }

        $expected = [ordered]@{
            'gpg.format' = 'ssh'
            'gpg.ssh.program' = ($ExpectedSshenc -replace '\\','/')
            'user.signingkey' = ($ExpectedPublicKey -replace '\\','/')
            'gpg.ssh.allowedSignersFile' = ($ExpectedAllowedSigners -replace '\\','/')
        }

        foreach ($key in $expected.Keys) {
            $value = Get-GitOne -Git $Git -Arguments @('-C',$RepoPath,'config','--includes','--get',$key) -Context "Read effective target Git value $key" -AllowAbsent
            if ($null -eq $value) {
                Add-Finding -Severity 'BLOCK' -Check "git.target.$key" -Message 'Required effective target Git setting is absent.' -Value $RepoPath
                continue
            }
            $matches = if ($key -eq 'gpg.format') {
                $value -ceq $expected[$key]
            } else {
                Test-WindowsPathEqual -Left $value -Right $expected[$key]
            }
            if ($matches) {
                Add-Finding -Severity 'PASS' -Check "git.target.$key" -Message 'Effective target repository value matches hello-approval.' -Value $value
            } else {
                Add-Finding -Severity 'BLOCK' -Check "git.target.$key" -Message 'Effective target repository value overrides/mismatches hello-approval.' -Value ([pscustomobject]@{ expected = $expected[$key]; actual = $value; repo = $RepoPath })
            }
        }
    } catch {
        Add-Finding -Severity 'BLOCK' -Check 'git.target' -Message 'Could not validate effective Git state in target repository.' -Value $_.Exception.Message
    }
}

try {
    if ($env:OS -ne 'Windows_NT') {
        Add-Finding -Severity 'BLOCK' -Check 'platform' -Message 'hello-approval Doctor supports Windows only.' -Value $env:OS
        throw 'unsupported-platform'
    }

    foreach ($required in @('LOCALAPPDATA','USERPROFILE','APPDATA','SystemRoot')) {
        $value = [Environment]::GetEnvironmentVariable($required, 'Process')
        if ([string]::IsNullOrWhiteSpace($value)) {
            Add-Finding -Severity 'BLOCK' -Check "environment.$required" -Message 'Required Windows environment path is unavailable.'
        }
    }
    if (@($findings | Where-Object { $_.severity -eq 'BLOCK' }).Count -gt 0) {
        throw 'required-environment-missing'
    }

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $projectRoot = Join-Path $env:LOCALAPPDATA 'hello-approval'
    $gitRoot = Join-Path $projectRoot 'git'
    $signingConfig = Join-Path $gitRoot 'signing.gitconfig'
    $verificationConfig = Join-Path $gitRoot 'verification.gitconfig'
    $allowedSigners = Join-Path $gitRoot 'allowed_signers'
    $publicKey = Join-Path $env:USERPROFILE '.ssh\github-signing.pub'

    Add-Finding -Severity 'INFO' -Check 'project.root' -Message 'Expected hello-approval project root.' -Value $projectRoot

    $principal = $null
    if (Test-Path -LiteralPath $allowedSigners -PathType Leaf) {
        $lines = @(Get-Content -LiteralPath $allowedSigners)
        if ($lines.Count -lt 1 -or $lines[0] -cne ("# {0}" -f $VerificationSchema)) {
            Add-Finding -Severity 'BLOCK' -Check 'trust.ownership' -Message 'Project allowed_signers marker is missing or foreign.' -Value $allowedSigners
        } else {
            Add-Finding -Severity 'PASS' -Check 'trust.ownership' -Message 'Project allowed_signers ownership marker matches.' -Value $VerificationSchema
        }
        $entries = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#') })
        if ($entries.Count -eq 1 -and $entries[0] -match '\A(?<principal>[A-Za-z0-9][A-Za-z0-9@._+:-]*) namespaces="git" (?<type>\S+) (?<blob>[A-Za-z0-9+/]+={0,2})\z') {
            $principal = [string]$Matches.principal
            Add-Finding -Severity 'PASS' -Check 'trust.principal' -Message 'Project-owned allowed_signers exposes one exact Git namespace principal.' -Value $principal
        } else {
            Add-Finding -Severity 'BLOCK' -Check 'trust.principal' -Message 'Could not derive one exact principal from project-owned allowed_signers.' -Value $allowedSigners
        }
    } else {
        Add-Finding -Severity 'BLOCK' -Check 'trust.present' -Message 'Project-owned allowed_signers is missing.' -Value $allowedSigners
    }

    Invoke-ContractProbe -Name 'scheduled-task' -ScriptPath (Join-Path $PSScriptRoot 'Install-HelloApprovalScheduledTask.ps1')
    Invoke-ContractProbe -Name 'git-signing' -ScriptPath (Join-Path $PSScriptRoot 'Install-HelloApprovalGitConfig.ps1') -Arguments @('-OverrideExistingSigningConfig')
    if ($null -ne $principal) {
        Invoke-ContractProbe -Name 'local-verification' -ScriptPath (Join-Path $PSScriptRoot 'Install-HelloApprovalLocalVerification.ps1') -Arguments @('-Principal',$principal,'-OverrideExistingVerificationConfig')
    } else {
        Add-Finding -Severity 'BLOCK' -Check 'contract.local-verification' -Message 'Local-verification contract probe was skipped because the current principal could not be derived.'
    }

    $pinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'
    $pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
    $releaseTag = [string]$pin.upstream.release_tag
    $runtimeRoot = Join-Path $projectRoot ("runtime\sshenc\{0}" -f $releaseTag)
    $runtimeBin = Join-Path $runtimeRoot 'bin'
    $sshencPath = Join-Path $runtimeBin 'sshenc.exe'
    $agentPath = Join-Path $runtimeBin 'sshenc-agent.exe'

    $configPath = $null
    $sshencPinned = Test-PinnedRuntimeFile -Path $sshencPath -Pin $pin -Name 'sshenc.exe'
    if ($sshencPinned) {
        try {
            $configResult = Invoke-Native -Exe $sshencPath -Arguments @('config','path') -Context 'Resolve authoritative sshenc config path'
            if ($configResult.Output.Count -ne 1) { throw 'sshenc config path did not return exactly one line.' }
            $configPath = [IO.Path]::GetFullPath(([string]$configResult.Output[0]).Trim())
            Add-Finding -Severity 'PASS' -Check 'sshenc.config.path' -Message 'Authoritative sshenc config path resolved through the provenance-validated runtime.' -Value $configPath
        } catch {
            Add-Finding -Severity 'BLOCK' -Check 'sshenc.config.path' -Message 'Could not resolve authoritative sshenc config path.' -Value $_.Exception.Message
        }
    } else {
        Add-Finding -Severity 'BLOCK' -Check 'sshenc.config.path' -Message 'Skipped sshenc execution because the runtime executable did not pass provenance validation.' -Value $sshencPath
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUser = $identity.Name
    $currentSid = $identity.User.Value
    $powershellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $sourceLauncher = Join-Path $PSScriptRoot 'Start-HelloApprovalAgent.ps1'
    $launcherHash = if (Test-Path -LiteralPath $sourceLauncher -PathType Leaf) { Get-FileSha256 -Path $sourceLauncher } else { $null }
    $launcherVersionRoot = if ($null -ne $launcherHash) { Join-Path $projectRoot ("app\launcher\{0}" -f $launcherHash) } else { $null }
    $installedLauncher = if ($null -ne $launcherVersionRoot) { Join-Path $launcherVersionRoot 'Start-HelloApprovalAgent.ps1' } else { $null }

    $task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    $taskOwned = $false
    $taskMatches = $false
    if ($null -eq $task) {
        Add-Finding -Severity 'BLOCK' -Check 'task.present' -Message 'Owned hello-approval Scheduled Task is missing.' -Value "$TaskPath$TaskName"
    } else {
        try {
            $xml = Get-TaskXml
            $ns = New-TaskNamespaceManager -Xml $xml
            $description = Get-XmlText -Xml $xml -Ns $ns -XPath '/t:Task/t:RegistrationInfo/t:Description'
            if ($description -ne $TaskMarker) {
                Add-Finding -Severity 'BLOCK' -Check 'task.ownership' -Message 'Same-name Scheduled Task is not owned by hello-approval.' -Value $description
            } else {
                $taskOwned = $true
                Add-Finding -Severity 'PASS' -Check 'task.ownership' -Message 'Scheduled Task ownership marker matches.' -Value $TaskMarker

                if ($null -eq $configPath -or $null -eq $installedLauncher -or -not (Test-Path -LiteralPath $agentPath -PathType Leaf)) {
                    Add-Finding -Severity 'BLOCK' -Check 'task.definition' -Message 'Cannot derive exact desired task definition because required installed paths are missing.'
                } else {
                    $actionArguments = @(
                        '-NoProfile',
                        '-NonInteractive',
                        '-WindowStyle','Hidden',
                        '-ExecutionPolicy','RemoteSigned',
                        '-File',(Quote-WindowsArgument -Value $installedLauncher),
                        '-AgentPath',(Quote-WindowsArgument -Value $agentPath),
                        '-ConfigPath',(Quote-WindowsArgument -Value $configPath),
                        '-SocketPath',(Quote-WindowsArgument -Value $SocketPath)
                    ) -join ' '

                    $taskMatches = Test-TaskMatchesDesired -Xml $xml -ExpectedSid $currentSid -ExpectedUser $currentUser -ExpectedPowerShell $powershellPath -ExpectedArguments $actionArguments -ExpectedWorkingDirectory $launcherVersionRoot
                    if ($taskMatches) {
                        Add-Finding -Severity 'PASS' -Check 'task.definition' -Message 'Scheduled Task matches the exact HA-1.3 critical definition.'
                    } else {
                        Add-Finding -Severity 'BLOCK' -Check 'task.definition' -Message 'Scheduled Task differs from the exact HA-1.3 critical definition.'
                    }
                }
            }
        } catch {
            Add-Finding -Severity 'BLOCK' -Check 'task.definition' -Message 'Could not inspect Scheduled Task definition.' -Value $_.Exception.Message
        }
    }

    $pipePresent = Test-DedicatedPipePresent
    if ($pipePresent) {
        Add-Finding -Severity 'INFO' -Check 'agent.pipe' -Message 'Dedicated signing pipe is present.' -Value $SocketPath
    } else {
        Add-Finding -Severity 'INFO' -Check 'agent.pipe' -Message 'Dedicated signing pipe is absent.' -Value $SocketPath
    }

    if ($null -ne $task) {
        if ($task.State -eq 'Running' -and $pipePresent) {
            Add-Finding -Severity 'PASS' -Check 'task.runtime' -Message 'Owned task is Running and the dedicated pipe is present.'
        } elseif ($task.State -eq 'Running' -and -not $pipePresent) {
            Add-Finding -Severity 'BLOCK' -Check 'task.runtime' -Message 'Task reports Running but the dedicated pipe is absent.'
        } elseif ($task.State -ne 'Running' -and $pipePresent) {
            Add-Finding -Severity 'BLOCK' -Check 'agent.pipe.collision' -Message 'Dedicated pipe is occupied while the hello-approval task is not Running.' -Value $task.State
        } else {
            Add-Finding -Severity 'BLOCK' -Check 'task.runtime' -Message 'hello-approval task is not Running.' -Value $task.State
        }
    } elseif ($pipePresent) {
        Add-Finding -Severity 'BLOCK' -Check 'agent.pipe.collision' -Message 'Dedicated pipe is occupied without the owned hello-approval task.'
    }

    try {
        $agentProcesses = @(Get-CimInstance Win32_Process -Filter "Name='sshenc-agent.exe'" -ErrorAction Stop)
        $expectedProcesses = @()
        $foreignProcesses = @()
        foreach ($process in $agentProcesses) {
            $path = [string]$process.ExecutablePath
            if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-WindowsPathEqual -Left $path -Right $agentPath)) {
                $expectedProcesses += $process
            } else {
                $foreignProcesses += $process
            }
        }

        if ($expectedProcesses.Count -eq 1) {
            $cmd = [string]$expectedProcesses[0].CommandLine
            $commandMatches = $cmd -match '(?i)--foreground' -and
                $cmd -match [regex]::Escape($SocketPath) -and
                ($null -eq $configPath -or $cmd -match [regex]::Escape($configPath))
            if ($commandMatches) {
                Add-Finding -Severity 'PASS' -Check 'agent.process' -Message 'Exactly one pinned sshenc-agent process uses the dedicated signing contract.' -Value ([pscustomobject]@{ pid = $expectedProcesses[0].ProcessId; path = $expectedProcesses[0].ExecutablePath })
            } else {
                Add-Finding -Severity 'BLOCK' -Check 'agent.process' -Message 'Pinned sshenc-agent process command line does not match the dedicated signing contract.' -Value $cmd
            }
        } elseif ($expectedProcesses.Count -eq 0) {
            Add-Finding -Severity 'BLOCK' -Check 'agent.process' -Message 'No pinned sshenc-agent process is running.'
        } else {
            Add-Finding -Severity 'BLOCK' -Check 'agent.process' -Message 'Multiple pinned sshenc-agent processes are running.' -Value @($expectedProcesses | ForEach-Object { $_.ProcessId })
        }

        if ($foreignProcesses.Count -gt 0) {
            Add-Finding -Severity 'WARN' -Check 'agent.process.foreign' -Message 'Other sshenc-agent processes were observed outside the pinned hello-approval runtime.' -Value @($foreignProcesses | ForEach-Object { [pscustomobject]@{ pid = $_.ProcessId; path = $_.ExecutablePath; commandLine = $_.CommandLine } })
        } else {
            Add-Finding -Severity 'PASS' -Check 'agent.process.foreign' -Message 'No foreign sshenc-agent process was observed.'
        }
    } catch {
        Add-Finding -Severity 'WARN' -Check 'agent.process' -Message 'Could not inspect sshenc-agent processes through CIM.' -Value $_.Exception.Message
    }

    $takeoverFingerprint = $false
    foreach ($target in @('Process','User','Machine')) {
        $sshencOverride = [Environment]::GetEnvironmentVariable('SSHENC_AGENT_SOCKET', $target)
        if (-not [string]::IsNullOrWhiteSpace($sshencOverride)) {
            Add-Finding -Severity 'BLOCK' -Check "environment.$target.SSHENC_AGENT_SOCKET" -Message 'SSHENC_AGENT_SOCKET overrides the approved sshenc config socket.' -Value $sshencOverride
        } else {
            Add-Finding -Severity 'PASS' -Check "environment.$target.SSHENC_AGENT_SOCKET" -Message 'No SSHENC_AGENT_SOCKET override is present.'
        }

        foreach ($name in @('SSH_AUTH_SOCK','GIT_SSH_COMMAND')) {
            $value = [Environment]::GetEnvironmentVariable($name, $target)
            if ([string]::IsNullOrWhiteSpace($value)) {
                Add-Finding -Severity 'PASS' -Check "environment.$target.$name" -Message "$name is absent."
                continue
            }

            if ($value -match '(?i)sshenc' -or $value -match [regex]::Escape($SocketPath)) {
                $takeoverFingerprint = $true
                Add-Finding -Severity 'BLOCK' -Check "environment.$target.$name" -Message 'Persistent/process SSH integration points at sshenc or the dedicated signing pipe, which violates transport isolation.' -Value $value
            } else {
                Add-Finding -Severity 'WARN' -Check "environment.$target.$name" -Message "$name is set to unrelated user state; hello-approval does not own or modify it." -Value $value
            }
        }
    }

    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='ssh-agent'" -ErrorAction Stop
        if ($null -eq $svc) {
            Add-Finding -Severity 'INFO' -Check 'stock-ssh-agent' -Message 'Windows OpenSSH Authentication Agent service is not installed.'
        } else {
            $snapshot = [pscustomobject]@{ state = $svc.State; startMode = $svc.StartMode; startName = $svc.StartName }
            if ($svc.StartMode -eq 'Disabled') {
                $severity = if ($takeoverFingerprint) { 'BLOCK' } else { 'WARN' }
                Add-Finding -Severity $severity -Check 'stock-ssh-agent' -Message 'Stock ssh-agent is Disabled. Doctor cannot infer who changed it; combined with sshenc takeover fingerprints this is prohibited integration state.' -Value $snapshot
            } else {
                Add-Finding -Severity 'INFO' -Check 'stock-ssh-agent' -Message 'Observed stock ssh-agent service state. hello-approval does not mutate this service.' -Value $snapshot
            }
        }
    } catch {
        $svcFallback = Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue
        if ($null -eq $svcFallback) {
            Add-Finding -Severity 'INFO' -Check 'stock-ssh-agent' -Message 'Windows OpenSSH Authentication Agent service is not installed or could not be queried through CIM.'
        } else {
            Add-Finding -Severity 'INFO' -Check 'stock-ssh-agent' -Message 'Observed stock ssh-agent state through non-CIM fallback; startup mode is unavailable without broader service query access.' -Value ([pscustomobject]@{ state = [string]$svcFallback.Status; name = $svcFallback.Name })
        }
    }

    $sshConfigPath = Join-Path $env:USERPROFILE '.ssh\config'
    if (Test-Path -LiteralPath $sshConfigPath -PathType Leaf) {
        $sshConfigText = Get-Content -LiteralPath $sshConfigPath -Raw
        $sshConfigLines = @($sshConfigText -split '\r?\n')
        $includeLines = @($sshConfigLines | Where-Object { $_ -match '(?i)^\s*Include(?:\s*=\s*|\s+)' })
        $hasIncludes = $includeLines.Count -gt 0

        if ($sshConfigText -match '(?im)(sshenc-managed|BEGIN\s+sshenc\s+managed\s+block)') {
            Add-Finding -Severity 'BLOCK' -Check 'ssh.config.upstream-managed' -Message 'User SSH config contains an upstream sshenc-managed block, which is outside the hello-approval integration boundary.' -Value $sshConfigPath
        } elseif ($hasIncludes) {
            Add-Finding -Severity 'BLOCK' -Check 'ssh.config.upstream-managed' -Message 'Cannot prove absence of an upstream sshenc-managed block because SSH Include directives are present and included files are not recursively inspected in v0.1.' -Value $includeLines
        } else {
            Add-Finding -Severity 'PASS' -Check 'ssh.config.upstream-managed' -Message 'No upstream sshenc-managed block is present in the complete directly inspected SSH config.'
        }

        $identityAgentLines = @($sshConfigLines | Where-Object { $_ -match '(?i)^\s*IdentityAgent(?:\s*=\s*|\s+)' })
        if ($identityAgentLines.Count -gt 0) {
            $sshencIdentity = @($identityAgentLines | Where-Object { $_ -match '(?i)sshenc' -or $_ -match [regex]::Escape($SocketPath) })
            if ($sshencIdentity.Count -gt 0) {
                Add-Finding -Severity 'BLOCK' -Check 'ssh.config.identity-agent' -Message 'IdentityAgent points at sshenc/the signing pipe, which couples normal SSH transport to the signing agent.' -Value $sshencIdentity
            } elseif ($hasIncludes) {
                Add-Finding -Severity 'BLOCK' -Check 'ssh.config.identity-agent' -Message 'Cannot prove absence of a prohibited IdentityAgent because SSH Include directives are present and included files are not recursively inspected in v0.1.' -Value ([pscustomobject]@{ directIdentityAgent = @($identityAgentLines); includes = @($includeLines) })
            } else {
                Add-Finding -Severity 'WARN' -Check 'ssh.config.identity-agent' -Message 'Unrelated IdentityAgent configuration is present and remains outside hello-approval ownership.' -Value $identityAgentLines
            }
        } elseif ($hasIncludes) {
            Add-Finding -Severity 'BLOCK' -Check 'ssh.config.identity-agent' -Message 'Cannot prove absence of a prohibited IdentityAgent because SSH Include directives are present and included files are not recursively inspected in v0.1.' -Value $includeLines
        } else {
            Add-Finding -Severity 'PASS' -Check 'ssh.config.identity-agent' -Message 'No IdentityAgent directive is present in the complete directly inspected SSH config.'
        }
    } else {
        Add-Finding -Severity 'INFO' -Check 'ssh.config' -Message 'User SSH config does not exist.' -Value $sshConfigPath
    }
    $gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
    if ($null -eq $gitCommand) {
        Add-Finding -Severity 'BLOCK' -Check 'git.present' -Message 'Git executable is not available.'
    } else {
        $git = $gitCommand.Source
        Add-Finding -Severity 'PASS' -Check 'git.present' -Message 'Git executable is available.' -Value $git

        $ownedGitFiles = @(
            [pscustomobject]@{ path = $signingConfig; schema = $SigningSchema; check = 'git.signing-fragment' },
            [pscustomobject]@{ path = $verificationConfig; schema = $VerificationSchema; check = 'git.verification-fragment' }
        )
        foreach ($owned in $ownedGitFiles) {
            if (-not (Test-Path -LiteralPath $owned.path -PathType Leaf)) {
                Add-Finding -Severity 'BLOCK' -Check $owned.check -Message 'Owned Git config fragment is missing.' -Value $owned.path
                continue
            }
            try {
                $schemas = @(Get-GitAll -Git $git -Arguments @('config','--file',$owned.path,'--get-all','hello-approval.schema') -Context "Read schema values from $($owned.path)")
                if ($schemas.Count -eq 1 -and $schemas[0] -ceq $owned.schema) {
                    Add-Finding -Severity 'PASS' -Check $owned.check -Message 'Owned Git config fragment contains exactly one matching schema value.' -Value $owned.path
                } else {
                    Add-Finding -Severity 'BLOCK' -Check $owned.check -Message 'Owned Git config fragment must contain exactly one matching schema value.' -Value ([pscustomobject]@{ expected = $owned.schema; actual = @($schemas); count = $schemas.Count; path = $owned.path })
                }
            } catch {
                Add-Finding -Severity 'BLOCK' -Check $owned.check -Message 'Could not validate owned Git config fragment.' -Value $_.Exception.Message
            }
        }

        try {
            $directIncludes = @(Get-GitAll -Git $git -Arguments @('config','--global','--get-all','include.path') -Context 'Read direct global include.path')
            foreach ($ownedPath in @($signingConfig,$verificationConfig)) {
                $count = @($directIncludes | Where-Object { Test-WindowsPathEqual -Left ([string]$_) -Right $ownedPath }).Count
                $checkName = if (Test-WindowsPathEqual -Left $ownedPath -Right $signingConfig) { 'git.include.signing' } else { 'git.include.verification' }
                if ($count -eq 1) {
                    Add-Finding -Severity 'PASS' -Check $checkName -Message 'Direct global config contains exactly one owned include.path.' -Value $ownedPath
                } else {
                    Add-Finding -Severity 'BLOCK' -Check $checkName -Message 'Direct global config must contain exactly one owned include.path.' -Value ([pscustomobject]@{ path = $ownedPath; count = $count })
                }
            }
        } catch {
            Add-Finding -Severity 'BLOCK' -Check 'git.include' -Message 'Could not inspect direct global include.path values.' -Value $_.Exception.Message
        }

        $verifyRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        $verifyRootGitMarker = Join-Path $verifyRoot '.git'
        if (Test-Path -LiteralPath $verifyRootGitMarker) {
            Add-Finding -Severity 'BLOCK' -Check 'git.global.probe-root' -Message 'Cannot prove context-neutral global Git values because the read-only probe root itself contains .git.' -Value $verifyRootGitMarker
        } else {
            Add-Finding -Severity 'PASS' -Check 'git.global.probe-root' -Message 'Read-only context-neutral Git probe root is not itself a worktree.' -Value $verifyRoot
            $oldCeiling = $env:GIT_CEILING_DIRECTORIES
            try {
                $env:GIT_CEILING_DIRECTORIES = $verifyRoot
                $expectedGlobal = [ordered]@{
                    'gpg.format' = 'ssh'
                    'gpg.ssh.program' = ($sshencPath.Replace([IO.Path]::DirectorySeparatorChar, [char]'/'))
                    'user.signingkey' = ($publicKey.Replace([IO.Path]::DirectorySeparatorChar, [char]'/'))
                    'gpg.ssh.allowedSignersFile' = ($allowedSigners.Replace([IO.Path]::DirectorySeparatorChar, [char]'/'))
                }
                foreach ($key in $expectedGlobal.Keys) {
                    $value = Get-GitOne -Git $git -Arguments @('-C',$verifyRoot,'config','--global','--includes','--get',$key) -Context "Read context-neutral global $key" -AllowAbsent
                    if ($null -eq $value) {
                        Add-Finding -Severity 'BLOCK' -Check "git.global.$key" -Message 'Required context-neutral global Git value is absent.'
                        continue
                    }
                    $matches = if ($key -eq 'gpg.format') {
                        $value -ceq $expectedGlobal[$key]
                    } else {
                        Test-WindowsPathEqual -Left $value -Right $expectedGlobal[$key]
                    }
                    if ($matches) {
                        Add-Finding -Severity 'PASS' -Check "git.global.$key" -Message 'Context-neutral global Git value matches hello-approval.' -Value $value
                    } else {
                        Add-Finding -Severity 'BLOCK' -Check "git.global.$key" -Message 'Context-neutral global Git value is overridden/mismatched.' -Value ([pscustomobject]@{ expected = $expectedGlobal[$key]; actual = $value })
                    }
                }
            } catch {
                Add-Finding -Severity 'BLOCK' -Check 'git.global' -Message 'Could not validate context-neutral global Git state.' -Value $_.Exception.Message
            } finally {
                $env:GIT_CEILING_DIRECTORIES = $oldCeiling
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($Repo)) {
            $targetRepo = [IO.Path]::GetFullPath($Repo)
            Test-RepoEffectiveGit -Git $git -RepoPath $targetRepo -ExpectedSshenc $sshencPath -ExpectedPublicKey $publicKey -ExpectedAllowedSigners $allowedSigners
        } else {
            Add-Finding -Severity 'INFO' -Check 'git.target' -Message 'No -Repo was supplied; repository-local/conditional overrides were not inspected.'
        }
    }

    if (Test-Path -LiteralPath $publicKey -PathType Leaf) {
        $keyLines = @(Get-Content -LiteralPath $publicKey | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($keyLines.Count -eq 1 -and $keyLines[0] -match ('\A' + [regex]::Escape($ExpectedKeyType) + '\s+[A-Za-z0-9+/]+={0,2}(?:\s+.*)?\z')) {
            Add-Finding -Severity 'PASS' -Check 'credential.public-key' -Message 'Canonical public signing key has the expected hardware-backed OpenSSH key type.' -Value $publicKey
        } else {
            Add-Finding -Severity 'BLOCK' -Check 'credential.public-key' -Message 'Canonical public signing key is malformed or has the wrong key type.' -Value $publicKey
        }
    } else {
        Add-Finding -Severity 'BLOCK' -Check 'credential.public-key' -Message 'Canonical public signing key is missing.' -Value $publicKey
    }

    Add-Finding -Severity 'INFO' -Check 'credential.private' -Message 'Doctor intentionally does not enumerate/delete platform private credentials. Credential existence/use is proven by signing acceptance, not by materializing private key state.'
} catch {
    if ($_.Exception.Message -notin @('unsupported-platform','required-environment-missing')) {
        Add-Finding -Severity 'BLOCK' -Check 'doctor.internal' -Message 'Doctor encountered an unexpected internal failure.' -Value $_.Exception.Message
    }
}

$blocked = @($findings | Where-Object { $_.severity -eq 'BLOCK' }).Count -gt 0

if ($Json) {
    [pscustomobject]@{
        schema = 'hello-approval/doctor/v1'
        healthy = -not $blocked
        findings = $findings.ToArray()
    } | ConvertTo-Json -Depth 8
} else {
    foreach ($finding in $findings) {
        $suffix = if ($finding.PSObject.Properties.Name -contains 'value') {
            " | $($finding.value | ConvertTo-Json -Compress -Depth 6)"
        } else {
            ''
        }
        Write-Host ("[{0}] {1}: {2}{3}" -f $finding.severity, $finding.check, $finding.message, $suffix)
    }

    if ($blocked) {
        Write-Host 'Doctor result: BLOCKED' -ForegroundColor Red
    } else {
        Write-Host 'Doctor result: HEALTHY' -ForegroundColor Green
    }
}

if ($blocked) { exit 2 }
exit 0
