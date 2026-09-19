#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HelloApprovalRepo,
    [Parameter(Mandatory = $true)][string]$TargetRepo,
    [switch]$DevelopmentSkipProductionProbe
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ExpectedHead = '1f9176df646ca56ce38d501d395d8d55d8aea03a'
$ReviewedInputs = @(
    'scripts/Test-HelloApprovalDoctor.ps1',
    'scripts/Uninstall-HelloApproval.ps1'
)

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$AllowExitTwo
    )

    $saved = $ErrorActionPreference
    $stderrPath = [IO.Path]::GetTempFileName()
    $output = @()
    $stderr = @()
    $rc = $null
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Exe @Arguments 2> $stderrPath | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
        if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            $stderr = @([IO.File]::ReadAllLines($stderrPath) | ForEach-Object { [string]$_ })
        }
    } finally {
        $ErrorActionPreference = $saved
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }

    if ($rc -eq 0 -or ($AllowExitTwo -and $rc -eq 2)) {
        return [pscustomobject]@{ ExitCode = $rc; Output = $output; Stderr = $stderr }
    }

    $detail = @($stderr) + @($output)
    throw "$Context failed with exit $rc.$(if ($detail.Count) { ' ' + ($detail -join ' | ') })"
}

function Get-One {
    param([string]$Exe, [string[]]$Arguments, [string]$Context)
    $r = Invoke-Native -Exe $Exe -Arguments $Arguments -Context $Context
    if ($r.Output.Count -ne 1) { throw "$Context returned $($r.Output.Count) lines; expected one." }
    return [string]$r.Output[0]
}

function Get-FileState {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ path = $Path; exists = $false; sha256 = $null; length = $null }
    }

    $item = Get-Item -LiteralPath $Path -Force
    return [pscustomobject]@{
        path = [IO.Path]::GetFullPath($Path)
        exists = $true
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        length = [int64]$item.Length
    }
}

function Get-RelevantTaskState {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -match '(?i)sshenc|hello-approval'
    })) {
        try {
            $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
            $bytes = [Text.Encoding]::UTF8.GetBytes([string]$xml)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $xmlHash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
            } finally {
                $sha.Dispose()
            }
            [void]$rows.Add([pscustomobject]@{
                taskPath = $task.TaskPath
                taskName = $task.TaskName
                state = [string]$task.State
                xmlSha256 = $xmlHash
            })
        } catch {
            [void]$rows.Add([pscustomobject]@{
                taskPath = $task.TaskPath
                taskName = $task.TaskName
                state = [string]$task.State
                xmlSha256 = '<unavailable>'
            })
        }
    }
    return @($rows.ToArray() | Sort-Object taskPath,taskName)
}

function Get-StableState {
    param([Parameter(Mandatory = $true)][string]$Git, [Parameter(Mandatory = $true)][string]$Target)

    $files = New-Object System.Collections.Generic.List[object]
    $globalCandidates = @(Invoke-Native -Exe $Git -Arguments @('var','GIT_CONFIG_GLOBAL') -Context 'Read Git global candidates').Output
    foreach ($candidate in $globalCandidates) {
        if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
            $nativeCandidate = ([string]$candidate).Replace('/', [IO.Path]::DirectorySeparatorChar)
            [void]$files.Add((Get-FileState -Path ([IO.Path]::GetFullPath($nativeCandidate))))
        }
    }

    $projectRoot = Join-Path $env:LOCALAPPDATA 'hello-approval'
    $projectGitRoot = Join-Path $projectRoot 'git'
    $runtimeRoot = Join-Path (Join-Path (Join-Path $projectRoot 'runtime') 'sshenc') 'v0.6.101'
    $runtimeBin = Join-Path $runtimeRoot 'bin'
    $userSshRoot = Join-Path $env:USERPROFILE '.ssh'

    foreach ($path in @(
        (Join-Path $projectGitRoot 'signing.gitconfig'),
        (Join-Path $projectGitRoot 'verification.gitconfig'),
        (Join-Path $projectGitRoot 'allowed_signers'),
        (Join-Path $runtimeBin 'sshenc.exe'),
        (Join-Path $runtimeBin 'sshenc-agent.exe'),
        (Join-Path $userSshRoot 'github-signing.pub'),
        (Join-Path $userSshRoot 'github-signing-z.pub'),
        (Join-Path $userSshRoot 'allowed_signers')
    )) {
        [void]$files.Add((Get-FileState -Path $path))
    }

    $canonicalSshenc = Join-Path $runtimeBin 'sshenc.exe'
    if (Test-Path -LiteralPath $canonicalSshenc -PathType Leaf) {
        try {
            $configPath = Get-One -Exe $canonicalSshenc -Arguments @('config','path') -Context 'Resolve sshenc config path'
            [void]$files.Add((Get-FileState -Path $configPath.Trim()))
        } catch {}
    }

    $environment = New-Object System.Collections.Generic.List[object]
    foreach ($scope in @('Process','User','Machine')) {
        foreach ($name in @('SSHENC_AGENT_SOCKET','SSH_AUTH_SOCK','GIT_SSH','GIT_SSH_COMMAND')) {
            [void]$environment.Add([pscustomobject]@{
                scope = $scope
                name = $name
                value = [Environment]::GetEnvironmentVariable($name, $scope)
            })
        }
    }

    $gitValues = New-Object System.Collections.Generic.List[object]
    foreach ($key in @('gpg.format','gpg.ssh.program','user.signingkey','gpg.ssh.allowedSignersFile','commit.gpgsign','tag.gpgsign','core.sshCommand','core.sshVariant')) {
        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $value = @(& $Git -C $Target config --includes --get-all $key 2>$null | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }
        [void]$gitValues.Add([pscustomobject]@{
            key = $key
            exitCode = $rc
            values = @($value)
        })
    }

    $scopedTransport = New-Object System.Collections.Generic.List[object]
    foreach ($scope in @('system','global')) {
        foreach ($key in @('core.sshCommand','core.sshVariant')) {
            $saved = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $value = @(& $Git config ("--{0}" -f $scope) --includes --get-all $key 2>$null | ForEach-Object { [string]$_ })
                $rc = $LASTEXITCODE
            } finally {
                $ErrorActionPreference = $saved
            }
            [void]$scopedTransport.Add([pscustomobject]@{
                scope = $scope
                key = $key
                exitCode = $rc
                values = @($value)
            })
        }
    }

    $pipePresent = $false
    try {
        $pipeRoot = [string]::Concat([IO.Path]::DirectorySeparatorChar, [IO.Path]::DirectorySeparatorChar, '.', [IO.Path]::DirectorySeparatorChar, 'pipe', [IO.Path]::DirectorySeparatorChar)
        $pipePresent = @([IO.Directory]::GetFiles($pipeRoot) | ForEach-Object { [IO.Path]::GetFileName($_) } | Where-Object {
            $_ -ieq 'sshenc-github-signing'
        }).Count -gt 0
    } catch {}

    return [pscustomobject]@{
        files = @($files.ToArray() | Sort-Object path)
        tasks = @(Get-RelevantTaskState)
        environment = @($environment.ToArray() | Sort-Object scope,name)
        targetGit = @($gitValues.ToArray() | Sort-Object key)
        scopedGitTransport = @($scopedTransport.ToArray() | Sort-Object scope,key)
        dedicatedPipePresent = $pipePresent
    }
}

function Get-StateJson {
    param([Parameter(Mandatory = $true)]$State)
    return ($State | ConvertTo-Json -Depth 8 -Compress)
}

if ($env:OS -ne 'Windows_NT') { throw 'HA-1.7 production acceptance supports Windows only.' }
if (-not [Environment]::Is64BitProcess) { throw 'Run HA-1.7 production acceptance in 64-bit Windows PowerShell.' }

$gitCommand = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $gitCommand) { $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue }
if ($null -eq $gitCommand) { throw 'Git was not found.' }
$git = $gitCommand.Source

$helloRepo = [IO.Path]::GetFullPath($HelloApprovalRepo)
$target = [IO.Path]::GetFullPath($TargetRepo)
if (-not (Test-Path -LiteralPath $helloRepo -PathType Container)) { throw "HelloApprovalRepo is missing: $helloRepo" }
if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw "TargetRepo is missing: $target" }

$actualHead = Get-One -Exe $git -Arguments @('-C',$helloRepo,'rev-parse','HEAD') -Context 'Read hello-approval checkout HEAD'
$ancestor = Invoke-Native -Exe $git -Arguments @('-C',$helloRepo,'merge-base','--is-ancestor',$ExpectedHead,'HEAD') -Context 'Verify reviewed HA-1.7 ancestry' -AllowExitTwo
if ($ancestor.ExitCode -ne 0) { throw "Reviewed HA-1.7 commit $ExpectedHead is not an ancestor of checkout HEAD $actualHead." }
foreach ($input in $ReviewedInputs) {
    $diff = Invoke-Native -Exe $git -Arguments @('-C',$helloRepo,'diff','--quiet',$ExpectedHead,'--',$input) -Context "Compare reviewed HA-1.7 input $input" -AllowExitTwo
    if ($diff.ExitCode -ne 0) { throw "Refusing production acceptance: $input differs from reviewed product HEAD $ExpectedHead." }
}

$scriptsRoot = Join-Path $helloRepo 'scripts'
$doctor = Join-Path $scriptsRoot 'Test-HelloApprovalDoctor.ps1'
$cleanup = Join-Path $scriptsRoot 'Uninstall-HelloApproval.ps1'
if (-not (Test-Path -LiteralPath $doctor -PathType Leaf)) { throw "Doctor missing: $doctor" }
if (-not (Test-Path -LiteralPath $cleanup -PathType Leaf)) { throw "Cleanup script missing: $cleanup" }

Write-Host '=== HA-1.7 production acceptance baseline ==='
Write-Host "checkout HEAD:   $actualHead"
Write-Host "reviewed HA-1.7: $ExpectedHead"
Write-Host "target repo:     $target"

$before = Get-StableState -Git $git -Target $target
$beforeJson = Get-StateJson -State $before

if ($DevelopmentSkipProductionProbe) {
    Write-Host ("Development baseline snapshot: files={0}, tasks={1}, env={2}, git={3}, scopedTransport={4}, pipe={5}" -f $before.files.Count, $before.tasks.Count, $before.environment.Count, $before.targetGit.Count, $before.scopedGitTransport.Count, $before.dedicatedPipePresent)
    Write-Warning 'DEVELOPMENT ONLY: Z Doctor/WhatIf probe skipped. Production acceptance is INCOMPLETE.'
    exit 3
}

Write-Host '=== Read-only Doctor ==='
$windowsPowerShell = Join-Path (Join-Path (Join-Path (Join-Path $env:SystemRoot 'System32') 'WindowsPowerShell') 'v1.0') 'powershell.exe'
$doctorResult = Invoke-Native -Exe $windowsPowerShell -Arguments @(
    '-NoProfile','-ExecutionPolicy','Bypass','-File',$doctor,'-Repo',$target,'-Json'
) -Context 'Run HA-1.7 Doctor' -AllowExitTwo
if ($doctorResult.ExitCode -ne 2) {
    throw "Expected current mixed legacy/canonical production state to be BLOCKED by Doctor (exit 2), got $($doctorResult.ExitCode)."
}

$doctorText = $doctorResult.Output -join "`n"
$doctorJson = $doctorText | ConvertFrom-Json -ErrorAction Stop
if ($doctorJson.schema -cne 'hello-approval/doctor/v1' -or $doctorJson.healthy -ne $false) {
    throw 'Doctor JSON contract/health value did not match expected current production drift state.'
}
if (@($doctorJson.findings | Where-Object { $_.check -eq 'doctor.internal' }).Count -ne 0) {
    throw 'Doctor reported an internal failure instead of diagnostics.'
}

$expectedBlocks = @(
    'trust.present',
    'task.present',
    'git.signing-fragment',
    'git.verification-fragment',
    'git.include.signing',
    'git.include.verification',
    'git.global.gpg.ssh.program',
    'git.global.user.signingkey',
    'git.global.gpg.ssh.allowedSignersFile',
    'git.target.gpg.ssh.program',
    'git.target.user.signingkey',
    'git.target.gpg.ssh.allowedSignersFile'
)
foreach ($check in $expectedBlocks) {
    $matches = @($doctorJson.findings | Where-Object { $_.check -eq $check -and $_.severity -eq 'BLOCK' })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one BLOCK finding for known legacy/canonical drift '$check', got $($matches.Count)."
    }
}
$formatPass = @($doctorJson.findings | Where-Object { $_.check -eq 'git.target.gpg.format' -and $_.severity -eq 'PASS' })
if ($formatPass.Count -ne 1) {
    throw 'Expected target gpg.format=ssh to remain a PASS while legacy paths are diagnosed.'
}
Write-Host 'Doctor diagnosed known production drift without internal failure: PASS'

$afterDoctor = Get-StableState -Git $git -Target $target
if ((Get-StateJson -State $afterDoctor) -cne $beforeJson) {
    throw 'Doctor changed one or more stable production surfaces.'
}
Write-Host 'Doctor stable-state byte/config/task/env/pipe snapshot unchanged: PASS'

Write-Host '=== Conservative cleanup WhatIf ==='
[void](Invoke-Native -Exe $windowsPowerShell -Arguments @(
    '-NoProfile','-ExecutionPolicy','Bypass','-File',$cleanup,'-WhatIf'
) -Context 'Run HA-1.7 cleanup WhatIf')
$afterWhatIf = Get-StableState -Git $git -Target $target
if ((Get-StateJson -State $afterWhatIf) -cne $beforeJson) {
    throw 'Cleanup -WhatIf changed one or more stable production surfaces.'
}
Write-Host 'Cleanup -WhatIf stable-state byte/config/task/env/pipe snapshot unchanged: PASS'

Write-Host 'HA-1.7 PRODUCTION READ-ONLY ACCEPTANCE: PASS' -ForegroundColor Green
exit 0
