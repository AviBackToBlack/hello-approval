#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$findings = New-Object 'System.Collections.Generic.List[object]'

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'INFO', 'WARN', 'BLOCK')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Check,
        [Parameter(Mandatory = $true)][string]$Message,
        [AllowNull()][object]$Value = $null
    )

    $findings.Add([pscustomobject]@{
        severity = $Severity
        check    = $Check
        message  = $Message
        value    = $Value
    }) | Out-Null
}

function Get-EnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('Process', 'User')][string]$Target
    )
    return [Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::$Target)
}

function Get-GitGlobalValue {
    param([Parameter(Mandatory = $true)][string]$Key)

    $value = & git config --global --get $Key 2>$null
    if ($LASTEXITCODE -eq 0) {
        return ($value -join "`n")
    }
    return $null
}

try {
    if ($env:OS -ne 'Windows_NT') {
        Add-Finding -Severity 'BLOCK' -Check 'platform' -Message 'hello-approval v0.1 runtime is Windows-only.' -Value $env:OS
        throw 'Unsupported platform.'
    }

    foreach ($required in @('LOCALAPPDATA', 'APPDATA', 'USERPROFILE')) {
        $value = [Environment]::GetEnvironmentVariable($required, 'Process')
        if ([string]::IsNullOrWhiteSpace($value)) {
            Add-Finding -Severity 'BLOCK' -Check "environment.$required" -Message "Required Windows environment path $required is not available."
        } else {
            Add-Finding -Severity 'PASS' -Check "environment.$required" -Message "$required is available." -Value $value
        }
    }

    if (@($findings | Where-Object { $_.severity -eq 'BLOCK' }).Count -gt 0) {
        throw 'Required platform paths are unavailable.'
    }

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $pinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'
    if (-not (Test-Path -LiteralPath $pinPath -PathType Leaf)) {
        Add-Finding -Severity 'BLOCK' -Check 'pin.present' -Message 'Pinned provenance JSON is missing.' -Value $pinPath
        throw 'Pinned provenance JSON is missing.'
    }

    $pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
    if ($pin.schema -ne 'hello-approval/upstream-pin/v1') {
        Add-Finding -Severity 'BLOCK' -Check 'pin.schema' -Message 'Unexpected provenance pin schema.' -Value $pin.schema
        throw 'Unsupported provenance pin schema.'
    } else {
        Add-Finding -Severity 'PASS' -Check 'pin.schema' -Message 'Provenance pin schema is supported.' -Value $pin.schema
    }

    $releaseTag = [string]$pin.upstream.release_tag
    $runtimeRoot = Join-Path $env:LOCALAPPDATA ("hello-approval\runtime\sshenc\{0}" -f $releaseTag)
    $runtimeBin = Join-Path $runtimeRoot 'bin'
    $expectedPipe = '\\.\pipe\sshenc-github-signing'
    $expectedPipeName = 'sshenc-github-signing'
    $configCandidates = @(
        (Join-Path $env:APPDATA 'sshenc\config.toml'),
        (Join-Path $env:USERPROFILE '.config\sshenc\config.toml')
    ) | Select-Object -Unique
    $configPath = $null
    $sshConfigPath = Join-Path $env:USERPROFILE '.ssh\config'

    Add-Finding -Severity 'INFO' -Check 'runtime.root' -Message 'Expected pinned runtime root.' -Value $runtimeRoot
    Add-Finding -Severity 'INFO' -Check 'agent.pipe' -Message 'Expected dedicated signing pipe.' -Value $expectedPipe

    $requiredFiles = @($pin.installation_policy.installed_files)
    $runtimeVerified = $false
    if (Test-Path -LiteralPath $runtimeBin -PathType Container) {
        $runtimeProblems = 0
        $unexpected = @(
            Get-ChildItem -LiteralPath $runtimeBin -File |
                Where-Object { $requiredFiles -notcontains $_.Name } |
                Select-Object -ExpandProperty Name
        )
        if ($unexpected.Count -gt 0) {
            $runtimeProblems++
            Add-Finding -Severity 'BLOCK' -Check 'runtime.surface' -Message 'Runtime bin directory contains files outside the approved surface.' -Value ($unexpected -join ', ')
        }

        foreach ($name in $requiredFiles) {
            $path = Join-Path $runtimeBin $name
            $filePin = $pin.files | Where-Object { $_.name -eq $name } | Select-Object -First 1
            if ($null -eq $filePin) {
                $runtimeProblems++
                Add-Finding -Severity 'BLOCK' -Check "runtime.$name" -Message 'Required runtime file is missing from provenance pin.'
                continue
            }
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $runtimeProblems++
                Add-Finding -Severity 'BLOCK' -Check "runtime.$name" -Message 'Pinned runtime directory exists but a required file is missing.' -Value $path
                continue
            }
            $item = Get-Item -LiteralPath $path
            $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if (($item.Length -ne [int64]$filePin.size_bytes) -or ($hash -ne ([string]$filePin.sha256).ToLowerInvariant())) {
                $runtimeProblems++
                Add-Finding -Severity 'BLOCK' -Check "runtime.$name" -Message 'Existing runtime file does not match the provenance pin.' -Value $path
            } else {
                Add-Finding -Severity 'PASS' -Check "runtime.$name" -Message 'Existing runtime file matches the provenance pin.' -Value $path
            }
        }
        $runtimeVerified = ($runtimeProblems -eq 0)
    } else {
        Add-Finding -Severity 'INFO' -Check 'runtime.surface' -Message 'Pinned runtime is not installed yet.' -Value $runtimeBin
    }

    if ($runtimeVerified) {
        $sshencPath = Join-Path $runtimeBin 'sshenc.exe'
        try {
            $resolvedConfig = & $sshencPath config path 2>$null
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($resolvedConfig -join ''))) {
                throw 'sshenc config path returned no usable path.'
            }
            $configPath = ($resolvedConfig | Select-Object -First 1).Trim()
            Add-Finding -Severity 'PASS' -Check 'sshenc.config.path' -Message 'Resolved authoritative sshenc config path through the pinned binary.' -Value $configPath
        } catch {
            Add-Finding -Severity 'BLOCK' -Check 'sshenc.config.path' -Message 'Could not resolve config path through the verified pinned sshenc.exe.' -Value $_.Exception.Message
        }
    } else {
        Add-Finding -Severity 'INFO' -Check 'sshenc.config.path' -Message 'Pinned runtime is not yet verified; inspecting common config candidates until sshenc.exe can resolve the authoritative path.' -Value ($configCandidates -join '; ')
    }

    foreach ($target in @('Process', 'User')) {
        $override = Get-EnvironmentValue -Name 'SSHENC_AGENT_SOCKET' -Target $target
        if (-not [string]::IsNullOrWhiteSpace($override)) {
            Add-Finding -Severity 'BLOCK' -Check "environment.$target.SSHENC_AGENT_SOCKET" -Message 'SSHENC_AGENT_SOCKET would override the approved config socket.' -Value $override
        } else {
            Add-Finding -Severity 'PASS' -Check "environment.$target.SSHENC_AGENT_SOCKET" -Message 'No sshenc client socket override is set.'
        }

        foreach ($name in @('SSH_AUTH_SOCK', 'GIT_SSH_COMMAND')) {
            $value = Get-EnvironmentValue -Name $name -Target $target
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                Add-Finding -Severity 'WARN' -Check "environment.$target.$name" -Message "$name is already set and must be preserved, not overwritten." -Value $value
            } else {
                Add-Finding -Severity 'PASS' -Check "environment.$target.$name" -Message "$name is not set at this scope."
            }
        }
    }

    try {
        $pipeNames = @([System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [System.IO.Path]::GetFileName($_) })
        if ($pipeNames -contains $expectedPipeName) {
            Add-Finding -Severity 'BLOCK' -Check 'agent.pipe.collision' -Message 'The dedicated hello-approval pipe name is already in use.' -Value $expectedPipe
        } else {
            Add-Finding -Severity 'PASS' -Check 'agent.pipe.collision' -Message 'The dedicated hello-approval pipe name is currently free.' -Value $expectedPipe
        }
    } catch {
        Add-Finding -Severity 'WARN' -Check 'agent.pipe.collision' -Message 'Could not enumerate Windows named pipes; verify pipe availability before agent installation.' -Value $_.Exception.Message
    }

    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='ssh-agent'" -ErrorAction Stop
        if ($null -eq $svc) {
            Add-Finding -Severity 'INFO' -Check 'stock-ssh-agent' -Message 'Windows OpenSSH Authentication Agent service is not installed.'
        } else {
            Add-Finding -Severity 'INFO' -Check 'stock-ssh-agent' -Message 'Observed stock ssh-agent state; hello-approval will not change it.' -Value ([pscustomobject]@{
                state      = $svc.State
                start_mode = $svc.StartMode
            })
        }
    } catch {
        try {
            $svcFallback = Get-Service -Name 'ssh-agent' -ErrorAction Stop
            Add-Finding -Severity 'INFO' -Check 'stock-ssh-agent' -Message 'Observed stock ssh-agent state through non-CIM fallback; hello-approval will not change it.' -Value ([pscustomobject]@{
                state      = [string]$svcFallback.Status
                start_mode = [string]$svcFallback.StartType
            })
        } catch {
            Add-Finding -Severity 'WARN' -Check 'stock-ssh-agent' -Message 'Could not query stock ssh-agent service state.' -Value $_.Exception.Message
        }
    }

    $pathsToInspect = @($configCandidates)
    if (-not [string]::IsNullOrWhiteSpace($configPath)) {
        $pathsToInspect += $configPath
    }
    $pathsToInspect = @($pathsToInspect | Select-Object -Unique)
    $existingConfigs = @($pathsToInspect | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($existingConfigs.Count -gt 0) {
        Add-Finding -Severity 'WARN' -Check 'sshenc.config.existing' -Message 'Existing sshenc config state was found. It is shared user state and must be reconciled explicitly; do not overwrite it by default.' -Value ($existingConfigs -join '; ')
    } else {
        Add-Finding -Severity 'PASS' -Check 'sshenc.config.existing' -Message 'No sshenc config was found at the authoritative/common candidate paths.' -Value ($pathsToInspect -join '; ')
    }

    if (Test-Path -LiteralPath $sshConfigPath -PathType Leaf) {
        $sshConfig = Get-Content -LiteralPath $sshConfigPath -Raw
        if ($sshConfig -match '(?im)sshenc-managed') {
            Add-Finding -Severity 'BLOCK' -Check 'ssh.config.upstream-managed' -Message 'SSH config contains an upstream sshenc-managed block. Reconcile prior upstream integration before proceeding.' -Value $sshConfigPath
        }
        if ($sshConfig -match '(?im)^\s*IdentityAgent\s+') {
            Add-Finding -Severity 'WARN' -Check 'ssh.config.identity-agent' -Message 'SSH config already contains IdentityAgent configuration. hello-approval must preserve it.' -Value $sshConfigPath
        } else {
            Add-Finding -Severity 'PASS' -Check 'ssh.config.identity-agent' -Message 'No IdentityAgent directive was detected in the user SSH config.' -Value $sshConfigPath
        }
    } else {
        Add-Finding -Severity 'INFO' -Check 'ssh.config' -Message 'User SSH config does not exist.' -Value $sshConfigPath
    }

    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    if ($null -eq $gitCommand) {
        Add-Finding -Severity 'WARN' -Check 'git.present' -Message 'Git was not found in PATH; Git configuration preflight was skipped.'
    } else {
        Add-Finding -Severity 'PASS' -Check 'git.present' -Message 'Git is available.' -Value $gitCommand.Source
        foreach ($key in @(
            'core.sshCommand',
            'gpg.format',
            'gpg.ssh.program',
            'gpg.ssh.allowedSignersFile',
            'user.signingkey',
            'commit.gpgsign',
            'tag.gpgsign',
            'user.name',
            'user.email'
        )) {
            $value = Get-GitGlobalValue -Key $key
            if ($null -ne $value -and $value -ne '') {
                $severity = 'INFO'
                if ($key -eq 'core.sshCommand') {
                    $severity = 'WARN'
                }
                Add-Finding -Severity $severity -Check "git.global.$key" -Message 'Existing global Git setting observed; later slices must not overwrite it implicitly.' -Value $value
            } else {
                Add-Finding -Severity 'PASS' -Check "git.global.$key" -Message 'Global Git setting is absent.'
            }
        }
    }

    $blocked = @($findings | Where-Object { $_.severity -eq 'BLOCK' }).Count -gt 0

    if ($Json) {
        [pscustomobject]@{
            schema   = 'hello-approval/preflight/v1'
            blocked  = $blocked
            findings = $findings.ToArray()
        } | ConvertTo-Json -Depth 8
    } else {
        $findings | Format-Table -AutoSize severity, check, message, value
        if ($blocked) {
            Write-Host 'Preflight result: BLOCKED' -ForegroundColor Red
        } else {
            Write-Host 'Preflight result: no blocking findings' -ForegroundColor Green
        }
    }

    if ($blocked) { exit 2 }
    exit 0
} catch {
    if ($findings.Count -eq 0) {
        Write-Error $_
        exit 1
    }

    $blocked = @($findings | Where-Object { $_.severity -eq 'BLOCK' }).Count -gt 0
    if ($Json) {
        [pscustomobject]@{
            schema   = 'hello-approval/preflight/v1'
            blocked  = $blocked
            error    = $_.Exception.Message
            findings = $findings.ToArray()
        } | ConvertTo-Json -Depth 8
    } else {
        $findings | Format-Table -AutoSize severity, check, message, value
        Write-Error $_.Exception.Message
    }

    if ($blocked) { exit 2 }
    exit 1
}
