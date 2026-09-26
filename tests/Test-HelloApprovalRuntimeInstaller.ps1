#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalRuntimeInstaller.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceInstaller = Join-Path $repoRoot 'scripts\Install-HelloApprovalRuntime.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

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

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
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

    Copy-Item -LiteralPath $sourceInstaller -Destination (Join-Path $scripts 'Install-HelloApprovalRuntime.ps1') -Force
    if (Test-Path -LiteralPath $sourceModule -PathType Leaf) {
        Copy-Item -LiteralPath $sourceModule -Destination (Join-Path $lib 'HelloApproval.Validation.psm1') -Force
    }

    $archive = Join-Path $Root 'synthetic.zip'
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $payloads = [ordered]@{
        'alpha.exe' = [byte[]](1,2,3,4,5)
        'beta.exe' = [byte[]](9,8,7,6)
        'unused.exe' = [byte[]](4,4,4)
    }

    $zip = [IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $payloads.Keys) {
            $entry = $zip.CreateEntry($name,[IO.Compression.CompressionLevel]::NoCompression)
            $stream = $entry.Open()
            try {
                $stream.Write($payloads[$name],0,$payloads[$name].Length)
            } finally {
                $stream.Dispose()
            }
        }
    } finally {
        $zip.Dispose()
    }

    $files = New-Object System.Collections.Generic.List[object]
    foreach ($name in $payloads.Keys) {
        $disposition = if ($name -ceq 'unused.exe') { 'unused' } else { 'required' }
        [void]$files.Add([ordered]@{
            name = $name
            size_bytes = [int64]$payloads[$name].Length
            sha256 = Get-BytesSha256 -Bytes $payloads[$name]
            policy = [ordered]@{ disposition = $disposition }
        })
    }

    $archiveBytes = [IO.File]::ReadAllBytes($archive)
    $pin = [ordered]@{
        schema = 'hello-approval/upstream-pin/v1'
        upstream = [ordered]@{ release_tag = 'v-test' }
        selected_asset = [ordered]@{
            name = [IO.Path]::GetFileName($archive)
            size_bytes = [int64]$archiveBytes.Length
            sha256 = Get-BytesSha256 -Bytes $archiveBytes
        }
        files = @($files.ToArray())
        installation_policy = [ordered]@{
            target_architecture = 'x86_64-pc-windows-msvc'
            allowed_distribution = 'zip-manual-placement'
            installed_files = @('alpha.exe','beta.exe')
        }
    }

    $pinJson = $pin | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText((Join-Path $provenance 'sshenc-v0.6.101.json'),$pinJson,[Text.UTF8Encoding]::new($false))

    return [pscustomobject]@{
        Repo = $mini
        Installer = Join-Path $scripts 'Install-HelloApprovalRuntime.ps1'
        Archive = $archive
    }
}

function Invoke-Installer {
    param(
        [string]$Installer,
        [string]$Archive,
        [string]$LocalAppData,
        [switch]$WhatIf
    )

    [void][IO.Directory]::CreateDirectory($LocalAppData)
    $oldLocal = $env:LOCALAPPDATA
    try {
        $env:LOCALAPPDATA = $LocalAppData
        $args = @(
            '-NoProfile',
            '-ExecutionPolicy','Bypass',
            '-File',$Installer,
            '-ArchivePath',$Archive
        )
        if ($WhatIf) { $args += '-WhatIf' }

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $ps51 @args 2>&1 | ForEach-Object { [string]$_ })
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

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-runtime-installer-{0}' -f [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

try {
    $fixture = New-SyntheticRepo -Root $root

    $localExact = Join-Path $root 'local-exact'
    $first = Invoke-Installer -Installer $fixture.Installer -Archive $fixture.Archive -LocalAppData $localExact
    $second = Invoke-Installer -Installer $fixture.Installer -Archive $fixture.Archive -LocalAppData $localExact
    $runtimeExact = Join-Path $localExact 'hello-approval\runtime\sshenc\v-test'
    if ($first.ExitCode -eq 0 -and $second.ExitCode -eq 0 -and (Test-Path -LiteralPath $runtimeExact -PathType Container)) {
        Pass 'exact install and idempotent rerun'
    } else {
        Fail 'exact install and idempotent rerun' ("first={0} second={1} output={2}" -f $first.ExitCode,$second.ExitCode,($second.Output -join ' | '))
    }

    $localWhatIf = Join-Path $root 'local-whatif'
    $whatIf = Invoke-Installer -Installer $fixture.Installer -Archive $fixture.Archive -LocalAppData $localWhatIf -WhatIf
    $runtimeWhatIf = Join-Path $localWhatIf 'hello-approval\runtime\sshenc\v-test'
    if ($whatIf.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $runtimeWhatIf)) {
        Pass 'WhatIf verifies without installing runtime'
    } else {
        Fail 'WhatIf verifies without installing runtime' ("rc={0} runtimeExists={1}" -f $whatIf.ExitCode,(Test-Path -LiteralPath $runtimeWhatIf))
    }

    # Approved delta: Phase 1 accepted case-only surface drift; hardened migration must reject it.
    $bin = Join-Path $runtimeExact 'bin'
    Rename-Item -LiteralPath $bin -NewName 'bin.tmp'
    Rename-Item -LiteralPath (Join-Path $runtimeExact 'bin.tmp') -NewName 'Bin'
    $bin = Join-Path $runtimeExact 'Bin'
    $alpha = Join-Path $bin 'alpha.exe'
    Rename-Item -LiteralPath $alpha -NewName 'alpha.tmp'
    Rename-Item -LiteralPath (Join-Path $bin 'alpha.tmp') -NewName 'ALPHA.EXE'

    $caseResult = Invoke-Installer -Installer $fixture.Installer -Archive $fixture.Archive -LocalAppData $localExact
    if ($ExpectedPhase1) {
        if ($caseResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts case-only runtime surface drift'
        } else {
            Fail 'Phase1 baseline accepts case-only runtime surface drift' ($caseResult.Output -join ' | ')
        }
    } else {
        if ($caseResult.ExitCode -ne 0) {
            Pass 'hardened installer rejects case-only runtime surface drift'
        } else {
            Fail 'hardened installer rejects case-only runtime surface drift' 'installer unexpectedly returned success'
        }
    }

    # Approved delta: Phase 1 can create runtime through an intermediate junction below LOCALAPPDATA.
    $localJunction = Join-Path $root 'local-junction'
    [void][IO.Directory]::CreateDirectory($localJunction)
    $redirect = Join-Path $root 'redirect-target'
    [void][IO.Directory]::CreateDirectory($redirect)
    $link = Join-Path $localJunction 'hello-approval'

    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $junctionOutput = @(& cmd.exe /d /c mklink /J "$link" "$redirect" 2>&1 | ForEach-Object { [string]$_ })
        $junctionRc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($junctionRc -ne 0) {
        throw "Could not create junction fixture: $($junctionOutput -join ' | ')"
    }

    $junctionResult = Invoke-Installer -Installer $fixture.Installer -Archive $fixture.Archive -LocalAppData $localJunction
    $outsideRuntime = Join-Path $redirect 'runtime\sshenc\v-test'

    if ($ExpectedPhase1) {
        if ($junctionResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $outsideRuntime -PathType Container)) {
            Pass 'Phase1 baseline permits intermediate-junction install redirect'
        } else {
            Fail 'Phase1 baseline permits intermediate-junction install redirect' ("rc={0} outside={1} output={2}" -f $junctionResult.ExitCode,(Test-Path -LiteralPath $outsideRuntime),($junctionResult.Output -join ' | '))
        }
    } else {
        if ($junctionResult.ExitCode -ne 0 -and -not (Test-Path -LiteralPath $outsideRuntime)) {
            Pass 'hardened installer rejects intermediate junction before out-of-base mutation'
        } else {
            Fail 'hardened installer rejects intermediate junction before out-of-base mutation' ("rc={0} outside={1} output={2}" -f $junctionResult.ExitCode,(Test-Path -LiteralPath $outsideRuntime),($junctionResult.Output -join ' | '))
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if ($script:Failed -ne 0) { exit 1 }
    exit 0
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
