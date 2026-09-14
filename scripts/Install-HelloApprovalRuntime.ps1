#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ArchivePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-StreamSha256 {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash($Stream)
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}


function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        return Get-StreamSha256 -Stream $stream
    } finally {
        $stream.Dispose()
    }
}

function Assert-ExistingRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][object]$Pin
    )

    $required = @($Pin.installation_policy.installed_files)
    if (-not (Test-Path -LiteralPath $RuntimeRoot -PathType Container)) {
        throw "Runtime root is not a directory: $RuntimeRoot"
    }

    $rootItems = @(Get-ChildItem -LiteralPath $RuntimeRoot -Force)
    if ($rootItems.Count -ne 1 -or $rootItems[0].Name -ne 'bin' -or -not $rootItems[0].PSIsContainer) {
        throw "Existing runtime root surface differs from the approved layout (exactly one bin directory required): $RuntimeRoot"
    }

    $binPath = Join-Path $RuntimeRoot 'bin'
    $actualItems = @(Get-ChildItem -LiteralPath $binPath -Force)
    $actualNames = @($actualItems | ForEach-Object { $_.Name })
    $nameDiff = @(Compare-Object -ReferenceObject ($required | Sort-Object) -DifferenceObject ($actualNames | Sort-Object))
    $nonFiles = @($actualItems | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
    if ($nameDiff.Count -ne 0 -or $nonFiles.Count -ne 0) {
        throw "Existing runtime bin surface differs from the approved installed_files set: $binPath"
    }

    foreach ($name in $required) {
        $filePin = $Pin.files | Where-Object { $_.name -eq $name } | Select-Object -First 1
        if ($null -eq $filePin) {
            throw "Required file '$name' is not present in the provenance pin."
        }
        $path = Join-Path $binPath $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required runtime path is not a regular file: $path"
        }
        $item = Get-Item -LiteralPath $path -Force
        $hash = Get-FileSha256 -Path $path
        if ($item.Length -ne [int64]$filePin.size_bytes -or $hash -ne ([string]$filePin.sha256).ToLowerInvariant()) {
            throw "Existing runtime file does not match pin: $path"
        }
    }
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Install-HelloApprovalRuntime.ps1 supports Windows only.'
}
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is not available.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$pinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'
if (-not (Test-Path -LiteralPath $pinPath -PathType Leaf)) {
    throw "Pinned provenance JSON is missing: $pinPath"
}
$pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
if ($pin.schema -ne 'hello-approval/upstream-pin/v1') {
    throw "Unsupported provenance pin schema: $($pin.schema)"
}
if ($pin.installation_policy.target_architecture -ne 'x86_64-pc-windows-msvc') {
    throw "This installer slice only supports x86_64-pc-windows-msvc; pin says $($pin.installation_policy.target_architecture)."
}
if ($pin.installation_policy.allowed_distribution -ne 'zip-manual-placement') {
    throw "This installer slice only supports zip-manual-placement; pin says $($pin.installation_policy.allowed_distribution)."
}
$validDispositions = @('required', 'unused', 'excluded')
$invalidDispositions = @($pin.files | Where-Object { $validDispositions -notcontains $_.policy.disposition } | ForEach-Object { $_.name })
if ($invalidDispositions.Count -gt 0) {
    throw "Unsupported file policy disposition(s) in pin: $($invalidDispositions -join ', ')"
}
$requiredByPolicy = @($pin.files | Where-Object { $_.policy.disposition -eq 'required' } | ForEach-Object { $_.name } | Sort-Object)
$installedByPolicy = @($pin.installation_policy.installed_files | Sort-Object)
if (@(Compare-Object -ReferenceObject $requiredByPolicy -DifferenceObject $installedByPolicy).Count -gt 0) {
    throw 'Pin inconsistency: installed_files must exactly match files with policy.disposition=required.'
}

if (-not [System.IO.File]::Exists($ArchivePath)) {
    throw "Archive does not exist: $ArchivePath"
}
$resolvedArchive = [System.IO.Path]::GetFullPath($ArchivePath)
$archiveItem = New-Object System.IO.FileInfo($resolvedArchive)
if ($archiveItem.Name -ne $pin.selected_asset.name) {
    throw "Archive filename mismatch. Expected '$($pin.selected_asset.name)', got '$($archiveItem.Name)'."
}
if ($archiveItem.Length -ne [int64]$pin.selected_asset.size_bytes) {
    throw "Archive size mismatch for '$resolvedArchive'."
}
$archiveHash = Get-FileSha256 -Path $resolvedArchive
if ($archiveHash -ne ([string]$pin.selected_asset.sha256).ToLowerInvariant()) {
    throw "Archive SHA-256 mismatch for '$resolvedArchive'."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($resolvedArchive)
try {
    $entries = @($zip.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) })
    $pinNames = @($pin.files | ForEach-Object { [string]$_.name })
    $archiveNames = @($entries | ForEach-Object { [string]$_.FullName })

    foreach ($entry in $entries) {
        if ($entry.FullName -ne $entry.Name) {
            throw "Unexpected nested/path entry in pinned archive: $($entry.FullName)"
        }
    }

    $entryDiff = @(Compare-Object -ReferenceObject ($pinNames | Sort-Object) -DifferenceObject ($archiveNames | Sort-Object))
    if ($entryDiff.Count -ne 0) {
        throw 'Archive entry set does not match the provenance pin.'
    }

    foreach ($entry in $entries) {
        $filePin = $pin.files | Where-Object { $_.name -eq $entry.Name } | Select-Object -First 1
        if ($null -eq $filePin) {
            throw "Archive entry '$($entry.Name)' has no provenance record."
        }
        if ($entry.Length -ne [int64]$filePin.size_bytes) {
            throw "Archive entry size mismatch: $($entry.Name)"
        }
        $stream = $entry.Open()
        try {
            $hash = Get-StreamSha256 -Stream $stream
        } finally {
            $stream.Dispose()
        }
        if ($hash -ne ([string]$filePin.sha256).ToLowerInvariant()) {
            throw "Archive entry SHA-256 mismatch: $($entry.Name)"
        }
    }

    $releaseTag = [string]$pin.upstream.release_tag
    $runtimeRoot = Join-Path $env:LOCALAPPDATA ("hello-approval\runtime\sshenc\{0}" -f $releaseTag)
    $binPath = Join-Path $runtimeRoot 'bin'

    if (Test-Path -LiteralPath $runtimeRoot) {
        Assert-ExistingRuntime -RuntimeRoot $runtimeRoot -Pin $pin
        Write-Host "Pinned runtime is already installed and matches the provenance pin: $runtimeRoot"
        return
    }

    if (-not $PSCmdlet.ShouldProcess($runtimeRoot, "Install verified hello-approval sshenc runtime $releaseTag")) {
        Write-Host "Verified archive and all entries; WhatIf prevented runtime installation."
        return
    }

    $runtimeParent = Split-Path -Parent $runtimeRoot
    if (-not (Test-Path -LiteralPath $runtimeParent -PathType Container)) {
        New-Item -ItemType Directory -Path $runtimeParent -Force | Out-Null
    }

    $leaf = Split-Path -Leaf $runtimeRoot
    $stagingRoot = Join-Path $runtimeParent ('.{0}.staging.{1}' -f $leaf, [Guid]::NewGuid().ToString('N'))
    $stagingBin = Join-Path $stagingRoot 'bin'

    try {
        New-Item -ItemType Directory -Path $stagingBin -Force | Out-Null

        foreach ($name in @($pin.installation_policy.installed_files)) {
            $entry = $zip.Entries | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            if ($null -eq $entry) {
                throw "Required archive entry disappeared during staging: $name"
            }
            $destination = Join-Path $stagingBin $name
            $input = $entry.Open()
            $output = [System.IO.File]::Open($destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            try {
                $input.CopyTo($output)
            } finally {
                $output.Dispose()
                $input.Dispose()
            }
        }

        Assert-ExistingRuntime -RuntimeRoot $stagingRoot -Pin $pin

        [System.IO.Directory]::Move($stagingRoot, $runtimeRoot)
        Write-Host "Installed verified runtime: $runtimeRoot"
    } catch {
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    }
} finally {
    $zip.Dispose()
}
