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


if ($env:OS -ne 'Windows_NT') {
    throw 'Install-HelloApprovalRuntime.ps1 supports Windows only.'
}
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is not available.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$validationModulePath = Join-Path (Join-Path $repoRoot 'lib') 'HelloApproval.Validation.psm1'
if (-not (Test-Path -LiteralPath $validationModulePath -PathType Leaf)) {
    throw "Shared validation module is missing: $validationModulePath"
}
Import-Module $validationModulePath -Force -ErrorAction Stop

$pinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'
if (-not (Test-Path -LiteralPath $pinPath -PathType Leaf)) {
    throw "Pinned provenance JSON is missing: $pinPath"
}
$pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json
[void](Assert-HelloApprovalPinPolicy -Pin $pin)

if ($pin.installation_policy.target_architecture -ne 'x86_64-pc-windows-msvc') {
    throw "This installer slice only supports x86_64-pc-windows-msvc; pin says $($pin.installation_policy.target_architecture)."
}
if ($pin.installation_policy.allowed_distribution -ne 'zip-manual-placement') {
    throw "This installer slice only supports zip-manual-placement; pin says $($pin.installation_policy.allowed_distribution)."
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
    $runtimeBase = Join-Path (Join-Path (Join-Path $env:LOCALAPPDATA 'hello-approval') 'runtime') 'sshenc'
    $runtimeRoot = Join-Path $runtimeBase $releaseTag

    [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $runtimeRoot -ExpectedType Directory -AllowMissing)

    if (Test-Path -LiteralPath $runtimeRoot) {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $runtimeRoot -Pin $pin -TrustedBase $env:LOCALAPPDATA)
        Write-Host "Pinned runtime is already installed and matches the provenance pin: $runtimeRoot"
        return
    }

    if (-not $PSCmdlet.ShouldProcess($runtimeRoot, "Install verified hello-approval sshenc runtime $releaseTag")) {
        Write-Host "Verified archive and all entries; WhatIf prevented runtime installation."
        return
    }

    $runtimeParent = Split-Path -Parent $runtimeRoot
    [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $runtimeParent -ExpectedType Directory -AllowMissing)
    if (-not (Test-Path -LiteralPath $runtimeParent -PathType Container)) {
        New-Item -ItemType Directory -Path $runtimeParent -Force | Out-Null
    }
    [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $runtimeParent -ExpectedType Directory)

    $leaf = Split-Path -Leaf $runtimeRoot
    $stagingRoot = Join-Path $runtimeParent ('.{0}.staging.{1}' -f $leaf, [Guid]::NewGuid().ToString('N'))
    $stagingBin = Join-Path $stagingRoot 'bin'

    try {
        New-Item -ItemType Directory -Path $stagingBin -Force | Out-Null
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $stagingBin -ExpectedType Directory)

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

        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $stagingRoot -Pin $pin -TrustedBase $env:LOCALAPPDATA)
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $env:LOCALAPPDATA -Path $runtimeRoot -ExpectedType Directory -AllowMissing)

        [System.IO.Directory]::Move($stagingRoot, $runtimeRoot)
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $runtimeRoot -Pin $pin -TrustedBase $env:LOCALAPPDATA)
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
