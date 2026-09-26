#requires -Version 5.1

Set-StrictMode -Version 2.0

function Get-HelloApprovalFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "Hash target path must be absolute: $Path"
    }

    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) {
        throw "Hash target does not exist as a file: $full"
    }

    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Hash target must be a regular non-reparse file: $full"
    }

    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Test-HelloApprovalLeafName {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -ceq '.' -or $Name -ceq '..') { return $false }
    if ($Name.IndexOf([IO.Path]::DirectorySeparatorChar) -ge 0) { return $false }
    if ($Name.IndexOf([IO.Path]::AltDirectorySeparatorChar) -ge 0) { return $false }
    return $true
}

function Test-HelloApprovalNonNegativeInteger {
    param($Value)

    if ($null -eq $Value) { return $false }

    $validTypes = @(
        [byte], [sbyte],
        [int16], [uint16],
        [int32], [uint32],
        [int64], [uint64]
    )

    foreach ($type in $validTypes) {
        if ($Value -is $type) {
            try { return ([decimal]$Value -ge 0) } catch { return $false }
        }
    }
    return $false
}

function Assert-HelloApprovalUniqueWindowsNames {
    param(
        [Parameter(Mandatory = $true)][object[]]$Names,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in $Names) {
        if ($null -eq $raw) {
            throw "$Purpose contains a null name."
        }
        $name = [string]$raw
        if (-not (Test-HelloApprovalLeafName -Name $name)) {
            throw "$Purpose contains an invalid non-leaf name: '$name'"
        }
        if (-not $seen.Add($name)) {
            throw "$Purpose contains duplicate/case-colliding Windows name: '$name'"
        }
    }
}

function Assert-HelloApprovalPinPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Pin
    )

    $schemaProperty = $Pin.PSObject.Properties['schema']
    $schema = if ($null -eq $schemaProperty) { $null } else { [string]$schemaProperty.Value }
    if ($schema -cne 'hello-approval/upstream-pin/v1') {
        throw "Unsupported or missing provenance pin schema: '$schema'"
    }

    $filesProperty = $Pin.PSObject.Properties['files']
    if ($null -eq $filesProperty -or $null -eq $filesProperty.Value) {
        throw 'Provenance pin files collection is missing.'
    }

    $installationPolicyProperty = $Pin.PSObject.Properties['installation_policy']
    if ($null -eq $installationPolicyProperty -or $null -eq $installationPolicyProperty.Value) {
        throw 'Provenance pin installation_policy.installed_files is missing.'
    }
    $installedFilesProperty = $installationPolicyProperty.Value.PSObject.Properties['installed_files']
    if ($null -eq $installedFilesProperty -or $null -eq $installedFilesProperty.Value) {
        throw 'Provenance pin installation_policy.installed_files is missing.'
    }

    $files = @($filesProperty.Value)
    $installed = @($installedFilesProperty.Value)

    $validatedRecords = New-Object System.Collections.Generic.List[object]
    foreach ($file in $files) {
        if ($null -eq $file) {
            throw 'Provenance pin contains a null file record.'
        }

        $nameProperty = $file.PSObject.Properties['name']
        if ($null -eq $nameProperty) {
            throw 'Provenance file record is missing name.'
        }
        $name = [string]$nameProperty.Value

        $policyProperty = $file.PSObject.Properties['policy']
        if ($null -eq $policyProperty -or $null -eq $policyProperty.Value) {
            throw "Provenance file record '$name' is missing policy."
        }

        $dispositionProperty = $policyProperty.Value.PSObject.Properties['disposition']
        if ($null -eq $dispositionProperty) {
            throw "Provenance file record '$name' is missing policy.disposition."
        }
        $disposition = [string]$dispositionProperty.Value

        [void]$validatedRecords.Add([pscustomobject]@{
            Record = $file
            Name = $name
            Disposition = $disposition
        })
    }

    $fileNames = @($validatedRecords | ForEach-Object { $_.Name })
    Assert-HelloApprovalUniqueWindowsNames -Names $fileNames -Purpose 'Provenance file records'
    Assert-HelloApprovalUniqueWindowsNames -Names $installed -Purpose 'installation_policy.installed_files'

    $validDispositions = @('required', 'unused', 'excluded')
    foreach ($validated in $validatedRecords) {
        $file = $validated.Record
        $name = $validated.Name
        $disposition = $validated.Disposition

        if (-not ($validDispositions -ccontains $disposition)) {
            throw "Unsupported file policy disposition '$disposition' for '$name'."
        }

        if ($disposition -ceq 'required') {
            $sizeProperty = $file.PSObject.Properties['size_bytes']
            if ($null -eq $sizeProperty) {
                throw "Required file '$name' is missing size_bytes."
            }
            if (-not (Test-HelloApprovalNonNegativeInteger -Value $sizeProperty.Value)) {
                throw "Required file '$name' size_bytes must be a non-negative integer."
            }

            $shaProperty = $file.PSObject.Properties['sha256']
            if ($null -eq $shaProperty) {
                throw "Required file '$name' is missing sha256."
            }
            $sha = [string]$shaProperty.Value
            if ($sha -notmatch '^[0-9A-Fa-f]{64}$') {
                throw "Required file '$name' sha256 must be exactly 64 hexadecimal characters."
            }
        }
    }

    $requiredRecords = @($files | Where-Object { $_.policy.disposition -ceq 'required' })
    $requiredNames = @($requiredRecords | ForEach-Object { [string]$_.name })

    if ($requiredNames.Count -ne $installed.Count) {
        throw 'installation_policy.installed_files cardinality does not match required provenance records.'
    }

    foreach ($installedName in $installed) {
        $matches = @($requiredRecords | Where-Object { [string]$_.name -ceq [string]$installedName })
        if ($matches.Count -ne 1) {
            throw "Installed file '$installedName' must have exactly one case-exact required provenance record."
        }
    }

    foreach ($requiredName in $requiredNames) {
        if (-not ($installed -ccontains $requiredName)) {
            throw "Required provenance file '$requiredName' is absent from installation_policy.installed_files with exact case."
        }
    }

    return $true
}

function Assert-HelloApprovalTrustedPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TrustedBase,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [ValidateSet('Any', 'Directory', 'File')]
        [string]$ExpectedType = 'Any',

        [switch]$AllowMissing
    )

    if (-not [IO.Path]::IsPathRooted($TrustedBase)) {
        throw "Trusted base must be absolute: $TrustedBase"
    }
    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "Target path must be absolute: $Path"
    }

    $baseFull = [IO.Path]::GetFullPath($TrustedBase)
    $targetFull = [IO.Path]::GetFullPath($Path)

    $baseRoot = [IO.Path]::GetPathRoot($baseFull)
    $baseTrimmed = if ([string]::Equals($baseFull, $baseRoot, [StringComparison]::OrdinalIgnoreCase)) {
        $baseFull
    } else {
        $baseFull.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    }

    $targetTrimmed = $targetFull.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $baseComparable = $baseTrimmed.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $same = [string]::Equals($targetTrimmed, $baseComparable, [StringComparison]::OrdinalIgnoreCase)

    if ($same) {
        try {
            $baseItem = Get-Item -LiteralPath $targetFull -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            if ($AllowMissing) { return $targetFull }
            throw "Trusted path is missing: $targetFull"
        }

        if ($ExpectedType -ceq 'Directory' -and -not $baseItem.PSIsContainer) {
            throw "Trusted path leaf must be a directory: $targetFull"
        }
        if ($ExpectedType -ceq 'File' -and $baseItem.PSIsContainer) {
            throw "Trusted path leaf must be a file: $targetFull"
        }
        return $targetFull
    }

    $prefix = if ($baseTrimmed.EndsWith([string][IO.Path]::DirectorySeparatorChar) -or
        $baseTrimmed.EndsWith([string][IO.Path]::AltDirectorySeparatorChar)) {
        $baseTrimmed
    } else {
        $baseTrimmed + [IO.Path]::DirectorySeparatorChar
    }

    if (-not $targetFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Target path escapes trusted base. Base='$baseFull' Target='$targetFull'"
    }

    $relative = $targetFull.Substring($prefix.Length)
    $parts = @($relative -split '[\\/]' | Where-Object { $_ -ne '' })
    $cursor = $baseTrimmed

    for ($i = 0; $i -lt $parts.Count; $i++) {
        $cursor = Join-Path $cursor $parts[$i]
        $isLeaf = ($i -eq ($parts.Count - 1))

        try {
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            if ($AllowMissing) {
                return $targetFull
            }
            throw "Trusted path component is missing: $cursor"
        }

        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Trusted path component must not be a reparse point: $cursor"
        }

        if (-not $isLeaf) {
            if (-not $item.PSIsContainer) {
                throw "Trusted path intermediate component must be a directory: $cursor"
            }
            continue
        }

        if ($ExpectedType -ceq 'Directory' -and -not $item.PSIsContainer) {
            throw "Trusted path leaf must be a directory: $cursor"
        }
        if ($ExpectedType -ceq 'File' -and $item.PSIsContainer) {
            throw "Trusted path leaf must be a file: $cursor"
        }
    }

    return $targetFull
}

function Assert-HelloApprovalPinnedRuntime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RuntimeRoot,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        $Pin,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TrustedBase
    )

    [void](Assert-HelloApprovalPinPolicy -Pin $Pin)

    $runtime = Assert-HelloApprovalTrustedPath -TrustedBase $TrustedBase -Path $RuntimeRoot -ExpectedType Directory
    $rootItems = @(Get-ChildItem -LiteralPath $runtime -Force)
    if ($rootItems.Count -ne 1) {
        throw "Pinned runtime root must contain exactly one entry: $runtime"
    }

    $binItem = $rootItems[0]
    if ($binItem.Name -cne 'bin' -or -not $binItem.PSIsContainer -or
        ($binItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Pinned runtime root must contain exactly one real directory named exactly 'bin': $runtime"
    }

    $bin = Assert-HelloApprovalTrustedPath -TrustedBase $TrustedBase -Path $binItem.FullName -ExpectedType Directory
    $required = @($Pin.installation_policy.installed_files | ForEach-Object { [string]$_ })
    $actualItems = @(Get-ChildItem -LiteralPath $bin -Force)
    $actualNames = @($actualItems | ForEach-Object { [string]$_.Name })

    if ($actualNames.Count -ne $required.Count) {
        throw "Pinned runtime bin surface file count differs from installed_files: $bin"
    }

    foreach ($requiredName in $required) {
        if (-not ($actualNames -ccontains $requiredName)) {
            throw "Pinned runtime bin surface is missing exact file '$requiredName': $bin"
        }
    }
    foreach ($actualName in $actualNames) {
        if (-not ($required -ccontains $actualName)) {
            throw "Pinned runtime bin surface contains unexpected or case-mismatched entry '$actualName': $bin"
        }
    }

    foreach ($name in $required) {
        $path = Join-Path $bin $name
        $resolved = Assert-HelloApprovalTrustedPath -TrustedBase $TrustedBase -Path $path -ExpectedType File
        $item = Get-Item -LiteralPath $resolved -Force

        $records = @($Pin.files | Where-Object {
            [string]$_.name -ceq $name -and [string]$_.policy.disposition -ceq 'required'
        })
        if ($records.Count -ne 1) {
            throw "Installed runtime file '$name' must have exactly one required provenance record."
        }

        $record = $records[0]
        if ($item.Length -ne [int64]$record.size_bytes) {
            throw "Pinned runtime file size mismatch: $resolved"
        }

        $actualHash = Get-HelloApprovalFileSha256 -Path $resolved
        $expectedHash = ([string]$record.sha256).ToLowerInvariant()
        if ($actualHash -cne $expectedHash) {
            throw "Pinned runtime file SHA-256 mismatch: $resolved"
        }
    }

    return [pscustomobject]@{
        RuntimeRoot = $runtime
        BinPath = $bin
        InstalledFiles = @($required)
    }
}

Export-ModuleMember -Function @(
    'Assert-HelloApprovalPinPolicy',
    'Assert-HelloApprovalTrustedPath',
    'Get-HelloApprovalFileSha256',
    'Assert-HelloApprovalPinnedRuntime'
)
