#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalValidation.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$shippedPinPath = Join-Path $repoRoot 'provenance\sshenc-v0.6.101.json'

Import-Module $modulePath -Force -ErrorAction Stop

$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0

function Write-TestPass {
    param([string]$Name)
    $script:Passed++
    Write-Host "PASS  $Name"
}

function Write-TestSkip {
    param([string]$Name, [string]$Reason)
    $script:Skipped++
    Write-Host "SKIP  $Name - $Reason"
}

function Invoke-PassCase {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        Write-TestPass -Name $Name
    } catch {
        $script:Failed++
        Write-Host "FAIL  $Name - $($_.Exception.Message)"
    }
}

function Invoke-ThrowCase {
    param(
        [string]$Name,
        [string]$ExpectedMessagePattern,
        [scriptblock]$Body
    )

    try {
        & $Body
        $script:Failed++
        Write-Host "FAIL  $Name - expected throw"
    } catch {
        $message = [string]$_.Exception.Message
        if ($message -notmatch $ExpectedMessagePattern) {
            $script:Failed++
            Write-Host "FAIL  $Name - wrong exception: $message"
            Write-Host "      expected message pattern: $ExpectedMessagePattern"
        } else {
            Write-TestPass -Name $Name
        }
    }
}

function Copy-Object {
    param($Value)
    return ($Value | ConvertTo-Json -Depth 20 | ConvertFrom-Json)
}

function New-SyntheticPin {
    param([string]$AlphaPath,[string]$BetaPath)

    $alpha = Get-Item -LiteralPath $AlphaPath
    $beta = Get-Item -LiteralPath $BetaPath
    return [pscustomobject]@{
        schema = 'hello-approval/upstream-pin/v1'
        files = @(
            [pscustomobject]@{
                name='alpha.exe'
                sha256=(Get-HelloApprovalFileSha256 -Path $AlphaPath)
                size_bytes=[int64]$alpha.Length
                policy=[pscustomobject]@{ disposition='required' }
            },
            [pscustomobject]@{
                name='beta.exe'
                sha256=(Get-HelloApprovalFileSha256 -Path $BetaPath)
                size_bytes=[int64]$beta.Length
                policy=[pscustomobject]@{ disposition='required' }
            },
            [pscustomobject]@{
                name='unused.exe'
                sha256=('0' * 64)
                size_bytes=[int64]0
                policy=[pscustomobject]@{ disposition='unused' }
            }
        )
        installation_policy = [pscustomobject]@{
            installed_files=@('alpha.exe','beta.exe')
        }
    }
}

function New-RuntimeFixture {
    param([string]$Root,[string]$BinName='bin')

    $trusted = Join-Path $Root 'trusted'
    $runtime = Join-Path $trusted 'hello-approval\runtime\sshenc\v-test'
    $bin = Join-Path $runtime $BinName
    [void][IO.Directory]::CreateDirectory($bin)

    $alpha = Join-Path $bin 'alpha.exe'
    $beta = Join-Path $bin 'beta.exe'
    [IO.File]::WriteAllBytes($alpha,[byte[]](1,2,3,4,5))
    [IO.File]::WriteAllBytes($beta,[byte[]](9,8,7,6))

    return [pscustomobject]@{
        Trusted=$trusted
        Runtime=$runtime
        Bin=$bin
        Alpha=$alpha
        Beta=$beta
        Pin=(New-SyntheticPin -AlphaPath $alpha -BetaPath $beta)
    }
}

function New-Junction {
    param(
        [string]$Link,
        [string]$Target,
        [switch]$DoNotCreateTarget
    )

    if (-not $DoNotCreateTarget) {
        [void][IO.Directory]::CreateDirectory($Target)
    }

    $parent = Split-Path -Parent $Link
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][IO.Directory]::CreateDirectory($parent)
    }

    $savedEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& cmd.exe /d /c mklink /J "$Link" "$Target" 2>&1 | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedEap
    }

    $linkItem = $null
    try {
        $linkItem = Get-Item -LiteralPath $Link -Force -ErrorAction Stop
    } catch {}

    if ($rc -ne 0 -or $null -eq $linkItem) {
        throw "Could not create junction '$Link' -> '$Target': $($output -join ' | ')"
    }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-validation-{0}' -f [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)

try {
    $fixture = New-RuntimeFixture -Root (Join-Path $testRoot 'baseline')

    Invoke-PassCase 'module imports under Windows PowerShell 5.1' {
        if ($null -eq (Get-Command Assert-HelloApprovalPinnedRuntime -ErrorAction Stop)) {
            throw 'missing command'
        }
    }

    Invoke-PassCase 'shipped provenance pin policy is valid' {
        $pin = Get-Content -LiteralPath $shippedPinPath -Raw | ConvertFrom-Json
        [void](Assert-HelloApprovalPinPolicy -Pin $pin)
    }

    Invoke-PassCase 'synthetic exact runtime is accepted' {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $fixture.Runtime -Pin $fixture.Pin -TrustedBase $fixture.Trusted)
    }

    $pinCases = @()

    $p = Copy-Object $fixture.Pin
    $p.PSObject.Properties.Remove('schema')
    $pinCases += [pscustomobject]@{
        Name='pin missing schema'
        Pin=$p
        Expected='Unsupported or missing provenance pin schema'
    }

    $p = Copy-Object $fixture.Pin
    $p.schema='wrong/schema'
    $pinCases += [pscustomobject]@{
        Name='pin wrong schema'
        Pin=$p
        Expected='Unsupported or missing provenance pin schema'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].PSObject.Properties.Remove('name')
    $pinCases += [pscustomobject]@{
        Name='pin record missing name'
        Pin=$p
        Expected='Provenance file record is missing name'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].PSObject.Properties.Remove('policy')
    $pinCases += [pscustomobject]@{
        Name='pin record missing policy'
        Pin=$p
        Expected='is missing policy'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].policy.PSObject.Properties.Remove('disposition')
    $pinCases += [pscustomobject]@{
        Name='pin record missing policy disposition'
        Pin=$p
        Expected='is missing policy.disposition'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].PSObject.Properties.Remove('size_bytes')
    $pinCases += [pscustomobject]@{
        Name='pin required record missing size'
        Pin=$p
        Expected='is missing size_bytes'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].PSObject.Properties.Remove('sha256')
    $pinCases += [pscustomobject]@{
        Name='pin required record missing sha'
        Pin=$p
        Expected='is missing sha256'
    }

    foreach ($bad in @('', '   ', '.', '..', 'dir/name.exe', 'dir\name.exe')) {
        $p = Copy-Object $fixture.Pin
        $p.files[0].name=$bad
        $pinCases += [pscustomobject]@{
            Name="pin invalid file leaf [$bad]"
            Pin=$p
            Expected='Provenance file records contains an invalid non-leaf name'
        }
    }

    $p = Copy-Object $fixture.Pin
    $p.files += Copy-Object $p.files[0]
    $pinCases += [pscustomobject]@{
        Name='pin duplicate file record'
        Pin=$p
        Expected='Provenance file records contains duplicate/case-colliding Windows name'
    }

    $p = Copy-Object $fixture.Pin
    $dup=Copy-Object $p.files[0]
    $dup.name='ALPHA.EXE'
    $p.files += $dup
    $pinCases += [pscustomobject]@{
        Name='pin case-colliding file record'
        Pin=$p
        Expected='Provenance file records contains duplicate/case-colliding Windows name'
    }

    foreach ($bad in @('', '   ', '.', '..', 'dir/name.exe', 'dir\name.exe')) {
        $p = Copy-Object $fixture.Pin
        $p.installation_policy.installed_files[0]=$bad
        $pinCases += [pscustomobject]@{
            Name="pin invalid installed leaf [$bad]"
            Pin=$p
            Expected='installation_policy.installed_files contains an invalid non-leaf name'
        }
    }

    $p = Copy-Object $fixture.Pin
    $p.installation_policy.installed_files += 'alpha.exe'
    $pinCases += [pscustomobject]@{
        Name='pin duplicate installed entry'
        Pin=$p
        Expected='installation_policy.installed_files contains duplicate/case-colliding Windows name'
    }

    $p = Copy-Object $fixture.Pin
    $p.installation_policy.installed_files += 'ALPHA.EXE'
    $pinCases += [pscustomobject]@{
        Name='pin case-colliding installed entry'
        Pin=$p
        Expected='installation_policy.installed_files contains duplicate/case-colliding Windows name'
    }

    $p = Copy-Object $fixture.Pin
    $p.installation_policy.installed_files[0]='ALPHA.EXE'
    $pinCases += [pscustomobject]@{
        Name='pin installed exact-case mismatch'
        Pin=$p
        Expected='must have exactly one case-exact required provenance record'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].name='ALPHA.EXE'
    $pinCases += [pscustomobject]@{
        Name='pin required record exact-case mismatch'
        Pin=$p
        Expected='must have exactly one case-exact required provenance record'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].policy.disposition='mystery'
    $pinCases += [pscustomobject]@{
        Name='pin unknown disposition'
        Pin=$p
        Expected='Unsupported file policy disposition'
    }

    $p = Copy-Object $fixture.Pin
    $p.installation_policy.installed_files=@('alpha.exe')
    $pinCases += [pscustomobject]@{
        Name='pin required-installed mismatch'
        Pin=$p
        Expected='cardinality does not match required provenance records'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].policy.disposition='unused'
    $pinCases += [pscustomobject]@{
        Name='pin missing required record'
        Pin=$p
        Expected='cardinality does not match required provenance records'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].size_bytes='5'
    $pinCases += [pscustomobject]@{
        Name='pin non-integer size'
        Pin=$p
        Expected='size_bytes must be a non-negative integer'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].size_bytes=[int64]-1
    $pinCases += [pscustomobject]@{
        Name='pin negative size'
        Pin=$p
        Expected='size_bytes must be a non-negative integer'
    }

    $p = Copy-Object $fixture.Pin
    $p.files[0].sha256='xyz'
    $pinCases += [pscustomobject]@{
        Name='pin malformed sha'
        Pin=$p
        Expected='sha256 must be exactly 64 hexadecimal characters'
    }

    foreach ($case in $pinCases) {
        Invoke-ThrowCase -Name $case.Name -ExpectedMessagePattern $case.Expected -Body {
            [void](Assert-HelloApprovalPinPolicy -Pin $case.Pin)
        }
    }

    Invoke-ThrowCase -Name 'runtime missing root' -ExpectedMessagePattern 'Trusted path component is missing' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot (Join-Path $fixture.Trusted 'missing') -Pin $fixture.Pin -TrustedBase $fixture.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'extra-root')
    [IO.File]::WriteAllText((Join-Path $r.Runtime 'extra.txt'),'x')
    Invoke-ThrowCase -Name 'runtime extra root entry' -ExpectedMessagePattern 'must contain exactly one entry' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'bin-case') -BinName 'Bin'
    Invoke-ThrowCase -Name 'runtime Bin instead of bin' -ExpectedMessagePattern "must contain exactly one real directory named exactly 'bin'" -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'missing-file')
    Remove-Item -LiteralPath $r.Beta -Force
    Invoke-ThrowCase -Name 'runtime missing file' -ExpectedMessagePattern 'file count differs from installed_files' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'extra-file')
    [IO.File]::WriteAllText((Join-Path $r.Bin 'extra.exe'),'x')
    Invoke-ThrowCase -Name 'runtime extra file' -ExpectedMessagePattern 'file count differs from installed_files' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'case-file')
    Rename-Item -LiteralPath $r.Alpha -NewName 'alpha.tmp'
    Rename-Item -LiteralPath (Join-Path $r.Bin 'alpha.tmp') -NewName 'ALPHA.EXE'
    Invoke-ThrowCase -Name 'runtime case-only filename mismatch' -ExpectedMessagePattern 'is missing exact file' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'directory-file')
    Remove-Item -LiteralPath $r.Alpha -Force
    [void][IO.Directory]::CreateDirectory($r.Alpha)
    Invoke-ThrowCase -Name 'runtime directory where file expected' -ExpectedMessagePattern 'Trusted path leaf must be a file' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'size-mismatch')
    [IO.File]::AppendAllText($r.Alpha,'x')
    Invoke-ThrowCase -Name 'runtime size mismatch' -ExpectedMessagePattern 'file size mismatch' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $r = New-RuntimeFixture -Root (Join-Path $testRoot 'hash-mismatch')
    $bytes=[IO.File]::ReadAllBytes($r.Alpha)
    $bytes[0]=$bytes[0] -bxor 0xFF
    [IO.File]::WriteAllBytes($r.Alpha,$bytes)
    Invoke-ThrowCase -Name 'runtime hash mismatch' -ExpectedMessagePattern 'file SHA-256 mismatch' -Body {
        [void](Assert-HelloApprovalPinnedRuntime -RuntimeRoot $r.Runtime -Pin $r.Pin -TrustedBase $r.Trusted)
    }

    $boundaryRoot = Join-Path $testRoot 'boundary'
    $trusted = Join-Path $boundaryRoot 'Base'
    [void][IO.Directory]::CreateDirectory($trusted)

    Invoke-PassCase 'path trusted base itself accepted' {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $trusted -Path $trusted -ExpectedType Directory)
    }

    Invoke-ThrowCase -Name 'path trusted base explicit wrong type rejected' -ExpectedMessagePattern 'Trusted path leaf must be a file' -Body {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $trusted -Path $trusted -ExpectedType File)
    }

    $missingTrustedBase = Join-Path $boundaryRoot 'MissingBase'
    Invoke-ThrowCase -Name 'path missing trusted base rejected without AllowMissing' -ExpectedMessagePattern 'Trusted path is missing' -Body {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $missingTrustedBase -Path $missingTrustedBase -ExpectedType Directory)
    }

    Invoke-PassCase 'path missing trusted base accepted only with AllowMissing' {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $missingTrustedBase -Path $missingTrustedBase -ExpectedType Directory -AllowMissing)
        if (Test-Path -LiteralPath $missingTrustedBase) {
            throw 'validator created missing trusted base'
        }
    }

    $outside = Join-Path $boundaryRoot 'Outside'
    [void][IO.Directory]::CreateDirectory($outside)
    Invoke-ThrowCase -Name 'path outside trusted base rejected' -ExpectedMessagePattern 'escapes trusted base' -Body {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $trusted -Path $outside -ExpectedType Directory)
    }

    $sibling = $trusted + '2'
    [void][IO.Directory]::CreateDirectory($sibling)
    Invoke-ThrowCase -Name 'path sibling-prefix rejected' -ExpectedMessagePattern 'escapes trusted base' -Body {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $trusted -Path $sibling -ExpectedType Directory)
    }

    $escaped = Join-Path $trusted '..\Outside'
    Invoke-ThrowCase -Name 'path normalized dot-dot escape rejected' -ExpectedMessagePattern 'escapes trusted base' -Body {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $trusted -Path $escaped -ExpectedType Directory)
    }

    $missingAllowed = Join-Path $trusted 'future\child'
    Invoke-PassCase 'path AllowMissing is read-only' {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $trusted -Path $missingAllowed -ExpectedType Directory -AllowMissing)
        if (Test-Path -LiteralPath $missingAllowed) {
            throw 'validator created path'
        }
    }

    Invoke-ThrowCase -Name 'path missing rejected without AllowMissing' -ExpectedMessagePattern 'Trusted path component is missing' -Body {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $trusted -Path $missingAllowed -ExpectedType Directory)
    }

    $danglingRoot = Join-Path $testRoot 'dangling-junction'
    $danglingTrusted = Join-Path $danglingRoot 'trusted'
    [void][IO.Directory]::CreateDirectory($danglingTrusted)
    $danglingLink = Join-Path $danglingTrusted 'redirect'
    $danglingTarget = Join-Path $danglingRoot 'target-does-not-exist'
    New-Junction -Link $danglingLink -Target $danglingTarget -DoNotCreateTarget

    Invoke-ThrowCase -Name 'path dangling junction rejected under AllowMissing' -ExpectedMessagePattern 'must not be a reparse point' -Body {
        [void](Assert-HelloApprovalTrustedPath -TrustedBase $danglingTrusted -Path (Join-Path $danglingLink 'future') -ExpectedType Directory -AllowMissing)
    }

    foreach ($position in @('project','runtime','sshenc','v-test','bin')) {
        $caseRoot = Join-Path $testRoot ('junction-' + $position)
        $trustedCase = Join-Path $caseRoot 'trusted'
        [void][IO.Directory]::CreateDirectory($trustedCase)
        $target = Join-Path $trustedCase 'project\runtime\sshenc\v-test\bin'
        $cursor = $trustedCase

        foreach ($part in @('project','runtime','sshenc','v-test','bin')) {
            $next = Join-Path $cursor $part
            if ($part -ceq $position) {
                New-Junction -Link $next -Target (Join-Path $caseRoot ('redirect-' + $part))
                break
            }
            [void][IO.Directory]::CreateDirectory($next)
            $cursor = $next
        }

        Invoke-ThrowCase -Name "path junction at $position rejected" -ExpectedMessagePattern 'must not be a reparse point' -Body {
            [void](Assert-HelloApprovalTrustedPath -TrustedBase $trustedCase -Path $target -ExpectedType Directory -AllowMissing)
        }
    }

    $linkRoot = Join-Path $testRoot 'file-link'
    $trustedLink = Join-Path $linkRoot 'trusted'
    $realDir = Join-Path $trustedLink 'real'
    [void][IO.Directory]::CreateDirectory($realDir)
    $realFile = Join-Path $realDir 'real.exe'
    [IO.File]::WriteAllText($realFile,'x')
    $linkDir = Join-Path $trustedLink 'surface'
    [void][IO.Directory]::CreateDirectory($linkDir)
    $linkFile = Join-Path $linkDir 'linked.exe'

    $savedEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $linkOutput = @(& cmd.exe /d /c mklink "$linkFile" "$realFile" 2>&1 | ForEach-Object { [string]$_ })
        $linkRc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedEap
    }

    if ($linkRc -eq 0 -and (Test-Path -LiteralPath $linkFile)) {
        Invoke-ThrowCase -Name 'path file-leaf reparse rejected' -ExpectedMessagePattern 'must not be a reparse point' -Body {
            [void](Assert-HelloApprovalTrustedPath -TrustedBase $trustedLink -Path $linkFile -ExpectedType File)
        }
    } else {
        Write-TestSkip -Name 'path file-leaf reparse rejected' -Reason 'symbolic-link creation unavailable'
    }
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host ("RESULT passed={0} failed={1} skipped={2}" -f $script:Passed,$script:Failed,$script:Skipped)
if ($script:Failed -ne 0) { exit 1 }
exit 0
