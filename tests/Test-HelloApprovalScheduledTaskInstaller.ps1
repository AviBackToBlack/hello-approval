#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ExpectedPhase1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Test-HelloApprovalScheduledTaskInstaller.ps1 supports Windows only.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceInstaller = Join-Path $repoRoot 'scripts\Install-HelloApprovalScheduledTask.ps1'
$sourceLauncher = Join-Path $repoRoot 'scripts\Start-HelloApprovalAgent.ps1'
$sourceModule = Join-Path $repoRoot 'lib\HelloApproval.Validation.psm1'
$ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$taskName = 'hello-approval Git Signing Agent'

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

function Get-FileSha256Local([string]$Path) {
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Compile-TestExe {
    param(
        [string]$OutputPath,
        [string]$SourceText
    )

    $sourcePath = [IO.Path]::ChangeExtension($OutputPath,'.cs')
    [IO.File]::WriteAllText($sourcePath,$SourceText,[Text.UTF8Encoding]::new($false))

    $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
        $csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
    }
    if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
        throw 'Could not find .NET Framework csc.exe for synthetic test PE generation.'
    }

    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $csc /nologo /target:exe "/out:$OutputPath" $sourcePath 2>&1 | ForEach-Object { [string]$_ })
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($rc -ne 0 -or -not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
        throw "Synthetic PE compilation failed: $($output -join ' | ')"
    }
    Remove-Item -LiteralPath $sourcePath -Force
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

    Copy-Item -LiteralPath $sourceInstaller -Destination (Join-Path $scripts 'Install-HelloApprovalScheduledTask.ps1') -Force
    Copy-Item -LiteralPath $sourceLauncher -Destination (Join-Path $scripts 'Start-HelloApprovalAgent.ps1') -Force
    Copy-Item -LiteralPath $sourceModule -Destination (Join-Path $lib 'HelloApproval.Validation.psm1') -Force

    return [pscustomobject]@{
        Repo = $mini
        Installer = Join-Path $scripts 'Install-HelloApprovalScheduledTask.ps1'
        PinPath = Join-Path $provenance 'sshenc-v0.6.101.json'
    }
}

function New-SyntheticRuntime {
    param(
        [string]$LocalAppData,
        [string]$PinPath,
        [string]$ConfigPath,
        [switch]$RuntimeThroughJunction,
        [switch]$UnknownUnusedDisposition
    )

    [void][IO.Directory]::CreateDirectory($LocalAppData)
    $projectRoot = Join-Path $LocalAppData 'hello-approval'
    [void][IO.Directory]::CreateDirectory($projectRoot)

    if ($RuntimeThroughJunction) {
        $redirect = Join-Path (Split-Path -Parent $LocalAppData) ('redirect-' + [Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($redirect)
        $runtimeLink = Join-Path $projectRoot 'runtime'

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& cmd.exe /d /c mklink /J "$runtimeLink" "$redirect" 2>&1 | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }
        if ($rc -ne 0) {
            throw "Could not create runtime junction fixture: $($output -join ' | ')"
        }
        $runtimeBase = Join-Path $redirect 'sshenc'
    } else {
        $runtimeBase = Join-Path (Join-Path $projectRoot 'runtime') 'sshenc'
    }

    $runtimeRoot = Join-Path $runtimeBase 'v-test'
    $bin = Join-Path $runtimeRoot 'bin'
    [void][IO.Directory]::CreateDirectory($bin)

    $sshenc = Join-Path $bin 'sshenc.exe'
    $agent = Join-Path $bin 'sshenc-agent.exe'

    $sshencSource = @'
using System;
public static class Program {
    public static int Main(string[] args) {
        if (args.Length == 2 && args[0] == "config" && args[1] == "path") {
            Console.WriteLine(Environment.GetEnvironmentVariable("HELLO_APPROVAL_TEST_CONFIG_PATH"));
            return 0;
        }
        if (args.Length == 2 && args[0] == "config" && args[1] == "show") {
            string labels = Environment.GetEnvironmentVariable("HELLO_APPROVAL_TEST_ALLOWED_LABELS");
            Console.WriteLine(@"socket_path = '\\.\pipe\sshenc-github-signing'");
            Console.WriteLine("allowed_labels = " + (labels ?? "[\"github-signing\"]"));
            Console.WriteLine("prompt_policy = \"always\"");
            return 0;
        }
        if (args.Length == 2 && args[0] == "list" && args[1] == "--json") {
            string exitText = Environment.GetEnvironmentVariable("HELLO_APPROVAL_TEST_LIST_EXIT");
            if (!String.IsNullOrEmpty(exitText)) { return Int32.Parse(exitText); }
            string listPath = Environment.GetEnvironmentVariable("HELLO_APPROVAL_TEST_LIST_JSON");
            if (String.IsNullOrEmpty(listPath) || !System.IO.File.Exists(listPath)) { return 3; }
            Console.Write(System.IO.File.ReadAllText(listPath));
            return 0;
        }
        return 2;
    }
}
'@
    $agentSource = @'
public static class Program {
    public static int Main(string[] args) { return 0; }
}
'@

    Compile-TestExe -OutputPath $sshenc -SourceText $sshencSource
    Compile-TestExe -OutputPath $agent -SourceText $agentSource

    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $ConfigPath))
    [IO.File]::WriteAllText($ConfigPath,'synthetic-config',[Text.UTF8Encoding]::new($false))

    $unusedDisposition = if ($UnknownUnusedDisposition) { 'mystery' } else { 'unused' }
    $pin = [ordered]@{
        schema = 'hello-approval/upstream-pin/v1'
        upstream = [ordered]@{ release_tag = 'v-test' }
        files = @(
            [ordered]@{
                name='sshenc.exe'
                size_bytes=[int64](Get-Item -LiteralPath $sshenc).Length
                sha256=Get-FileSha256Local -Path $sshenc
                policy=[ordered]@{ disposition='required' }
            },
            [ordered]@{
                name='sshenc-agent.exe'
                size_bytes=[int64](Get-Item -LiteralPath $agent).Length
                sha256=Get-FileSha256Local -Path $agent
                policy=[ordered]@{ disposition='required' }
            },
            [ordered]@{
                name='unused.exe'
                size_bytes=[int64]0
                sha256=('0' * 64)
                policy=[ordered]@{ disposition=$unusedDisposition }
            }
        )
        installation_policy = [ordered]@{
            target_architecture='x86_64-pc-windows-msvc'
            allowed_distribution='zip-manual-placement'
            installed_files=@('sshenc.exe','sshenc-agent.exe')
        }
    }

    [IO.File]::WriteAllText(
        $PinPath,
        ($pin | ConvertTo-Json -Depth 20),
        [Text.UTF8Encoding]::new($false)
    )

    return [pscustomobject]@{
        RuntimeRoot=$runtimeRoot
        Bin=$bin
        ProjectRoot=$projectRoot
        RedirectRoot=if($RuntimeThroughJunction){$redirect}else{$null}
    }
}

function Invoke-InstallerWhatIf {
    param(
        [string]$Installer,
        [string]$LocalAppData,
        [string]$ConfigPath
    )

    $oldLocal = $env:LOCALAPPDATA
    $oldConfig = $env:HELLO_APPROVAL_TEST_CONFIG_PATH
    try {
        $env:LOCALAPPDATA = $LocalAppData
        $env:HELLO_APPROVAL_TEST_CONFIG_PATH = $ConfigPath

        $saved = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $ps51 -NoProfile -ExecutionPolicy Bypass -File $Installer -WhatIf 2>&1 | ForEach-Object { [string]$_ })
            $rc = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $saved
        }

        return [pscustomobject]@{
            ExitCode=$rc
            Output=@($output)
        }
    } finally {
        $env:LOCALAPPDATA = $oldLocal
        if ($null -eq $oldConfig) {
            Remove-Item Env:HELLO_APPROVAL_TEST_CONFIG_PATH -ErrorAction SilentlyContinue
        } else {
            $env:HELLO_APPROVAL_TEST_CONFIG_PATH = $oldConfig
        }
    }
}

function Invoke-InstallerToRegistrationBoundary {
    param(
        [string]$Installer,
        [string]$LocalAppData,
        [string]$ConfigPath
    )

    $oldLocal = $env:LOCALAPPDATA
    $oldConfig = $env:HELLO_APPROVAL_TEST_CONFIG_PATH
    try {
        $env:LOCALAPPDATA = $LocalAppData
        $env:HELLO_APPROVAL_TEST_CONFIG_PATH = $ConfigPath

        $sentinel = 'HELLO_APPROVAL_TEST_REGISTRATION_BOUNDARY'
        $caught = $null
        $capture = @{ WorkingDirectory = $null; Arguments = $null }

        try {
            & {
                param($InstallerPath,$SentinelText,$Capture)

                function Register-ScheduledTask {
                    [CmdletBinding()]
                    param(
                        [string]$TaskName,
                        [string]$TaskPath,
                        $Action,
                        $Trigger,
                        $Principal,
                        $Settings,
                        [string]$Description,
                        [switch]$Force
                    )
                    $Capture.WorkingDirectory = [string]$Action.WorkingDirectory
                    $Capture.Arguments = [string]$Action.Arguments
                    throw $SentinelText
                }

                function Unregister-ScheduledTask {
                    [CmdletBinding(SupportsShouldProcess = $true)]
                    param(
                        [string]$TaskName,
                        [string]$TaskPath
                    )
                    return
                }

                & $InstallerPath
            } $Installer $sentinel $capture
        } catch {
            $caught = [string]$_.Exception.Message
        }

        return [pscustomobject]@{
            Sentinel = $sentinel
            ExceptionMessage = $caught
            WorkingDirectory = $capture.WorkingDirectory
            Arguments = $capture.Arguments
        }
    } finally {
        $env:LOCALAPPDATA = $oldLocal
        if ($null -eq $oldConfig) {
            Remove-Item Env:HELLO_APPROVAL_TEST_CONFIG_PATH -ErrorAction SilentlyContinue
        } else {
            $env:HELLO_APPROVAL_TEST_CONFIG_PATH = $oldConfig
        }
    }
}

$existingTask = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    throw "Test precondition failed: Scheduled Task already exists: \$taskName"
}

function Set-FixtureReleaseTag {
    param(
        [Parameter(Mandatory = $true)][string]$PinPath,
        [Parameter(Mandatory = $true)][string]$Mode,
        [AllowNull()][string]$Value
    )

    $pinObject = Get-Content -LiteralPath $PinPath -Raw | ConvertFrom-Json
    switch ($Mode) {
        'missing' { [void]$pinObject.upstream.PSObject.Properties.Remove('release_tag') }
        'boolean' { $pinObject.upstream.release_tag = $true }
        default { $pinObject.upstream.release_tag = $Value }
    }
    $pinText = $pinObject | ConvertTo-Json -Depth 20
    # Keep the pin ASCII so non-ASCII fixture tags survive the reader's default PS5.1 encoding.
    $pinText = [regex]::Replace($pinText, '[^\x00-\x7F]', { param($m) '\u{0:X4}' -f [int][char]$m.Value })
    [IO.File]::WriteAllText($PinPath, $pinText, [Text.UTF8Encoding]::new($false))
}

function Test-ReleaseTagRefusal($Result) {
    return (($Result.Output -join ' ') -match 'Refusing installation because pinned upstream\.release_tag is missing, non-string')
}

$releaseTagCases = @(
    [pscustomobject]@{ Name = 'missing'; Mode = 'missing'; Value = $null; Reject = $true },
    [pscustomobject]@{ Name = 'non-string'; Mode = 'boolean'; Value = $null; Reject = $true },
    [pscustomobject]@{ Name = 'blank'; Mode = 'value'; Value = '   '; Reject = $true },
    [pscustomobject]@{ Name = 'current-directory'; Mode = 'value'; Value = '.'; Reject = $true },
    [pscustomobject]@{ Name = 'parent-directory'; Mode = 'value'; Value = '..'; Reject = $true },
    [pscustomobject]@{ Name = 'traversal'; Mode = 'value'; Value = '..\escape'; Reject = $true },
    [pscustomobject]@{ Name = 'drive-qualified'; Mode = 'value'; Value = 'C:'; Reject = $true },
    [pscustomobject]@{ Name = 'wildcard'; Mode = 'value'; Value = 'v*test'; Reject = $true },
    [pscustomobject]@{ Name = 'trailing-dot'; Mode = 'value'; Value = 'v-test.'; Reject = $true },
    [pscustomobject]@{ Name = 'reserved-device CONIN$'; Mode = 'value'; Value = 'conin$'; Reject = $true },
    [pscustomobject]@{ Name = 'reserved-device COM superscript-one'; Mode = 'value'; Value = ('COM' + [char]0x00B9); Reject = $true },
    [pscustomobject]@{ Name = 'overlong-component'; Mode = 'value'; Value = ('v' + ('x' * 255)); Reject = $true },
    [pscustomobject]@{ Name = 'MAX_PATH-exceeding composed runtime path'; Mode = 'value'; Value = ('v' + ('x' * 199)); Reject = $true },
    [pscustomobject]@{ Name = 'non-reserved COM10'; Mode = 'value'; Value = 'COM10'; Reject = $false }
)

function Assert-ReleaseTagCase($TagCase, $Result, [bool]$Mutated, [string]$Gate) {
    if ($TagCase.Reject) {
        $label = "hardened installer rejects $($TagCase.Name) upstream release tag before $Gate"
        if ($Result.ExitCode -ne 0 -and (Test-ReleaseTagRefusal $Result) -and -not $Mutated) { Pass $label }
        else { Fail $label ("rc={0} mutated={1} output={2}" -f $Result.ExitCode, $Mutated, ($Result.Output -join ' | ')) }
    } else {
        $label = "hardened installer does not refuse $($TagCase.Name) upstream release tag"
        if (-not (Test-ReleaseTagRefusal $Result) -and -not $Mutated) { Pass $label }
        else { Fail $label ("rc={0} mutated={1} output={2}" -f $Result.ExitCode, $Mutated, ($Result.Output -join ' | ')) }
    }
}
function New-PreviousGenerationBundle {
    # A self-consistent earlier bundle generation: different module bytes, and a launcher whose single
    # validation-module pin names them. It gets its own content-addressed digest directory, like any
    # bundle installed by an earlier commit.
    param([string]$Root)

    [void][IO.Directory]::CreateDirectory($Root)
    $utf8 = [Text.UTF8Encoding]::new($false)
    $module = Join-Path $Root 'HelloApproval.Validation.psm1'
    [IO.File]::WriteAllText($module, ([IO.File]::ReadAllText($sourceModule) + "# previous-generation bundle test fixture`n"), $utf8)
    $moduleHash = Get-FileSha256Local -Path $module

    $pinPattern = "(?m)^\`$ValidationModuleSha256 = '[a-f0-9]{64}'$"
    $launcherText = [IO.File]::ReadAllText($sourceLauncher)
    if ([regex]::Matches($launcherText, $pinPattern).Count -ne 1) { throw 'Launcher must contain exactly one validation-module pin.' }
    $launcher = Join-Path $Root 'Start-HelloApprovalAgent.ps1'
    [IO.File]::WriteAllText($launcher, [regex]::Replace($launcherText, $pinPattern, ("`$ValidationModuleSha256 = '{0}'" -f $moduleHash)), $utf8)

    return [pscustomobject]@{
        Launcher = $launcher
        Module = $module
        LauncherHash = Get-FileSha256Local -Path $launcher
        ModuleHash = $moduleHash
    }
}

function Install-BundleDirectory {
    param([string]$LauncherRoot, $Bundle)

    $dir = Join-Path $LauncherRoot $Bundle.LauncherHash
    [void][IO.Directory]::CreateDirectory($dir)
    Copy-Item -LiteralPath $Bundle.Launcher -Destination (Join-Path $dir 'Start-HelloApprovalAgent.ps1')
    Copy-Item -LiteralPath $Bundle.Module -Destination (Join-Path $dir 'HelloApproval.Validation.psm1')
    return $dir
}

function Test-BundleDirectoryExact {
    param([string]$Dir, [string]$LauncherHash, [string]$ModuleHash)

    if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return $false }
    $items = @(Get-ChildItem -LiteralPath $Dir -Force)
    $names = @($items | ForEach-Object { $_.Name })
    return (
        $items.Count -eq 2 -and
        ($names -ccontains 'Start-HelloApprovalAgent.ps1') -and
        ($names -ccontains 'HelloApproval.Validation.psm1') -and
        (Split-Path -Leaf $Dir) -ceq $LauncherHash -and
        (Get-FileSha256Local -Path (Join-Path $Dir 'Start-HelloApprovalAgent.ps1')) -ceq $LauncherHash -and
        (Get-FileSha256Local -Path (Join-Path $Dir 'HelloApproval.Validation.psm1')) -ceq $ModuleHash
    )
}

# Restaging creates fresh directories/files, so a sentinel creation time proves a bundle was left in place.
$bundleSentinelTime = [DateTime]::new(2001, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)

function Set-BundleSentinelTime {
    param([string]$Dir)
    foreach ($item in @(Get-ChildItem -LiteralPath $Dir -Force)) { $item.CreationTimeUtc = $bundleSentinelTime }
    (Get-Item -LiteralPath $Dir -Force).CreationTimeUtc = $bundleSentinelTime
}

function Test-BundleSentinelTime {
    param([string]$Dir)
    $items = @(Get-Item -LiteralPath $Dir -Force) + @(Get-ChildItem -LiteralPath $Dir -Force)
    return (@($items | Where-Object { $_.CreationTimeUtc -ne $bundleSentinelTime }).Count -eq 0)
}

function Get-SshFingerprint([byte[]]$Blob) {
    return 'SHA256:' + [Convert]::ToBase64String([Security.Cryptography.SHA256]::Create().ComputeHash($Blob)).TrimEnd('=')
}

function New-SigningIdentityFixture {
    # Isolated USERPROFILE with a canonical ~/.ssh/github-signing.pub. The installer derives the single
    # expected sshenc label from the credential whose fingerprint matches this key (#45).
    param([string]$Root)

    $profileRoot = Join-Path $Root 'profile'
    $ssh = Join-Path $profileRoot '.ssh'
    [void][IO.Directory]::CreateDirectory($ssh)
    $blob = [Text.Encoding]::ASCII.GetBytes('hello-approval synthetic canonical signing key blob')
    $publicKey = Join-Path $ssh 'github-signing.pub'
    [IO.File]::WriteAllText($publicKey, ('sk-ecdsa-sha2-nistp256@openssh.com {0} synthetic' -f [Convert]::ToBase64String($blob)), [Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{
        Profile = $profileRoot
        PublicKey = $publicKey
        Fingerprint = Get-SshFingerprint $blob
        OtherFingerprint = Get-SshFingerprint ([Text.Encoding]::ASCII.GetBytes('hello-approval synthetic unrelated key blob'))
        ListPath = Join-Path $Root 'sshenc-list.json'
    }
}

function Set-CredentialList {
    # Writes the fake `sshenc list --json` output in the upstream v0.6.101 shape.
    param([string]$Path, [object[]]$Entries)

    $items = @(foreach ($entry in $Entries) {
        [ordered]@{
            metadata = [ordered]@{ label = $entry.Label; algorithm = 'SkEcdsaP256' }
            fingerprint_sha256 = $entry.Fingerprint
        }
    })
    $json = if ($items.Count -eq 0) { '[]' } else { ConvertTo-Json -InputObject @($items) -Depth 5 }
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('hello-approval-task-installer-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

$identityEnvNames = @('USERPROFILE', 'HELLO_APPROVAL_TEST_LIST_JSON', 'HELLO_APPROVAL_TEST_LIST_EXIT', 'HELLO_APPROVAL_TEST_ALLOWED_LABELS')
$savedIdentityEnv = @{}
foreach ($name in $identityEnvNames) { $savedIdentityEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

try {
    # Every installer run below sees only the synthetic signing identity, never the real profile.
    $identity = New-SigningIdentityFixture -Root (Join-Path $root 'identity')
    Set-CredentialList -Path $identity.ListPath -Entries @(@{ Label = 'github-signing'; Fingerprint = $identity.Fingerprint })
    $env:USERPROFILE = $identity.Profile
    $env:HELLO_APPROVAL_TEST_LIST_JSON = $identity.ListPath
    [Environment]::SetEnvironmentVariable('HELLO_APPROVAL_TEST_LIST_EXIT', $null, 'Process')
    [Environment]::SetEnvironmentVariable('HELLO_APPROVAL_TEST_ALLOWED_LABELS', $null, 'Process')

    # Exact fixture.
    $exactRoot = Join-Path $root 'exact'
    [void][IO.Directory]::CreateDirectory($exactRoot)
    $exactRepo = New-SyntheticRepo -Root $exactRoot
    $exactLocal = Join-Path $exactRoot 'local'
    $exactConfig = Join-Path $exactRoot 'config\config.toml'
    $exactRuntime = New-SyntheticRuntime -LocalAppData $exactLocal -PinPath $exactRepo.PinPath -ConfigPath $exactConfig
    $exact = Invoke-InstallerWhatIf -Installer $exactRepo.Installer -LocalAppData $exactLocal -ConfigPath $exactConfig
    $launcherRoot = Join-Path (Join-Path (Join-Path $exactLocal 'hello-approval') 'app') 'launcher'
    if ($exact.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $launcherRoot)) {
        Pass 'exact runtime reaches Scheduled Task WhatIf gate without filesystem mutation'
    } else {
        Fail 'exact runtime reaches Scheduled Task WhatIf gate without filesystem mutation' ("rc={0} launcherRoot={1} output={2}" -f $exact.ExitCode,(Test-Path -LiteralPath $launcherRoot),($exact.Output -join ' | '))
    }

    if (-not $ExpectedPhase1) {
        $boundary = Invoke-InstallerToRegistrationBoundary -Installer $exactRepo.Installer -LocalAppData $exactLocal -ConfigPath $exactConfig
        $launcherHash = Get-FileSha256Local -Path $sourceLauncher
        $launcherVersionRoot = Join-Path $launcherRoot $launcherHash
        $installedLauncher = Join-Path $launcherVersionRoot 'Start-HelloApprovalAgent.ps1'
        $installedValidationModule = Join-Path $launcherVersionRoot 'HelloApproval.Validation.psm1'
        $validationModuleHash = Get-FileSha256Local -Path $sourceModule
        $launcherItems = @(if (Test-Path -LiteralPath $launcherVersionRoot -PathType Container) {
            Get-ChildItem -LiteralPath $launcherVersionRoot -Force
        })
        $stagingItems = @(if (Test-Path -LiteralPath $launcherRoot -PathType Container) {
            Get-ChildItem -LiteralPath $launcherRoot -Force | Where-Object { $_.Name -like '.staging.*' }
        })
        $taskAfterBoundary = Get-ScheduledTask -TaskName $taskName -TaskPath ([string][char]92) -ErrorAction SilentlyContinue

        $launcherNames = @($launcherItems | ForEach-Object { $_.Name })
        $launcherNonFiles = @($launcherItems | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
        $launcherExact = (
            $launcherItems.Count -eq 2 -and
            ($launcherNames -ccontains 'Start-HelloApprovalAgent.ps1') -and
            ($launcherNames -ccontains 'HelloApproval.Validation.psm1') -and
            $launcherNonFiles.Count -eq 0 -and
            (Get-FileSha256Local -Path $installedLauncher) -ceq $launcherHash -and
            (Get-FileSha256Local -Path $installedValidationModule) -ceq $validationModuleHash
        )

        if ($boundary.ExceptionMessage -ceq $boundary.Sentinel -and
            $launcherExact -and
            $stagingItems.Count -eq 0 -and
            $null -eq $taskAfterBoundary) {
            Pass 'launcher write path reaches stubbed registration boundary with exact committed cache surface'
        } else {
            Fail 'launcher write path reaches stubbed registration boundary with exact committed cache surface' (
                "exception={0} launcherExact={1} stagingCount={2} taskPresent={3}" -f
                $boundary.ExceptionMessage,$launcherExact,$stagingItems.Count,($null -ne $taskAfterBoundary)
            )
        }
    }

    if (-not $ExpectedPhase1) {
        $staleRoot = Join-Path $root 'stale-eol'
        [void][IO.Directory]::CreateDirectory($staleRoot)
        $staleRepo = New-SyntheticRepo -Root $staleRoot
        $staleLocal = Join-Path $staleRoot 'local'
        $staleConfig = Join-Path $staleRoot 'config\config.toml'
        [void](New-SyntheticRuntime -LocalAppData $staleLocal -PinPath $staleRepo.PinPath -ConfigPath $staleConfig)

        $staleModule = Join-Path (Join-Path $staleRepo.Repo 'lib') 'HelloApproval.Validation.psm1'
        $moduleText = [IO.File]::ReadAllText($staleModule)
        $moduleText = [regex]::Replace($moduleText, "\r?\n", "`r`n")
        [IO.File]::WriteAllText($staleModule,$moduleText,[Text.UTF8Encoding]::new($false))

        $staleResult = Invoke-InstallerWhatIf -Installer $staleRepo.Installer -LocalAppData $staleLocal -ConfigPath $staleConfig
        if ($staleResult.ExitCode -ne 0 -and (($staleResult.Output -join ' | ') -match 'stale CRLF working-tree bytes')) {
            Pass 'installer diagnoses stale CRLF validation-module working tree'
        } else {
            Fail 'installer diagnoses stale CRLF validation-module working tree' ("rc={0} output={1}" -f $staleResult.ExitCode,($staleResult.Output -join ' | '))
        }
    }

    # Exact-case behavior is already strict in Phase 1 and must remain strict.
    Rename-Item -LiteralPath (Join-Path $exactRuntime.Bin 'sshenc.exe') -NewName 'sshenc.tmp'
    Rename-Item -LiteralPath (Join-Path $exactRuntime.Bin 'sshenc.tmp') -NewName 'SSHENC.EXE'
    $caseResult = Invoke-InstallerWhatIf -Installer $exactRepo.Installer -LocalAppData $exactLocal -ConfigPath $exactConfig
    if ($caseResult.ExitCode -ne 0) {
        Pass 'case-only runtime drift is rejected'
    } else {
        Fail 'case-only runtime drift is rejected' 'installer unexpectedly returned success'
    }

    # Ancestry delta: Phase 1 does not inspect the intermediate runtime junction.
    $junctionRoot = Join-Path $root 'junction'
    [void][IO.Directory]::CreateDirectory($junctionRoot)
    $junctionRepo = New-SyntheticRepo -Root $junctionRoot
    $junctionLocal = Join-Path $junctionRoot 'local'
    $junctionConfig = Join-Path $junctionRoot 'config\config.toml'
    $junctionRuntime = New-SyntheticRuntime -LocalAppData $junctionLocal -PinPath $junctionRepo.PinPath -ConfigPath $junctionConfig -RuntimeThroughJunction
    $junctionResult = Invoke-InstallerWhatIf -Installer $junctionRepo.Installer -LocalAppData $junctionLocal -ConfigPath $junctionConfig

    if ($ExpectedPhase1) {
        if ($junctionResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts runtime through intermediate junction'
        } else {
            Fail 'Phase1 baseline accepts runtime through intermediate junction' ($junctionResult.Output -join ' | ')
        }
    } else {
        if ($junctionResult.ExitCode -ne 0 -and (($junctionResult.Output -join ' | ') -match 'reparse point')) {
            Pass 'hardened installer rejects runtime intermediate junction'
        } else {
            Fail 'hardened installer rejects runtime intermediate junction' ("rc={0} output={1}" -f $junctionResult.ExitCode,($junctionResult.Output -join ' | '))
        }
    }

    # Malformed-pin delta: unknown disposition on an uninstalled/unused record.
    $pinRoot = Join-Path $root 'malformed'
    [void][IO.Directory]::CreateDirectory($pinRoot)
    $pinRepo = New-SyntheticRepo -Root $pinRoot
    $pinLocal = Join-Path $pinRoot 'local'
    $pinConfig = Join-Path $pinRoot 'config\config.toml'
    [void](New-SyntheticRuntime -LocalAppData $pinLocal -PinPath $pinRepo.PinPath -ConfigPath $pinConfig -UnknownUnusedDisposition)
    $pinResult = Invoke-InstallerWhatIf -Installer $pinRepo.Installer -LocalAppData $pinLocal -ConfigPath $pinConfig

    if ($ExpectedPhase1) {
        if ($pinResult.ExitCode -eq 0) {
            Pass 'Phase1 baseline accepts unknown disposition on unused pin record'
        } else {
            Fail 'Phase1 baseline accepts unknown disposition on unused pin record' ($pinResult.Output -join ' | ')
        }
    } else {
        if ($pinResult.ExitCode -ne 0 -and (($pinResult.Output -join ' | ') -match 'Unsupported file policy disposition')) {
            Pass 'hardened installer rejects unknown pin disposition'
        } else {
            Fail 'hardened installer rejects unknown pin disposition' ("rc={0} output={1}" -f $pinResult.ExitCode,($pinResult.Output -join ' | '))
        }
    }

    if (-not $ExpectedPhase1) {
        $tagIndex = 0
        foreach ($tagCase in $releaseTagCases) {
            $tagIndex++
            $tagRoot = Join-Path $root ('release-tag-{0}' -f $tagIndex)
            [void][IO.Directory]::CreateDirectory($tagRoot)
            $tagRepo = New-SyntheticRepo -Root $tagRoot
            $tagLocal = Join-Path $tagRoot 'local'
            $tagConfig = Join-Path $tagRoot 'config\config.toml'
            [void](New-SyntheticRuntime -LocalAppData $tagLocal -PinPath $tagRepo.PinPath -ConfigPath $tagConfig)
            Set-FixtureReleaseTag -PinPath $tagRepo.PinPath -Mode $tagCase.Mode -Value $tagCase.Value
            $tagResult = Invoke-InstallerWhatIf -Installer $tagRepo.Installer -LocalAppData $tagLocal -ConfigPath $tagConfig
            $tagMutated = Test-Path -LiteralPath (Join-Path $tagLocal 'hello-approval\app\launcher')
            Assert-ReleaseTagCase $tagCase $tagResult $tagMutated 'runtime path construction'
        }
    }
    if (-not $ExpectedPhase1) {
        # Existing-install upgrade: an earlier bundle generation is installed; the current repository
        # stages its own digest directory, re-points the task there, and leaves the old one untouched.
        $migrationRoot = Join-Path $root 'migration'
        [void][IO.Directory]::CreateDirectory($migrationRoot)
        $migrationRepo = New-SyntheticRepo -Root $migrationRoot
        $migrationLocal = Join-Path $migrationRoot 'local'
        $migrationConfig = Join-Path $migrationRoot 'config\config.toml'
        [void](New-SyntheticRuntime -LocalAppData $migrationLocal -PinPath $migrationRepo.PinPath -ConfigPath $migrationConfig)
        $migrationLauncherRoot = Join-Path (Join-Path (Join-Path $migrationLocal 'hello-approval') 'app') 'launcher'
        [void][IO.Directory]::CreateDirectory($migrationLauncherRoot)
        $previous = New-PreviousGenerationBundle -Root (Join-Path $migrationRoot 'previous-generation')
        $previousDir = Install-BundleDirectory -LauncherRoot $migrationLauncherRoot -Bundle $previous
        Set-BundleSentinelTime -Dir $previousDir
        $currentHash = Get-FileSha256Local -Path $sourceLauncher
        $currentModuleHash = Get-FileSha256Local -Path $sourceModule
        $currentDir = Join-Path $migrationLauncherRoot $currentHash

        $upgrade = Invoke-InstallerToRegistrationBoundary -Installer $migrationRepo.Installer -LocalAppData $migrationLocal -ConfigPath $migrationConfig
        $staging = @(Get-ChildItem -LiteralPath $migrationLauncherRoot -Force | Where-Object { $_.Name -like '.staging.*' })
        if ($previous.LauncherHash -cne $currentHash -and
            $upgrade.ExceptionMessage -ceq $upgrade.Sentinel -and
            $upgrade.WorkingDirectory -ceq $currentDir -and
            (Test-BundleDirectoryExact -Dir $currentDir -LauncherHash $currentHash -ModuleHash $currentModuleHash) -and
            (Test-BundleDirectoryExact -Dir $previousDir -LauncherHash $previous.LauncherHash -ModuleHash $previous.ModuleHash) -and
            (Test-BundleSentinelTime -Dir $previousDir) -and
            $staging.Count -eq 0) {
            Pass 'existing-install upgrade stages the new digest directory and retains the previous bundle byte-exact'
        } else {
            Fail 'existing-install upgrade stages the new digest directory and retains the previous bundle byte-exact' ("exception={0} workdir={1} staging={2}" -f $upgrade.ExceptionMessage,$upgrade.WorkingDirectory,$staging.Count)
        }

        # Rollback: the previous commit's launcher and module re-point the task at the retained bundle,
        # which must verify byte-exact in place without restaging or touching the newer bundle.
        if (Test-Path -LiteralPath $currentDir -PathType Container) { Set-BundleSentinelTime -Dir $currentDir }
        $rollbackRepo = New-SyntheticRepo -Root (Join-Path $migrationRoot 'rollback')
        Copy-Item -LiteralPath $previous.Launcher -Destination (Join-Path (Join-Path $rollbackRepo.Repo 'scripts') 'Start-HelloApprovalAgent.ps1') -Force
        Copy-Item -LiteralPath $previous.Module -Destination (Join-Path (Join-Path $rollbackRepo.Repo 'lib') 'HelloApproval.Validation.psm1') -Force
        Copy-Item -LiteralPath $migrationRepo.PinPath -Destination $rollbackRepo.PinPath -Force
        $rollback = Invoke-InstallerToRegistrationBoundary -Installer $rollbackRepo.Installer -LocalAppData $migrationLocal -ConfigPath $migrationConfig
        $staging = @(Get-ChildItem -LiteralPath $migrationLauncherRoot -Force | Where-Object { $_.Name -like '.staging.*' })
        $digestDirs = @(Get-ChildItem -LiteralPath $migrationLauncherRoot -Force -Directory)
        if ($rollback.ExceptionMessage -ceq $rollback.Sentinel -and
            $rollback.WorkingDirectory -ceq $previousDir -and
            (Test-BundleDirectoryExact -Dir $previousDir -LauncherHash $previous.LauncherHash -ModuleHash $previous.ModuleHash) -and
            (Test-BundleDirectoryExact -Dir $currentDir -LauncherHash $currentHash -ModuleHash $currentModuleHash) -and
            (Test-BundleSentinelTime -Dir $previousDir) -and
            (Test-BundleSentinelTime -Dir $currentDir) -and
            $digestDirs.Count -eq 2 -and
            $staging.Count -eq 0) {
            Pass 'rollback re-points at the retained previous bundle after byte-exact verification'
        } else {
            Fail 'rollback re-points at the retained previous bundle after byte-exact verification' ("exception={0} workdir={1} dirs={2} staging={3}" -f $rollback.ExceptionMessage,$rollback.WorkingDirectory,$digestDirs.Count,$staging.Count)
        }

        # A tampered retained bundle must be refused rather than re-registered.
        [IO.File]::AppendAllText((Join-Path $previousDir 'HelloApproval.Validation.psm1'), "# tampered`n")
        $tampered = Invoke-InstallerToRegistrationBoundary -Installer $rollbackRepo.Installer -LocalAppData $migrationLocal -ConfigPath $migrationConfig
        if ($tampered.ExceptionMessage -match 'Installed launcher bundle contains mismatched bytes' -and $null -eq $tampered.WorkingDirectory) {
            Pass 'rollback refuses a tampered retained bundle before registration'
        } else {
            Fail 'rollback refuses a tampered retained bundle before registration' ("exception={0} workdir={1}" -f $tampered.ExceptionMessage,$tampered.WorkingDirectory)
        }
    }

    if (-not $ExpectedPhase1) {
        # #45: the single exposed label is the label of the credential whose public key is the canonical
        # ~/.ssh/github-signing.pub, compared exactly. A name alone is never enough.
        $labelRoot = Join-Path $root 'label'
        [void][IO.Directory]::CreateDirectory($labelRoot)
        $labelRepo = New-SyntheticRepo -Root $labelRoot
        $labelLocal = Join-Path $labelRoot 'local'
        $labelConfig = Join-Path $labelRoot 'config\config.toml'
        [void](New-SyntheticRuntime -LocalAppData $labelLocal -PinPath $labelRepo.PinPath -ConfigPath $labelConfig)
        $caseList = Join-Path $labelRoot 'case-list.json'

        $labelCases = @(
            @{ Name = 'per-host label of the canonical credential is accepted'; Entries = @(@{ Label = 'github-signing-host1'; Fingerprint = $identity.Fingerprint }); Allowed = '["github-signing-host1"]'; Expect = $null },
            @{ Name = 'canonical credential among unrelated credentials is accepted'; Entries = @(@{ Label = 'work-auth'; Fingerprint = $identity.OtherFingerprint }, @{ Label = 'github-signing-host1'; Fingerprint = $identity.Fingerprint }); Allowed = '["github-signing-host1"]'; Expect = $null },
            @{ Name = 'default label is refused when the canonical credential has another label'; Entries = @(@{ Label = 'github-signing-host1'; Fingerprint = $identity.Fingerprint }); Allowed = '["github-signing"]'; Expect = 'must contain exactly the canonical signing credential label' },
            @{ Name = 'a github-signing-named credential that is not the canonical key is refused'; Entries = @(@{ Label = 'github-signing'; Fingerprint = $identity.OtherFingerprint }, @{ Label = 'github-signing-host1'; Fingerprint = $identity.Fingerprint }); Allowed = '["github-signing"]'; Expect = 'must contain exactly the canonical signing credential label' },
            @{ Name = 'case-variant label is refused'; Entries = @(@{ Label = 'github-signing-host1'; Fingerprint = $identity.Fingerprint }); Allowed = '["GitHub-Signing-Host1"]'; Expect = 'must contain exactly the canonical signing credential label' },
            @{ Name = 'empty allowed_labels (upstream expose-all) is refused'; Entries = @(@{ Label = 'github-signing'; Fingerprint = $identity.Fingerprint }); Allowed = '[]'; Expect = 'must contain exactly the canonical signing credential label' },
            @{ Name = 'two allowed labels are refused'; Entries = @(@{ Label = 'github-signing'; Fingerprint = $identity.Fingerprint }); Allowed = '["github-signing", "work-auth"]'; Expect = 'must contain exactly the canonical signing credential label' },
            @{ Name = 'no credential for the canonical key is refused'; Entries = @(@{ Label = 'github-signing'; Fingerprint = $identity.OtherFingerprint }); Allowed = '["github-signing"]'; Expect = 'Expected exactly one sshenc credential matching the canonical signing public key' },
            @{ Name = 'empty credential list is refused'; Entries = @(); Allowed = '["github-signing"]'; Expect = 'Expected exactly one sshenc credential matching the canonical signing public key' },
            @{ Name = 'two credentials for the canonical key are refused'; Entries = @(@{ Label = 'github-signing'; Fingerprint = $identity.Fingerprint }, @{ Label = 'github-signing-host1'; Fingerprint = $identity.Fingerprint }); Allowed = '["github-signing"]'; Expect = 'Expected exactly one sshenc credential matching the canonical signing public key' },
            @{ Name = 'invalid credential label grammar is refused'; Entries = @(@{ Label = 'github signing'; Fingerprint = $identity.Fingerprint }); Allowed = '["github signing"]'; Expect = 'is not a valid sshenc label' },
            @{ Name = 'malformed sshenc list JSON is refused'; Raw = '{ not json'; Allowed = '["github-signing"]'; Expect = 'did not return a JSON credential array' },
            @{ Name = 'sshenc list entry without a label is refused'; Raw = ('[{"metadata":{},"fingerprint_sha256":"' + $identity.Fingerprint + '"}]'); Allowed = '["github-signing"]'; Expect = 'did not return a JSON credential array' },
            @{ Name = 'failing sshenc list is refused'; ListExit = '5'; Entries = @(); Allowed = '["github-signing"]'; Expect = 'list --json failed with exit 5' }
        )

        foreach ($labelCase in $labelCases) {
            if ($labelCase.ContainsKey('Raw')) {
                [IO.File]::WriteAllText($caseList, $labelCase.Raw, [Text.UTF8Encoding]::new($false))
            } else {
                Set-CredentialList -Path $caseList -Entries $labelCase.Entries
            }
            $env:HELLO_APPROVAL_TEST_LIST_JSON = $caseList
            $env:HELLO_APPROVAL_TEST_ALLOWED_LABELS = $labelCase.Allowed
            if ($labelCase.ContainsKey('ListExit')) { $env:HELLO_APPROVAL_TEST_LIST_EXIT = $labelCase.ListExit }
            try {
                $labelResult = Invoke-InstallerWhatIf -Installer $labelRepo.Installer -LocalAppData $labelLocal -ConfigPath $labelConfig
            } finally {
                $env:HELLO_APPROVAL_TEST_LIST_JSON = $identity.ListPath
                [Environment]::SetEnvironmentVariable('HELLO_APPROVAL_TEST_ALLOWED_LABELS', $null, 'Process')
                [Environment]::SetEnvironmentVariable('HELLO_APPROVAL_TEST_LIST_EXIT', $null, 'Process')
            }
            $labelOutput = $labelResult.Output -join ' | '
            $labelMutated = Test-Path -LiteralPath (Join-Path $labelLocal 'hello-approval\app\launcher')
            $ok = if ($null -eq $labelCase.Expect) {
                $labelResult.ExitCode -eq 0
            } else {
                $labelResult.ExitCode -ne 0 -and $labelOutput -match [regex]::Escape($labelCase.Expect)
            }
            if ($ok -and -not $labelMutated) { Pass ('signing label: ' + $labelCase.Name) }
            else { Fail ('signing label: ' + $labelCase.Name) ("rc={0} mutated={1} output={2}" -f $labelResult.ExitCode,$labelMutated,$labelOutput) }
        }

        # Canonical public-key preconditions (same contract as the Git signing installer).
        $publicKeyText = [IO.File]::ReadAllText($identity.PublicKey)
        $keyCases = @(
            @{ Name = 'missing canonical public key is refused'; Text = $null; Expect = 'Trusted path component is missing' },
            @{ Name = 'non-SK canonical public key is refused'; Text = ($publicKeyText -replace '^sk-ecdsa-sha2-nistp256@openssh.com', 'ssh-ed25519'); Expect = 'Signing public key must be an sk-ecdsa-sha2-nistp256@openssh.com key' },
            @{ Name = 'two-line canonical public key is refused'; Text = ($publicKeyText + "`n" + $publicKeyText); Expect = 'Signing public key must contain exactly one non-empty line' },
            @{ Name = 'non-base64 canonical public key is refused'; Text = 'sk-ecdsa-sha2-nistp256@openssh.com not*base64 synthetic'; Expect = 'Signing public key blob is not valid base64' }
        )
        foreach ($keyCase in $keyCases) {
            try {
                if ($null -eq $keyCase.Text) { [IO.File]::Delete($identity.PublicKey) }
                else { [IO.File]::WriteAllText($identity.PublicKey, $keyCase.Text, [Text.UTF8Encoding]::new($false)) }
                $keyResult = Invoke-InstallerWhatIf -Installer $labelRepo.Installer -LocalAppData $labelLocal -ConfigPath $labelConfig
            } finally {
                [IO.File]::WriteAllText($identity.PublicKey, $publicKeyText, [Text.UTF8Encoding]::new($false))
            }
            $keyOutput = $keyResult.Output -join ' | '
            if ($keyResult.ExitCode -ne 0 -and $keyOutput -match [regex]::Escape($keyCase.Expect)) { Pass ('signing label: ' + $keyCase.Name) }
            else { Fail ('signing label: ' + $keyCase.Name) ("rc={0} output={1}" -f $keyResult.ExitCode,$keyOutput) }
        }
    }

    Write-Host ''
    Write-Host ("RESULT passed={0} failed={1} mode={2}" -f $script:Passed,$script:Failed,$(if($ExpectedPhase1){'Phase1'}else{'Hardened'}))
    if ($script:Failed -ne 0) { exit 1 }
    exit 0
} finally {
    foreach ($name in $identityEnvNames) { [Environment]::SetEnvironmentVariable($name, $savedIdentityEnv[$name], 'Process') }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
