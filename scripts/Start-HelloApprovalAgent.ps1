#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AgentPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [ValidateNotNullOrEmpty()]
    [string]$SocketPath = '\\.\pipe\sshenc-github-signing',

    [ValidateNotNullOrEmpty()]
    [string]$LogDirectory = (Join-Path $env:LOCALAPPDATA 'hello-approval\logs')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Start-HelloApprovalAgent.ps1 supports Windows only.'
}
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is not available.'
}

function Resolve-ExistingRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )

    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) {
        throw "$Purpose does not exist: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Purpose must be a regular non-reparse file: $full"
    }
    return $full
}

function Assert-ProjectLogDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $projectRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'hello-approval'))
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $projectRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LogDirectory must stay under the project-owned root '$projectRoot': $full"
    }

    if (-not (Test-Path -LiteralPath $full)) {
        New-Item -ItemType Directory -Path $full -Force | Out-Null
    }
    $item = Get-Item -LiteralPath $full -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "LogDirectory must be a real directory, not a reparse point: $full"
    }
    return $full
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

$agent = Resolve-ExistingRegularFile -Path $AgentPath -Purpose 'sshenc-agent executable'
$config = Resolve-ExistingRegularFile -Path $ConfigPath -Purpose 'sshenc config'
if ([IO.Path]::GetFileName($agent) -ine 'sshenc-agent.exe') {
    throw "AgentPath must end in sshenc-agent.exe: $agent"
}
if ($SocketPath -notmatch '^\\\\\.\\pipe\\[A-Za-z0-9._-]+$') {
    throw "SocketPath must be a simple local Windows named-pipe path: $SocketPath"
}
if ($SocketPath -ieq '\\.\pipe\openssh-ssh-agent') {
    throw 'Refusing to launch on the stock Windows OpenSSH agent pipe.'
}
$logs = Assert-ProjectLogDirectory -Path $LogDirectory

$stdoutLog = Join-Path $logs 'agent.stdout.log'
$stderrLog = Join-Path $logs 'agent.stderr.log'
$operationLog = Join-Path $logs 'sshenc-operations.jsonl'
$launcherLog = Join-Path $logs 'launcher.log'

# Child-only override. Do not persist SSHENC_LOG in user/machine state.
$previousSshencLog = [Environment]::GetEnvironmentVariable('SSHENC_LOG', 'Process')
[Environment]::SetEnvironmentVariable('SSHENC_LOG', $operationLog, 'Process')

$nativeSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class HelloApprovalSupervisor
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint INFINITE = 0xFFFFFFFF;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_ALWAYS = 4;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private const uint FILE_END = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode, ref SECURITY_ATTRIBUTES securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(IntPtr hFile, long distance, out long newFilePointer, uint moveMethod);

    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    private static void ThrowLastError(string operation)
    {
        throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    private static IntPtr OpenAppendLog(string path)
    {
        var sa = new SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
            lpSecurityDescriptor = IntPtr.Zero,
            bInheritHandle = true
        };
        IntPtr handle = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, ref sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE) ThrowLastError("CreateFileW(" + path + ")");
        long ignored;
        if (!SetFilePointerEx(handle, 0, out ignored, FILE_END))
        {
            CloseHandle(handle);
            ThrowLastError("SetFilePointerEx(" + path + ")");
        }
        return handle;
    }

    public static int Run(string executable, string commandLine, string stdoutPath, string stderrPath)
    {
        IntPtr job = IntPtr.Zero;
        IntPtr stdout = INVALID_HANDLE_VALUE;
        IntPtr stderr = INVALID_HANDLE_VALUE;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool created = false;
        bool assigned = false;

        try
        {
            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) ThrowLastError("CreateJobObjectW");

            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr limitsPtr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(limits, limitsPtr, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, limitsPtr, (uint)size))
                    ThrowLastError("SetInformationJobObject(KILL_ON_JOB_CLOSE)");
            }
            finally
            {
                Marshal.FreeHGlobal(limitsPtr);
            }

            stdout = OpenAppendLog(stdoutPath);
            stderr = OpenAppendLog(stderrPath);

            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = IntPtr.Zero;
            si.hStdOutput = stdout;
            si.hStdError = stderr;

            if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                ThrowLastError("CreateProcessW");
            created = true;

            if (!AssignProcessToJobObject(job, pi.hProcess))
                ThrowLastError("AssignProcessToJobObject");
            assigned = true;

            if (ResumeThread(pi.hThread) == 0xFFFFFFFF)
                ThrowLastError("ResumeThread");

            uint wait = WaitForSingleObject(pi.hProcess, INFINITE);
            if (wait != 0) ThrowLastError("WaitForSingleObject");

            uint exitCode;
            if (!GetExitCodeProcess(pi.hProcess, out exitCode))
                ThrowLastError("GetExitCodeProcess");
            return unchecked((int)exitCode);
        }
        finally
        {
            if (created && !assigned && pi.hProcess != IntPtr.Zero)
                TerminateProcess(pi.hProcess, 125);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (stdout != INVALID_HANDLE_VALUE) CloseHandle(stdout);
            if (stderr != INVALID_HANDLE_VALUE) CloseHandle(stderr);
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }
}
'@

try {
    if (-not ('HelloApprovalSupervisor' -as [type])) {
        Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
    }

    $args = @(
        (Quote-WindowsArgument -Value $agent),
        '--foreground',
        '--config', (Quote-WindowsArgument -Value $config),
        '--socket', (Quote-WindowsArgument -Value $SocketPath)
    ) -join ' '

    $startedAt = [DateTimeOffset]::Now.ToString('o')
    Add-Content -LiteralPath $launcherLog -Value "$startedAt START agent=$agent config=$config socket=$SocketPath pid=$PID"

    $exitCode = [HelloApprovalSupervisor]::Run($agent, $args, $stdoutLog, $stderrLog)

    $endedAt = [DateTimeOffset]::Now.ToString('o')
    Add-Content -LiteralPath $launcherLog -Value "$endedAt EXIT code=$exitCode pid=$PID"
    exit $exitCode
} catch {
    try {
        $failedAt = [DateTimeOffset]::Now.ToString('o')
        Add-Content -LiteralPath $launcherLog -Value "$failedAt LAUNCHER_ERROR pid=$PID error=$($_.Exception.Message)"
    } catch {
        # Preserve the original launch failure if logging also fails.
    }
    Write-Error $_ -ErrorAction Continue
    exit 125
} finally {
    [Environment]::SetEnvironmentVariable('SSHENC_LOG', $previousSshencLog, 'Process')
}
