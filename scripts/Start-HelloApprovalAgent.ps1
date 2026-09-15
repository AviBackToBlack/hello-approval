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

    [AllowEmptyString()]
    [string]$LogDirectory = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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
    $rootTrimmed = $projectRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)
    $prefix = $rootTrimmed + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "LogDirectory must stay under the project-owned root '$projectRoot': $full"
    }

    # Establish/verify the project root before traversing any requested child.
    # Never create through an existing junction/symlink and reject a project
    # root that is itself redirected.
    if (-not (Test-Path -LiteralPath $projectRoot)) {
        New-Item -ItemType Directory -Path $projectRoot | Out-Null
    }
    $rootItem = Get-Item -LiteralPath $projectRoot -Force
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Project-owned log root must be a real directory, not a reparse point: $projectRoot"
    }

    $relative = $full.Substring($prefix.Length)
    $parts = @($relative -split '[\\/]' | Where-Object { $_ -ne '' })
    $cursor = $projectRoot
    foreach ($part in $parts) {
        $next = Join-Path $cursor $part
        if (Test-Path -LiteralPath $next) {
            $item = Get-Item -LiteralPath $next -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Project log path must use real directories, not reparse points: $next"
            }
        } else {
            New-Item -ItemType Directory -Path $next | Out-Null
            $item = Get-Item -LiteralPath $next -Force
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Newly created project log path is not a real directory: $next"
            }
        }
        $cursor = $next
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

$launcherLog = $null
$previousSshencLog = [Environment]::GetEnvironmentVariable('SSHENC_LOG', 'Process')
$sshencLogChanged = $false

try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'Start-HelloApprovalAgent.ps1 supports Windows only.'
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is not available.'
    }
    if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        $LogDirectory = Join-Path $env:LOCALAPPDATA 'hello-approval\logs'
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
    [Environment]::SetEnvironmentVariable('SSHENC_LOG', $operationLog, 'Process')
    $sshencLogChanged = $true

    $nativeSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class HelloApprovalSupervisor
{
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint INFINITE = 0xFFFFFFFF;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_APPEND_DATA = 0x00000004;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint OPEN_ALWAYS = 4;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
    private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
    private static readonly IntPtr PROC_THREAD_ATTRIBUTE_JOB_LIST = new IntPtr(0x0002000D);

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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
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
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        int dwAttributeCount,
        int dwFlags,
        ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,
        uint dwFlags,
        IntPtr attribute,
        IntPtr lpValue,
        IntPtr cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);


    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);


    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode, ref SECURITY_ATTRIBUTES securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    private static void ThrowLastError(string operation)
    {
        throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    private static SECURITY_ATTRIBUTES InheritableSecurityAttributes()
    {
        return new SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
            lpSecurityDescriptor = IntPtr.Zero,
            bInheritHandle = true
        };
    }

    private static IntPtr OpenAppendLog(string path)
    {
        var sa = InheritableSecurityAttributes();
        IntPtr handle = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, ref sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE) ThrowLastError("CreateFileW(" + path + ")");
        return handle;
    }

    private static IntPtr OpenNullInput()
    {
        var sa = InheritableSecurityAttributes();
        IntPtr handle = CreateFileW("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, ref sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (handle == INVALID_HANDLE_VALUE) ThrowLastError("CreateFileW(NUL)");
        return handle;
    }

    public static int Run(string executable, string commandLine, string stdoutPath, string stderrPath)
    {
        IntPtr job = IntPtr.Zero;
        IntPtr stdin = INVALID_HANDLE_VALUE;
        IntPtr stdout = INVALID_HANDLE_VALUE;
        IntPtr stderr = INVALID_HANDLE_VALUE;
        IntPtr attributeList = IntPtr.Zero;
        IntPtr handleList = IntPtr.Zero;
        IntPtr jobList = IntPtr.Zero;
        bool attributeListInitialized = false;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

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

            stdin = OpenNullInput();
            stdout = OpenAppendLog(stdoutPath);
            stderr = OpenAppendLog(stderrPath);

            IntPtr attributeBytes = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attributeBytes);
            if (attributeBytes == IntPtr.Zero)
                ThrowLastError("InitializeProcThreadAttributeList(size)");
            attributeList = Marshal.AllocHGlobal(attributeBytes);
            if (!InitializeProcThreadAttributeList(attributeList, 2, 0, ref attributeBytes))
                ThrowLastError("InitializeProcThreadAttributeList");
            attributeListInitialized = true;

            int handleBytes = IntPtr.Size * 3;
            handleList = Marshal.AllocHGlobal(handleBytes);
            Marshal.WriteIntPtr(handleList, 0 * IntPtr.Size, stdin);
            Marshal.WriteIntPtr(handleList, 1 * IntPtr.Size, stdout);
            Marshal.WriteIntPtr(handleList, 2 * IntPtr.Size, stderr);
            if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handleList,
                    new IntPtr(handleBytes),
                    IntPtr.Zero,
                    IntPtr.Zero))
                ThrowLastError("UpdateProcThreadAttribute(HANDLE_LIST)");

            jobList = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(jobList, job);
            if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST,
                    jobList,
                    new IntPtr(IntPtr.Size),
                    IntPtr.Zero,
                    IntPtr.Zero))
                ThrowLastError("UpdateProcThreadAttribute(JOB_LIST)");

            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = stdin;
            si.StartupInfo.hStdOutput = stdout;
            si.StartupInfo.hStdError = stderr;
            si.lpAttributeList = attributeList;

            var writableCommandLine = new StringBuilder(commandLine);
            if (!CreateProcessW(executable, writableCommandLine, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    IntPtr.Zero, null, ref si, out pi))
                ThrowLastError("CreateProcessW");

            // PROC_THREAD_ATTRIBUTE_JOB_LIST makes membership atomic with
            // process creation. The primary thread is still suspended here.
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
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (attributeListInitialized && attributeList != IntPtr.Zero) DeleteProcThreadAttributeList(attributeList);
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
            if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
            if (attributeList != IntPtr.Zero) Marshal.FreeHGlobal(attributeList);
            if (stdin != INVALID_HANDLE_VALUE) CloseHandle(stdin);
            if (stdout != INVALID_HANDLE_VALUE) CloseHandle(stdout);
            if (stderr != INVALID_HANDLE_VALUE) CloseHandle(stderr);
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }
}
'@

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
    if (-not [string]::IsNullOrWhiteSpace($launcherLog)) {
        try {
            $failedAt = [DateTimeOffset]::Now.ToString('o')
            Add-Content -LiteralPath $launcherLog -Value "$failedAt LAUNCHER_ERROR pid=$PID error=$($_.Exception.Message)"
        } catch {
            # Preserve the original launch failure if logging also fails.
        }
    }
    Write-Error $_ -ErrorAction Continue
    exit 125
} finally {
    if ($sshencLogChanged) {
        [Environment]::SetEnvironmentVariable('SSHENC_LOG', $previousSshencLog, 'Process')
    }
}
