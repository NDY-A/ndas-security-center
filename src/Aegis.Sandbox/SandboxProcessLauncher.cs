using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Aegis.Sandbox;

public sealed class SandboxProcessLaunchOptions
{
    public required string ExecutablePath { get; init; }
    public required IReadOnlyList<string> Arguments { get; init; }
    public required string WorkingDirectory { get; init; }
    public required string LogPath { get; init; }
    public long ProcessMemoryLimitBytes { get; init; } = 1_500_000_000;
    public long JobMemoryLimitBytes { get; init; } = 2_000_000_000;
}

/// <summary>
/// Starts the sandbox emulator inside a Job Object. When possible the child runs with a
/// restricted low-integrity token so an emulator vulnerability cannot write to normal
/// user data. Failures degrade to a plain job-limited process and are reported as warnings.
/// </summary>
public sealed class SandboxLaunchedProcess : IDisposable
{
    private IntPtr _job;
    private readonly IntPtr _processHandle;
    private readonly IntPtr _threadHandle;
    private readonly IntPtr _logHandle;
    private readonly IntPtr _nulHandle;
    private readonly Process? _fallbackProcess;
    private readonly StreamWriter? _fallbackLog;
    private readonly object _logLock = new();
    private bool _disposed;

    internal SandboxLaunchedProcess(
        int processId,
        bool lowIntegrity,
        string? warning,
        IntPtr job,
        IntPtr processHandle,
        IntPtr threadHandle,
        IntPtr logHandle,
        IntPtr nulHandle,
        Process? fallbackProcess,
        StreamWriter? fallbackLog)
    {
        ProcessId = processId;
        LowIntegrity = lowIntegrity;
        Warning = warning;
        _job = job;
        _processHandle = processHandle;
        _threadHandle = threadHandle;
        _logHandle = logHandle;
        _nulHandle = nulHandle;
        _fallbackProcess = fallbackProcess;
        _fallbackLog = fallbackLog;
    }

    public int ProcessId { get; }
    public bool LowIntegrity { get; }
    public string? Warning { get; }

    internal void AttachJob(IntPtr job)
    {
        _job = job;
    }

    public bool WaitForExit(TimeSpan timeout)
    {
        var milliseconds = (int)Math.Clamp(timeout.TotalMilliseconds, 0, int.MaxValue);
        if (_fallbackProcess is not null)
        {
            try
            {
                return _fallbackProcess.WaitForExit(milliseconds);
            }
            catch
            {
                return true;
            }
        }

        return SandboxProcessLauncher.WaitForSingleObject(_processHandle, (uint)milliseconds) == 0;
    }

    public void Kill()
    {
        try
        {
            if (_job != IntPtr.Zero)
            {
                SandboxProcessLauncher.TerminateJobObject(_job, 1);
            }
            else if (_fallbackProcess is not null)
            {
                _fallbackProcess.Kill(entireProcessTree: true);
            }
            else if (_processHandle != IntPtr.Zero)
            {
                SandboxProcessLauncher.TerminateProcess(_processHandle, 1);
            }
        }
        catch
        {
            // Killing is best-effort during teardown.
        }
    }

    internal void AppendLog(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        lock (_logLock)
        {
            try
            {
                _fallbackLog?.WriteLine(text);
                _fallbackLog?.Flush();
            }
            catch
            {
                // Logging must never break the run.
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_fallbackProcess is not null)
        {
            try
            {
                if (_fallbackProcess.HasExited)
                {
                    _fallbackProcess.WaitForExit();
                }
            }
            catch
            {
                // Best effort.
            }
        }

        lock (_logLock)
        {
            try
            {
                _fallbackLog?.Dispose();
            }
            catch
            {
                // Best effort.
            }
        }

        try
        {
            _fallbackProcess?.Dispose();
        }
        catch
        {
            // Best effort.
        }

        SandboxProcessLauncher.SafeClose(_logHandle);
        SandboxProcessLauncher.SafeClose(_nulHandle);
        SandboxProcessLauncher.SafeClose(_threadHandle);
        SandboxProcessLauncher.SafeClose(_processHandle);
        // Closing the job with KILL_ON_JOB_CLOSE terminates any surviving children.
        SandboxProcessLauncher.SafeClose(_job);
    }
}

public static class SandboxProcessLauncher
{
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint DisableMaxPrivilege = 0x0001;
    private const int TokenIntegrityLevelClass = 25;
    private const uint SeGroupIntegrity = 0x00000020;
    private const uint SePrivilegeEnabled = 0x00000002;

    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const int StartfUseShowWindow = 0x00000001;
    private const int StartfUseStdHandles = 0x00000100;

    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint OpenAlways = 4;
    private const uint FileAttributeNormal = 0x80;

    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitProcessMemory = 0x00000100;
    private const uint JobObjectLimitJobMemory = 0x00000200;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectUiLimitDesktop = 0x00000001;
    private const uint JobObjectUiLimitExitWindows = 0x00000008;
    private const int JobObjectBasicUiRestrictionsClass = 4;
    private const int JobObjectExtendedLimitInformationClass = 9;

    public static SandboxLaunchedProcess? Start(SandboxProcessLaunchOptions options, out string error)
    {
        error = string.Empty;
        Directory.CreateDirectory(options.WorkingDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(options.LogPath) ?? options.WorkingDirectory);

        try
        {
            var launched = TryStartWithRestrictedToken(options, out var nativeError);
            if (launched is not null)
            {
                return launched;
            }

            launched = TryStartFallback(options, nativeError, out error);
            return launched;
        }
        catch (Exception exception)
        {
            error = "启动沙箱进程失败：" + exception.Message;
            return null;
        }
    }

    private static SandboxLaunchedProcess? TryStartWithRestrictedToken(
        SandboxProcessLaunchOptions options, out string error)
    {
        error = string.Empty;
        var handles = new List<IntPtr>();
        IntPtr logHandle = IntPtr.Zero;
        IntPtr nulHandle = IntPtr.Zero;
        IntPtr job = IntPtr.Zero;
        IntPtr processHandle = IntPtr.Zero;
        IntPtr threadHandle = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero;
        var transferred = false;

        try
        {
            EnablePrivilege("SeAssignPrimaryTokenPrivilege");
            EnablePrivilege("SeIncreaseQuotaPrivilege");

            if (!OpenProcessToken(GetCurrentProcess(),
                    TokenDuplicate | TokenAssignPrimary | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId,
                    out var baseToken))
            {
                error = "OpenProcessToken 失败：" + LastError();
                return null;
            }

            handles.Add(baseToken);
            if (!CreateRestrictedToken(baseToken, DisableMaxPrivilege, 0, IntPtr.Zero, 0, IntPtr.Zero, 0,
                    IntPtr.Zero, out var restrictedToken))
            {
                error = "CreateRestrictedToken 失败：" + LastError();
                return null;
            }

            handles.Add(restrictedToken);
            if (ConvertStringSidToSidW("S-1-16-4096", out var lowSid))
            {
                handles.Add(lowSid);
                var label = new TokenMandatoryLabel
                {
                    Label = new SidAndAttributes { Sid = lowSid, Attributes = SeGroupIntegrity }
                };
                if (!SetTokenInformation(restrictedToken, TokenIntegrityLevelClass, ref label,
                        Marshal.SizeOf<TokenMandatoryLabel>()))
                {
                    error = "设置低完整性令牌失败：" + LastError();
                    return null;
                }
            }
            else
            {
                error = "无法构造低完整性 SID：" + LastError();
                return null;
            }

            var security = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                InheritHandle = 1
            };

            logHandle = CreateFileW(options.LogPath, GenericWrite,
                FileShareRead | FileShareWrite | FileShareDelete, ref security, OpenAlways,
                FileAttributeNormal, IntPtr.Zero);
            if (logHandle == new IntPtr(-1))
            {
                error = "创建沙箱日志文件失败：" + LastError();
                return null;
            }

            nulHandle = CreateFileW("NUL", GenericRead,
                FileShareRead | FileShareWrite, ref security, OpenExisting, 0, IntPtr.Zero);
            if (nulHandle == new IntPtr(-1))
            {
                error = "打开 NUL 设备失败：" + LastError();
                return null;
            }

            var startup = new StartupInfo
            {
                Size = Marshal.SizeOf<StartupInfo>(),
                Flags = StartfUseShowWindow | StartfUseStdHandles,
                ShowWindow = 0,
                StdInput = nulHandle,
                StdOutput = logHandle,
                StdError = logHandle
            };

            var commandLine = new StringBuilder(BuildCommandLine(options.ExecutablePath, options.Arguments));
            environment = BuildEnvironmentBlock(options.WorkingDirectory);

            const uint creationFlags = CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment;
            if (!CreateProcessAsUserW(restrictedToken, options.ExecutablePath, commandLine, IntPtr.Zero,
                    IntPtr.Zero, true, creationFlags, environment, options.WorkingDirectory,
                    ref startup, out var processInfo))
            {
                error = "CreateProcessAsUser 失败：" + LastError();
                return null;
            }

            processHandle = processInfo.ProcessHandle;
            threadHandle = processInfo.ThreadHandle;

            job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero || !ConfigureJob(job, options))
            {
                // Without the job object we do not run the emulator with SYSTEM privileges.
                error = "创建作业对象失败：" + LastError();
                TerminateProcess(processHandle, 1);
                SafeClose(processHandle);
                SafeClose(threadHandle);
                processHandle = IntPtr.Zero;
                threadHandle = IntPtr.Zero;
                return null;
            }

            if (!AssignProcessToJobObject(job, processHandle))
            {
                error = "将沙箱进程加入作业对象失败：" + LastError();
                TerminateProcess(processHandle, 1);
                SafeClose(processHandle);
                SafeClose(threadHandle);
                SafeClose(job);
                return null;
            }

            ResumeThread(threadHandle);
            transferred = true;

            return new SandboxLaunchedProcess(processInfo.ProcessId, true, null, job, processHandle,
                threadHandle, logHandle, nulHandle, null, null);
        }
        catch (Exception exception)
        {
            error = exception.Message;
            if (processHandle != IntPtr.Zero)
            {
                TerminateProcess(processHandle, 1);
            }

            SafeClose(threadHandle);
            SafeClose(processHandle);
            SafeClose(job);
            return null;
        }
        finally
        {
            if (!transferred)
            {
                SafeClose(logHandle);
                SafeClose(nulHandle);
            }

            SafeClose(environment);
            foreach (var handle in handles)
            {
                SafeClose(handle);
            }
        }
    }

    private static SandboxLaunchedProcess? TryStartFallback(
        SandboxProcessLaunchOptions options, string nativeError, out string error)
    {
        error = string.Empty;
        Process? process = null;
        StreamWriter? log = null;
        IntPtr job = IntPtr.Zero;
        try
        {
            Directory.CreateDirectory(Path.Combine(options.WorkingDirectory, "tmp"));
            var startInfo = new ProcessStartInfo(options.ExecutablePath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = options.WorkingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var argument in options.Arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            startInfo.Environment["TMP"] = Path.Combine(options.WorkingDirectory, "tmp");
            startInfo.Environment["TEMP"] = Path.Combine(options.WorkingDirectory, "tmp");
            startInfo.Environment["PYTHONDONTWRITEBYTECODE"] = "1";
            startInfo.Environment["PYTHONNOUSERSITE"] = "1";

            log = new StreamWriter(new FileStream(options.LogPath, FileMode.Append, FileAccess.Write,
                FileShare.ReadWrite | FileShare.Delete)) { AutoFlush = true };
            log.WriteLine("[NDAS] 低完整性令牌不可用（" + nativeError + "），改用普通作业对象限制。");

            process = Process.Start(startInfo);
            if (process is null)
            {
                error = "无法启动沙箱进程。";
                return null;
            }

            var launched = new SandboxLaunchedProcess(process.Id, false, nativeError, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, process, log);
            process.OutputDataReceived += (_, args) => launched.AppendLog(args.Data);
            process.ErrorDataReceived += (_, args) => launched.AppendLog(args.Data);
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            try
            {
                job = CreateJobObjectW(IntPtr.Zero, null);
                if (job != IntPtr.Zero && ConfigureJob(job, options))
                {
                    if (AssignProcessToJobObject(job, process.Handle))
                    {
                        launched.AttachJob(job);
                    }
                    else
                    {
                        SafeClose(job);
                        job = IntPtr.Zero;
                    }
                }
                else
                {
                    SafeClose(job);
                    job = IntPtr.Zero;
                }
            }
            catch
            {
                SafeClose(job);
                job = IntPtr.Zero;
            }

            return launched;
        }
        catch (Exception exception)
        {
            error = "启动沙箱进程失败：" + exception.Message;
            try
            {
                process?.Kill(entireProcessTree: true);
                process?.Dispose();
                log?.Dispose();
            }
            catch
            {
                // Best effort.
            }

            SafeClose(job);
            return null;
        }
    }

    private static bool ConfigureJob(IntPtr job, SandboxProcessLaunchOptions options)
    {
        var limits = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose | JobObjectLimitActiveProcess |
                             JobObjectLimitProcessMemory | JobObjectLimitJobMemory,
                ActiveProcessLimit = 1
            },
            ProcessMemoryLimit = (UIntPtr)(ulong)Math.Max(64 * 1024 * 1024, options.ProcessMemoryLimitBytes),
            JobMemoryLimit = (UIntPtr)(ulong)Math.Max(64 * 1024 * 1024, options.JobMemoryLimitBytes)
        };

        var limitsSize = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        var limitsPointer = Marshal.AllocHGlobal(limitsSize);
        try
        {
            Marshal.StructureToPtr(limits, limitsPointer, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, limitsPointer,
                    (uint)limitsSize))
            {
                return false;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(limitsPointer);
        }

        var ui = new JobObjectBasicUiRestrictions
        {
            UiRestrictions = JobObjectUiLimitDesktop | JobObjectUiLimitExitWindows
        };
        var uiSize = Marshal.SizeOf<JobObjectBasicUiRestrictions>();
        var uiPointer = Marshal.AllocHGlobal(uiSize);
        try
        {
            Marshal.StructureToPtr(ui, uiPointer, false);
            SetInformationJobObject(job, JobObjectBasicUiRestrictionsClass, uiPointer, (uint)uiSize);
        }
        finally
        {
            Marshal.FreeHGlobal(uiPointer);
        }

        return true;
    }

    private static IntPtr BuildEnvironmentBlock(string workingDirectory)
    {
        var variables = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string key && entry.Value is string value)
            {
                variables[key] = value;
            }
        }

        var temporary = Path.Combine(workingDirectory, "tmp");
        variables["TMP"] = temporary;
        variables["TEMP"] = temporary;
        variables["PYTHONDONTWRITEBYTECODE"] = "1";
        variables["PYTHONNOUSERSITE"] = "1";

        var builder = new StringBuilder();
        foreach (var pair in variables)
        {
            builder.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');
        }

        builder.Append('\0');
        return Marshal.StringToHGlobalUni(builder.ToString());
    }

    private static string BuildCommandLine(string executable, IReadOnlyList<string> arguments)
    {
        var builder = new StringBuilder(Quote(executable));
        foreach (var argument in arguments)
        {
            builder.Append(' ').Append(Quote(argument));
        }

        return builder.ToString();
    }

    private static string Quote(string value)
    {
        if (value.Length == 0)
        {
            return "\"\"";
        }

        if (value.IndexOfAny(new[] { ' ', '\t', '"' }) < 0)
        {
            return value;
        }

        var builder = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var character in value)
        {
            if (character == '\\')
            {
                backslashes++;
            }
            else if (character == '"')
            {
                builder.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
            }
            else
            {
                builder.Append('\\', backslashes).Append(character);
                backslashes = 0;
            }
        }

        builder.Append('\\', backslashes * 2).Append('"');
        return builder.ToString();
    }

    private static void EnablePrivilege(string name)
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out token))
            {
                return;
            }

            if (!LookupPrivilegeValueW(null, name, out var luid))
            {
                return;
            }

            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Privilege = new LuidAndAttributes { Luid = luid, Attributes = SePrivilegeEnabled }
            };
            AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        catch
        {
            // Missing privileges simply force the fallback launcher.
        }
        finally
        {
            SafeClose(token);
        }
    }

    private static string LastError() => new Win32Exception(Marshal.GetLastWin32Error()).Message;

    internal static void SafeClose(IntPtr handle)
    {
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            try
            {
                CloseHandle(handle);
            }
            catch
            {
                // Best effort.
            }
        }
    }

    // ---- Win32 interop ----

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel
    {
        public SidAndAttributes Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privilege;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
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
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicUiRestrictions
    {
        public uint UiRestrictions;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int Size;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2Size;
        public IntPtr Reserved2;
        public IntPtr StdInput;
        public IntPtr StdOutput;
        public IntPtr StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr ProcessHandle;
        public IntPtr ThreadHandle;
        public int ProcessId;
        public int ThreadId;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(IntPtr existingToken, uint flags, uint disableSidCount,
        IntPtr sidsToDisable, uint restrictSidCount, IntPtr sidsToRestrict, uint denySidCount, IntPtr sidsToDeny,
        out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
        ref TokenMandatoryLabel tokenInformation, int tokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
        ref TokenPrivileges newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUserW(IntPtr token, string? applicationName,
        StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint creationFlags, IntPtr environment, string? currentDirectory, ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        ref SecurityAttributes securityAttributes, uint creationDisposition, uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObjectW(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
