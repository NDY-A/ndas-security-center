using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Aegis.AgentHost;

public sealed class AgentLaunchOptions
{
    public required string ExecutablePath { get; init; }
    public required IReadOnlyList<string> Arguments { get; init; }
    public required string WorkingDirectory { get; init; }
    public required string LogPath { get; init; }
    // The 300M INT8 ONNX model plus ORT arenas commits ~650MB, so the old
    // 512MB/768MB caps would kill the daemon mid-load.
    public long ProcessMemoryLimitBytes { get; init; } = 2L * 1024 * 1024 * 1024;
    public long JobMemoryLimitBytes { get; init; } = 2560L * 1024 * 1024;
}

/// <summary>
/// A live agent child process. stdin/stdout are the protocol duplex pipes; stderr goes to
/// the log file. The child runs low-integrity with a restricted SID set and inside a
/// kill-on-close job object with a single-process limit.
/// </summary>
public sealed class AgentLaunchedProcess : IDisposable
{
    private readonly IntPtr _job;
    private readonly IntPtr _processHandle;
    private readonly IntPtr _threadHandle;
    private readonly IntPtr _logHandle;
    private readonly Process? _fallbackProcess;
    private bool _disposed;

    internal AgentLaunchedProcess(
        int processId,
        bool lowIntegrity,
        bool restrictedToken,
        string? warning,
        IntPtr job,
        IntPtr processHandle,
        IntPtr threadHandle,
        IntPtr logHandle,
        Stream stdin,
        Stream stdout,
        Process? fallbackProcess)
    {
        ProcessId = processId;
        LowIntegrity = lowIntegrity;
        RestrictedToken = restrictedToken;
        Warning = warning;
        _job = job;
        _processHandle = processHandle;
        _threadHandle = threadHandle;
        _logHandle = logHandle;
        _fallbackProcess = fallbackProcess;
        StandardInput = stdin;
        StandardOutput = stdout;
    }

    public int ProcessId { get; }
    public bool LowIntegrity { get; }
    public bool RestrictedToken { get; }
    public string? Warning { get; }
    public Stream StandardInput { get; }
    public Stream StandardOutput { get; }

    public bool HasExited
    {
        get
        {
            if (_fallbackProcess is not null)
            {
                try
                {
                    return _fallbackProcess.HasExited;
                }
                catch
                {
                    return true;
                }
            }

            return AgentProcessLauncher.WaitForSingleObject(_processHandle, 0) == 0;
        }
    }

    public bool WaitForExit(int milliseconds)
    {
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

        return AgentProcessLauncher.WaitForSingleObject(_processHandle, (uint)Math.Max(0, milliseconds)) == 0;
    }

    public void Kill()
    {
        try
        {
            if (_job != IntPtr.Zero)
            {
                AgentProcessLauncher.TerminateJobObject(_job, 1);
            }
            else if (_fallbackProcess is not null)
            {
                _fallbackProcess.Kill(entireProcessTree: true);
            }
            else if (_processHandle != IntPtr.Zero)
            {
                AgentProcessLauncher.TerminateProcess(_processHandle, 1);
            }
        }
        catch
        {
            // Teardown is best effort.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            StandardInput.Dispose();
        }
        catch
        {
            // ignore
        }

        try
        {
            StandardOutput.Dispose();
        }
        catch
        {
            // ignore
        }

        _fallbackProcess?.Dispose();
        AgentProcessLauncher.SafeClose(_processHandle);
        AgentProcessLauncher.SafeClose(_threadHandle);
        AgentProcessLauncher.SafeClose(_logHandle);
        if (_job != IntPtr.Zero)
        {
            AgentProcessLauncher.SafeClose(_job);
        }
    }
}

public static class AgentProcessLauncher
{
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenDisableMaxPrivilege = 0x0001;
    private const uint SeGroupIntegrity = 0x00000020;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const int TokenIntegrityLevelClass = 25;

    private const int StartfUseShowWindow = 0x00000001;
    private const int StartfUseStdHandles = 0x00000100;
    private const uint CreateSuspended = 0x00000004;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x00000400;

    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenAlways = 4;
    private const uint FileAttributeNormal = 0x80;
    private const uint HandleFlagInherit = 0x00000001;

    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitProcessMemory = 0x00000100;
    private const uint JobObjectLimitJobMemory = 0x00000200;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const uint JobObjectUiLimitDesktop = 0x00000001;
    private const uint JobObjectUiLimitExitWindows = 0x00000008;
    private const int JobObjectBasicUiRestrictionsClass = 4;
    private const int JobObjectExtendedLimitInformationClass = 9;

    public static AgentLaunchedProcess? Start(AgentLaunchOptions options, out string error)
    {
        error = string.Empty;
        Directory.CreateDirectory(options.WorkingDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(options.LogPath) ?? options.WorkingDirectory);

        try
        {
            var launched = TryStartRestricted(options, out var nativeError);
            if (launched is not null)
            {
                return launched;
            }

            return TryStartFallback(options, nativeError, out error);
        }
        catch (Exception exception)
        {
            error = "启动 agent 进程失败：" + exception.Message;
            return null;
        }
    }

    private static AgentLaunchedProcess? TryStartRestricted(AgentLaunchOptions options, out string error)
    {
        error = string.Empty;
        var cleanup = new List<IntPtr>();
        var transferred = false;

        IntPtr baseToken = IntPtr.Zero, restrictedToken = IntPtr.Zero, lowSid = IntPtr.Zero, everyoneSid = IntPtr.Zero;
        IntPtr userSid = IntPtr.Zero, restrictArray = IntPtr.Zero, logHandle = IntPtr.Zero;
        IntPtr stdinRead = IntPtr.Zero, stdinWrite = IntPtr.Zero, stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero;
        IntPtr environment = IntPtr.Zero, job = IntPtr.Zero;
        IntPtr processHandle = IntPtr.Zero, threadHandle = IntPtr.Zero;
        Stream? stdinStream = null, stdoutStream = null;

        try
        {
            EnablePrivilege("SeAssignPrimaryTokenPrivilege");
            EnablePrivilege("SeIncreaseQuotaPrivilege");

            if (!OpenProcessToken(GetCurrentProcess(),
                    TokenDuplicate | TokenAssignPrimary | TokenQuery | TokenAdjustDefault | TokenAdjustSessionId,
                    out baseToken))
            {
                error = "OpenProcessToken 失败：" + LastError();
                return null;
            }

            cleanup.Add(baseToken);

            // Restrict to Everyone + Users so the child cannot exercise the LocalSystem
            // token's broader access even if it somehow reaches an IPC endpoint.
            if (!ConvertStringSidToSidW("S-1-1-0", out everyoneSid) ||
                !ConvertStringSidToSidW("S-1-5-32-545", out userSid))
            {
                error = "构造受限 SID 失败：" + LastError();
                return null;
            }

            cleanup.Add(everyoneSid);
            cleanup.Add(userSid);

            var sidArray = new[]
            {
                new SidAndAttributes { Sid = everyoneSid, Attributes = 0 },
                new SidAndAttributes { Sid = userSid, Attributes = 0 },
            };
            restrictArray = Marshal.AllocHGlobal(Marshal.SizeOf<SidAndAttributes>() * sidArray.Length);
            for (var i = 0; i < sidArray.Length; i++)
            {
                Marshal.StructureToPtr(sidArray[i], restrictArray + i * Marshal.SizeOf<SidAndAttributes>(), false);
            }

            if (!CreateRestrictedToken(baseToken, TokenDisableMaxPrivilege, 0, IntPtr.Zero,
                    (uint)sidArray.Length, restrictArray, 0, IntPtr.Zero, out restrictedToken))
            {
                error = "CreateRestrictedToken 失败：" + LastError();
                return null;
            }

            cleanup.Add(restrictedToken);

            if (!ConvertStringSidToSidW("S-1-16-4096", out lowSid))
            {
                error = "无法构造低完整性 SID：" + LastError();
                return null;
            }

            cleanup.Add(lowSid);
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

            var inheritAttributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                InheritHandle = 1
            };

            if (!CreatePipe(out stdinRead, out stdinWrite, ref inheritAttributes, 0) ||
                !CreatePipe(out stdoutRead, out stdoutWrite, ref inheritAttributes, 0))
            {
                error = "创建管道失败：" + LastError();
                return null;
            }

            // Parent ends must not leak into any other child.
            SetHandleInformation(stdinWrite, HandleFlagInherit, 0);
            SetHandleInformation(stdoutRead, HandleFlagInherit, 0);

            logHandle = CreateFileW(options.LogPath, GenericWrite,
                FileShareRead | FileShareWrite | FileShareDelete, ref inheritAttributes, OpenAlways,
                FileAttributeNormal, IntPtr.Zero);
            if (logHandle == new IntPtr(-1))
            {
                error = "创建 agent 日志文件失败：" + LastError();
                return null;
            }

            var startup = new StartupInfo
            {
                Size = Marshal.SizeOf<StartupInfo>(),
                Flags = StartfUseShowWindow | StartfUseStdHandles,
                ShowWindow = 0,
                StdInput = stdinRead,
                StdOutput = stdoutWrite,
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
                error = "创建作业对象失败：" + LastError();
                TerminateProcess(processHandle, 1);
                SafeClose(processHandle);
                SafeClose(threadHandle);
                SafeClose(job);
                return null;
            }

            if (!AssignProcessToJobObject(job, processHandle))
            {
                error = "将 agent 进程加入作业对象失败：" + LastError();
                TerminateProcess(processHandle, 1);
                SafeClose(processHandle);
                SafeClose(threadHandle);
                SafeClose(job);
                return null;
            }

            stdinStream = new FileStream(new SafeFileHandle(stdinWrite, ownsHandle: true), FileAccess.Write, 4096, false);
            stdoutStream = new FileStream(new SafeFileHandle(stdoutRead, ownsHandle: true), FileAccess.Read, 4096, false);
            ResumeThread(threadHandle);

            transferred = true;
            return new AgentLaunchedProcess(processInfo.ProcessId, true, true, null, job, processHandle,
                threadHandle, logHandle, stdinStream, stdoutStream, null);
        }
        catch (Exception exception)
        {
            error = exception.Message;
            if (processHandle != IntPtr.Zero)
            {
                TerminateProcess(processHandle, 1);
            }

            stdinStream?.Dispose();
            stdoutStream?.Dispose();
            SafeClose(threadHandle);
            SafeClose(processHandle);
            SafeClose(job);
            return null;
        }
        finally
        {
            if (!transferred)
            {
                SafeClose(stdinRead);
                SafeClose(stdinWrite);
                SafeClose(stdoutRead);
                SafeClose(stdoutWrite);
                SafeClose(logHandle);
            }
            else
            {
                // The child inherited these ends at CreateProcess time; the parent keeps
                // only stdinWrite/stdoutRead (owned by the FileStreams) and logHandle
                // (owned by the launched-process wrapper).
                SafeClose(stdinRead);
                SafeClose(stdoutWrite);
            }

            SafeClose(environment);
            if (restrictArray != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(restrictArray);
            }

            foreach (var handle in cleanup)
            {
                SafeClose(handle);
            }
        }
    }

    private static AgentLaunchedProcess? TryStartFallback(AgentLaunchOptions options, string nativeError, out string error)
    {
        error = string.Empty;
        Process? process = null;
        IntPtr job = IntPtr.Zero;
        try
        {
            var startInfo = new ProcessStartInfo(options.ExecutablePath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = options.WorkingDirectory,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var argument in options.Arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            startInfo.Environment["TMP"] = Path.Combine(options.WorkingDirectory, "tmp");
            startInfo.Environment["TEMP"] = Path.Combine(options.WorkingDirectory, "tmp");
            startInfo.Environment["PYTHONDONTWRITEBYTECODE"] = "1";
            startInfo.Environment["PYTHONNOUSERSITE"] = "1";
            startInfo.Environment["PYTHONUNBUFFERED"] = "1";

            process = Process.Start(startInfo);
            if (process is null)
            {
                error = "无法启动 agent 进程。";
                return null;
            }

            var log = new StreamWriter(new FileStream(options.LogPath, FileMode.Append, FileAccess.Write,
                FileShare.ReadWrite | FileShare.Delete)) { AutoFlush = true };
            log.WriteLine("[NDAS] 受限令牌不可用（" + nativeError + "），agent 以回退模式运行。");
            process.ErrorDataReceived += (_, args) =>
            {
                if (args.Data is not null)
                {
                    try
                    {
                        log.WriteLine(args.Data);
                    }
                    catch
                    {
                        // Logging is best effort.
                    }
                }
            };
            process.BeginErrorReadLine();

            var launched = new AgentLaunchedProcess(process.Id, false, false, nativeError, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, process.StandardInput.BaseStream,
                process.StandardOutput.BaseStream, process);

            try
            {
                job = CreateJobObjectW(IntPtr.Zero, null);
                if (job != IntPtr.Zero && ConfigureJob(job, options) &&
                    AssignProcessToJobObject(job, process.Handle))
                {
                    // Job closes with the process wrapper; kill-on-close still applies.
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
            error = "启动 agent 进程失败：" + exception.Message;
            try
            {
                process?.Kill(entireProcessTree: true);
                process?.Dispose();
            }
            catch
            {
                // Best effort.
            }

            SafeClose(job);
            return null;
        }
    }

    private static bool ConfigureJob(IntPtr job, AgentLaunchOptions options)
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

        variables["TMP"] = Path.Combine(workingDirectory, "tmp");
        variables["TEMP"] = Path.Combine(workingDirectory, "tmp");
        variables["PYTHONDONTWRITEBYTECODE"] = "1";
        variables["PYTHONNOUSERSITE"] = "1";
        variables["PYTHONUNBUFFERED"] = "1";
        variables["ONNXRUNTIME_LOG_SEVERITY_LEVEL"] = "3";

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
            // Missing privileges force the fallback launcher.
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe,
        ref SecurityAttributes securityAttributes, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

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
