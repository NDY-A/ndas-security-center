using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Text;
using Aegis.Core.Infrastructure;
using Microsoft.Win32;

namespace Aegis.Hips;

public sealed class HipsService : IDisposable
{
    private const int MaxEvents = 500;

    private static readonly HashSet<string> OfficeParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword", "excel", "powerpnt", "wps", "et", "wpp", "outlook", "acrobat", "acrord32",
        "chrome", "msedge", "firefox", "wechat", "qq", "dingtalk", "feishu", "teams", "onenote"
    };

    private static readonly HashSet<string> ScriptChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
        "certutil", "bitsadmin", "msbuild", "installutil", "wmic", "schtasks", "curl", "ieexec"
    };

    private static readonly HashSet<string> DangerousTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "mimikatz", "psexec", "procdump", "ncat", "nc", "rubeus", "sharphound", "lazagne",
        "cobaltstrike", "beacon", "winpeas", "seatbelt"
    };

    private static readonly HashSet<string> SensitiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url", ".reg", ".msi"
    };

    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt"
    };

    private static readonly (string Pattern, string Rule, string Title, HipsSeverity Severity)[] CommandRules =
    {
        ("vssadmin delete shadows", "HIPS.CMD.SHADOW_DELETE", "尝试删除卷影副本", HipsSeverity.Critical),
        ("wbadmin delete catalog", "HIPS.CMD.BACKUP_DELETE", "尝试删除备份目录", HipsSeverity.Critical),
        ("bcdedit /set", "HIPS.CMD.BOOT_EDIT", "尝试修改启动配置", HipsSeverity.Critical),
        ("wevtutil cl", "HIPS.CMD.LOG_CLEAR", "尝试清空事件日志", HipsSeverity.Critical),
        ("mshta http", "HIPS.CMD.MSHTA_REMOTE", "mshta 加载远程脚本", HipsSeverity.Critical),
        ("wmic process call create", "HIPS.CMD.WMIC_CREATE", "WMIC 创建进程", HipsSeverity.Critical),
        ("rundll32 javascript", "HIPS.CMD.RUNDLL32_JS", "rundll32 执行 JavaScript", HipsSeverity.Critical),
        ("regsvr32 /s /u /i:", "HIPS.CMD.REGSVR32_REMOTE", "regsvr32 远程脚本", HipsSeverity.Critical),
        (" -encodedcommand", "HIPS.CMD.PS_ENCODED", "PowerShell 编码命令", HipsSeverity.High),
        (" -enc ", "HIPS.CMD.PS_ENCODED", "PowerShell 编码命令", HipsSeverity.High),
        ("frombase64string", "HIPS.CMD.PS_BASE64", "PowerShell Base64 解码", HipsSeverity.High),
        ("downloadstring", "HIPS.CMD.PS_DOWNLOAD", "PowerShell 远程下载", HipsSeverity.High),
        ("invoke-expression", "HIPS.CMD.PS_IEX", "PowerShell 动态执行", HipsSeverity.High),
        ("iex(", "HIPS.CMD.PS_IEX", "PowerShell 动态执行", HipsSeverity.High),
        (" -windowstyle hidden", "HIPS.CMD.PS_HIDDEN", "PowerShell 隐藏窗口", HipsSeverity.Low),
        (" -w hidden", "HIPS.CMD.PS_HIDDEN", "PowerShell 隐藏窗口", HipsSeverity.Low),
        ("certutil -urlcache", "HIPS.CMD.CERTUTIL_DOWNLOAD", "certutil 下载载荷", HipsSeverity.High),
        ("bitsadmin /transfer", "HIPS.CMD.BITS_DOWNLOAD", "BITS 后台传输", HipsSeverity.High),
        ("schtasks /create", "HIPS.CMD.SCHTASK", "创建计划任务", HipsSeverity.High)
    };

    private readonly ConcurrentQueue<HipsEvent> _events = new();
    private readonly object _lifecycleLock = new();
    private readonly object _registryLock = new();
    private readonly object _fileLock = new();
    private HipsOptions? _options;
    private ManagementEventWatcher? _processWatcher;
    private FileSystemWatcher[] _fileWatchers = Array.Empty<FileSystemWatcher>();
    private System.Threading.Timer? _registryTimer;
    private CancellationTokenSource? _pollCancellation;
    private Task? _pollTask;
    private HashSet<int> _knownProcesses = new();
    private Dictionary<string, string?> _runSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private bool _runSnapshotInitialized;
    private volatile bool _blockCritical;
    private bool _disposed;

    public bool IsRunning { get; private set; }

    public string? LastError { get; private set; }

    public bool ProcessMonitoringActive { get; private set; }

    public bool FileMonitoringActive { get; private set; }

    public bool RegistryMonitoringActive { get; private set; }

    public int EventCount => _events.Count;

    public bool BlockCritical
    {
        get => _blockCritical;
        set => _blockCritical = value;
    }

    public void UpdateOptions(HipsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _blockCritical = options.BlockCritical;
    }

    public bool DetectInjection { get; set; } = true;

    public bool BlockInjection { get; set; }

    public bool BlockRegistry { get; set; }

    public event EventHandler<HipsEvent>? EventRaised;

    public event EventHandler<HipsProcessObservation>? ProcessObserved;

    public event EventHandler? StateChanged;

    public void ReportEvent(HipsEvent hipsEvent) => AddEvent(hipsEvent);

    public IReadOnlyList<HipsEvent> GetRecent(int limit = 200)
    {
        if (limit <= 0)
        {
            return Array.Empty<HipsEvent>();
        }

        return _events.ToArray().Reverse().Take(limit).ToArray();
    }

    public void Start(HipsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        lock (_lifecycleLock)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(HipsService));
            }

            if (IsRunning)
            {
                return;
            }

            _options = options;
            _blockCritical = options.BlockCritical;
            LastError = null;
            IsRunning = true;

            StartProcessMonitoring();
            StartFileMonitoring();
            StartRegistryMonitoring(options);
        }

        RaiseStateChanged();
    }

    public void Stop()
    {
        lock (_lifecycleLock)
        {
            if (!IsRunning)
            {
                return;
            }

            IsRunning = false;
            try
            {
                if (_processWatcher is not null)
                {
                    _processWatcher.EventArrived -= OnProcessArrived;
                    _processWatcher.Stop();
                    _processWatcher.Dispose();
                }
            }
            catch
            {
                // Best-effort teardown.
            }

            _processWatcher = null;

            foreach (var watcher in _fileWatchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch
                {
                    // Best-effort teardown.
                }
            }

            _fileWatchers = Array.Empty<FileSystemWatcher>();
            _registryTimer?.Dispose();
            _registryTimer = null;
            _pollCancellation?.Cancel();
            _pollCancellation?.Dispose();
            _pollCancellation = null;
            _pollTask = null;
            ProcessMonitoringActive = false;
            FileMonitoringActive = false;
            RegistryMonitoringActive = false;
        }

        RaiseStateChanged();
    }

    private void StartProcessMonitoring()
    {
        try
        {
            var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
            var watcher = new ManagementEventWatcher(query);
            watcher.EventArrived += OnProcessArrived;
            watcher.Start();
            _processWatcher = watcher;
            ProcessMonitoringActive = true;
        }
        catch (Exception exception)
        {
            AppendError("进程监控不可用（需要管理员权限或 WMI）：" + exception.Message);
            StartProcessPolling();
        }
    }

    private void StartProcessPolling()
    {
        try
        {
            _knownProcesses = new HashSet<int>(Process.GetProcesses().Select(process => process.Id));
            _pollCancellation = new CancellationTokenSource();
            _pollTask = Task.Run(() => PollProcessesAsync(_pollCancellation.Token));
            ProcessMonitoringActive = true;
        }
        catch (Exception exception)
        {
            AppendError("进程轮询启动失败：" + exception.Message);
        }
    }

    private async Task PollProcessesAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    using (process)
                    {
                        if (!_knownProcesses.Add(process.Id))
                        {
                            continue;
                        }

                        string? path = null;
                        try
                        {
                            path = process.MainModule?.FileName;
                        }
                        catch
                        {
                            // Access can be denied for protected processes.
                        }

                        EvaluateProcess(process.Id, process.ProcessName + ".exe", path, null, null);
                    }
                }
            }
            catch
            {
                // Polling failures are non-fatal.
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private void OnProcessArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var eventData = e.NewEvent;
            var pid = Convert.ToInt32(eventData["ProcessID"]);
            var parentPid = Convert.ToInt32(eventData["ParentProcessID"]);
            var name = Convert.ToString(eventData["ProcessName"]) ?? string.Empty;
            if (pid == Environment.ProcessId)
            {
                return;
            }

            var (path, commandLine, parentName) = QueryProcess(pid, parentPid);
            EvaluateProcess(pid, name, path, commandLine, parentName);
        }
        catch
        {
            // WMI event payloads vary; a malformed event must not stop the watcher.
        }
    }

    private static (string? Path, string? CommandLine, string? ParentName) QueryProcess(int pid, int parentPid)
    {
        string? path = null;
        string? commandLine = null;
        string? parentName = null;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId={pid}");
            foreach (ManagementObject item in searcher.Get())
            {
                path = item["ExecutablePath"] as string;
                commandLine = item["CommandLine"] as string;
                break;
            }
        }
        catch
        {
            // Process may have exited or access may be denied.
        }

        try
        {
            using var parent = new ManagementObjectSearcher(
                $"SELECT Name FROM Win32_Process WHERE ProcessId={parentPid}");
            foreach (ManagementObject item in parent.Get())
            {
                parentName = item["Name"] as string;
                break;
            }
        }
        catch
        {
            // Parent may have exited.
        }

        return (path, commandLine, parentName);
    }

    private void EvaluateProcess(int pid, string? childName, string? path, string? commandLine, string? parentName)
    {
        if (!IsRunning || IsSelfPath(path) || IsSelfName(childName))
        {
            return;
        }

        var child = NormalizeName(childName);
        var parent = NormalizeName(parentName);
        var command = commandLine ?? string.Empty;

        if (_options is not null &&
            _options.SelfExclusions.Any(exclusion => command.Contains(exclusion, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        try
        {
            ProcessObserved?.Invoke(this, new HipsProcessObservation(pid, childName, path, parentName, commandLine));
        }
        catch
        {
            // Subscriber failures must not affect HIPS.
        }

        if (DetectInjection)
        {
            _ = Task.Run(() => InspectModulesAsync(pid, path, commandLine));
        }

        if (DangerousTools.Contains(child))
        {
            AddProcessEvent(pid, "HIPS.PROC.TOOL", "检测到高风险工具进程",
                $"进程 {childName} 属于常见攻击工具。", HipsSeverity.Critical, path, commandLine);
            return;
        }

        foreach (var rule in CommandRules)
        {
            if (!command.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            AddProcessEvent(pid, rule.Rule, rule.Title, rule.Title + "。", rule.Severity, path, commandLine);
            return;
        }

        if (parent.Length > 0 && child.Length > 0 &&
            OfficeParents.Contains(parent) && ScriptChildren.Contains(child))
        {
            AddProcessEvent(pid, "HIPS.PROC.OFFICE_CHAIN", "文档/浏览器启动脚本解释器",
                $"{parentName} 启动了 {childName}，符合钓鱼投递链特征。", HipsSeverity.High, path, commandLine);
            return;
        }

        if (child.Length > 0 && ScriptChildren.Contains(child) && IsUserWritablePath(path) &&
            parent.Length > 0 && OfficeParents.Contains(parent))
        {
            AddProcessEvent(pid, "HIPS.PROC.USER_CHAIN", "用户目录加载脚本解释器",
                $"{parentName} 从用户目录启动了 {childName}。", HipsSeverity.High, path, commandLine);
        }
    }

    private void AddProcessEvent(int pid, string ruleId, string title, string detail,
        HipsSeverity severity, string? path, string? commandLine)
    {
        var blocked = false;
        if (_blockCritical && severity == HipsSeverity.Critical && TryTerminate(pid, path))
        {
            blocked = true;
            detail += " 已终止进程。";
        }

        AddEvent(new HipsEvent(DateTimeOffset.Now, ruleId, title, detail, severity, path, commandLine,
            pid.ToString(), blocked));
    }

    private bool TryTerminate(int pid, string? path)
    {
        if (pid <= 4 || pid == Environment.ProcessId || IsSelfPath(path))
        {
            return false;
        }

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (path is { Length: > 0 } && windows.Length > 0 &&
            path.StartsWith(windows, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task InspectModulesAsync(int pid, string? processPath, string? commandLine)
    {
        try
        {
            await Task.Delay(500).ConfigureAwait(false);
            using var process = Process.GetProcessById(pid);
            foreach (ProcessModule module in process.Modules)
            {
                string? modulePath = null;
                try
                {
                    modulePath = module.FileName;
                }
                catch
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(modulePath) ||
                    !modulePath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                    !IsUserWritablePath(modulePath) ||
                    IsSelfPath(modulePath))
                {
                    continue;
                }

                var blocked = false;
                if (BlockInjection)
                {
                    blocked = TryTerminate(pid, processPath);
                }

                AddEvent(new HipsEvent(DateTimeOffset.Now, "HIPS.PROC.MODULE", "可疑模块注入/侧载",
                    $"进程 {process.ProcessName} 加载了用户目录 DLL：{modulePath}",
                    HipsSeverity.Critical, processPath, commandLine, modulePath, blocked));
                break;
            }
        }
        catch
        {
            // Protected processes and short-lived processes cannot be inspected.
        }
    }

    private void StartFileMonitoring()
    {
        var targets = new List<(string Path, bool Startup)>
        {
            (GetKnownFolder(Environment.SpecialFolder.DesktopDirectory,
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Desktop"), false),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"), false),
            (Path.GetTempPath(), false),
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), true),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), true)
        };

        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(30)))
        {
            if (!string.IsNullOrWhiteSpace(profile.Desktop))
            {
                targets.Add((profile.Desktop, false));
            }

            if (!string.IsNullOrWhiteSpace(profile.Downloads))
            {
                targets.Add((profile.Downloads, false));
            }

            targets.Add((Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft", "Windows",
                "Start Menu", "Programs", "Startup"), true));
        }

        var watchers = new List<FileSystemWatcher>();
        foreach (var (path, startup) in targets.DistinctBy(target => target.Path))
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
            {
                continue;
            }

            try
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    EnableRaisingEvents = true
                };
                watcher.Created += (_, args) => OnFileCreated(args.FullPath, path, startup);
                watchers.Add(watcher);
            }
            catch (Exception exception)
            {
                AppendError($"无法监控 {path}：{exception.Message}");
            }
        }

        _fileWatchers = watchers.ToArray();
        FileMonitoringActive = _fileWatchers.Length > 0;
    }

    private void OnFileCreated(string path, string watchedRoot, bool startup)
    {
        if (!IsRunning || IsSelfPath(path))
        {
            return;
        }

        var fileName = Path.GetFileName(path);
        if (fileName.StartsWith("__PSScriptPolicyTest_", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var extension = Path.GetExtension(path);
        if (extension.Length == 0 || !SensitiveExtensions.Contains(extension))
        {
            return;
        }

        var innerExtension = Path.GetExtension(Path.GetFileNameWithoutExtension(path));
        var doubleExtension = innerExtension.Length > 0 && DocumentExtensions.Contains(innerExtension);
        var severity = startup || doubleExtension
            ? HipsSeverity.Critical
            : extension is ".ps1" or ".psm1" or ".vbs" or ".vbe" or ".js" or ".jse" or ".hta" or ".wsf" or ".wsh"
                ? HipsSeverity.High
                : HipsSeverity.Medium;

        var detail = startup
            ? $"启动目录中创建了 {extension} 文件。"
            : doubleExtension
                ? $"检测到双扩展名可执行文件 {extension}。"
                : $"在 {watchedRoot} 中创建了 {extension} 文件。";
        AddEvent(new HipsEvent(DateTimeOffset.Now, "HIPS.FILE.CREATE", "敏感文件落盘",
            detail, severity, null, null, path));
    }

    private void StartRegistryMonitoring(HipsOptions options)
    {
        try
        {
            lock (_registryLock)
            {
                _runSnapshot = ReadRunValues();
                _runSnapshotInitialized = true;
            }

            _registryTimer = new System.Threading.Timer(_ => PollRegistry(), null,
                TimeSpan.Zero, options.RegistryPollInterval);
            RegistryMonitoringActive = true;
        }
        catch (Exception exception)
        {
            AppendError("注册表监控启动失败：" + exception.Message);
        }
    }

    private void PollRegistry()
    {
        if (!IsRunning)
        {
            return;
        }

        try
        {
            var current = ReadRunValues();
            lock (_registryLock)
            {
                if (!_runSnapshotInitialized)
                {
                    _runSnapshot = current;
                    _runSnapshotInitialized = true;
                    return;
                }

                foreach (var pair in current)
                {
                    if (_runSnapshot.TryGetValue(pair.Key, out var previous) &&
                        string.Equals(previous, pair.Value, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    if (pair.Value is { Length: > 0 } value && !IsSelfText(value))
                    {
                        var suspicious = value.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("mshta", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("rundll32", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("https://", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("\\appdata\\", StringComparison.OrdinalIgnoreCase);
                        var blocked = suspicious && BlockRegistry && TryRemoveRunValue(pair.Key);
                        AddEvent(new HipsEvent(DateTimeOffset.Now, "HIPS.REG.RUN",
                            suspicious ? "可疑自启动项变更" : "自启动项变更",
                            $"注册表 {pair.Key} 被设置为：{value}" + (blocked ? "，已回滚。" : string.Empty),
                            suspicious ? HipsSeverity.Critical : HipsSeverity.High,
                            null, null, pair.Key, blocked));
                    }
                }

                _runSnapshot = current;
            }
        }
        catch
        {
            // Registry access can race with uninstallers; ignore transient failures.
        }
    }

    private static bool TryRemoveRunValue(string compositeKey)
    {
        var first = compositeKey.IndexOf('\\');
        var last = compositeKey.LastIndexOf('\\');
        if (first <= 0 || last <= first)
        {
            return false;
        }

        var hiveText = compositeKey[..first];
        var subKey = compositeKey[(first + 1)..last];
        var valueName = compositeKey[(last + 1)..];
        if (!Enum.TryParse<RegistryHive>(hiveText, out var hive))
        {
            return false;
        }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var key = baseKey.OpenSubKey(subKey, writable: true);
            if (key is null)
            {
                return false;
            }

            key.DeleteValue(valueName, throwOnMissingValue: false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static Dictionary<string, string?> ReadRunValues()
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var locations = new List<(RegistryHive Hive, string SubKey)>
        {
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")
        };

        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(30)))
        {
            locations.Add((RegistryHive.Users, profile.Sid + @"\Software\Microsoft\Windows\CurrentVersion\Run"));
            locations.Add((RegistryHive.Users, profile.Sid + @"\Software\Microsoft\Windows\CurrentVersion\RunOnce"));
        }

        foreach (var (hive, subKey) in locations)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(subKey);
                if (key is null)
                {
                    continue;
                }

                foreach (var name in key.GetValueNames())
                {
                    var value = key.GetValue(name)?.ToString();
                    values[$"{hive}\\{subKey}\\{name}"] = value;
                }
            }
            catch
            {
                // Access to some machine hives can be denied.
            }
        }

        return values;
    }

    private static string GetKnownFolder(Environment.SpecialFolder fallback, string registryPath, string valueName)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(registryPath);
            if (key?.GetValue(valueName) is string configured && configured.Length > 0)
            {
                var expanded = Environment.ExpandEnvironmentVariables(configured);
                if (Directory.Exists(expanded))
                {
                    return expanded;
                }
            }
        }
        catch
        {
            // Fall back to the shell folder.
        }

        return Environment.GetFolderPath(fallback);
    }

    private bool IsUserWritablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var desktop = GetKnownFolder(Environment.SpecialFolder.DesktopDirectory,
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Desktop");
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var temp = Path.GetTempPath();
        if (IsUnder(path, desktop) || IsUnder(path, downloads) || IsUnder(path, temp) ||
            path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(30)))
        {
            if ((profile.Desktop is { } userDesktop && IsUnder(path, userDesktop)) ||
                (profile.Downloads is { } userDownloads && IsUnder(path, userDownloads)) ||
                IsUnder(path, Path.Combine(profile.ProfilePath, "AppData", "Local", "Temp")))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsUnder(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var root = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsSelfPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        if (_options is not null)
        {
            foreach (var exclusion in _options.SelfExclusions)
            {
                if (IsUnder(path, exclusion) || string.Equals(path, exclusion, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        return IsSelfName(Path.GetFileName(path));
    }

    private static bool IsSelfName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        return name.Equals("NDAS.exe", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("NDAS.dll", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Aegis.exe", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Aegis.dll", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Aegis.Agent.dll", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Aegis.Hips.dll", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("NDASService.exe", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Aegis.Service.dll", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsSelfText(string text)
    {
        if (_options is null)
        {
            return false;
        }

        foreach (var exclusion in _options.SelfExclusions)
        {
            if (text.Contains(exclusion, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return text.Contains("NDAS.exe", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("NDAS.Agent", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("Aegis.exe", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("Aegis.Agent", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        var fileName = Path.GetFileName(name.Trim());
        return Path.GetFileNameWithoutExtension(fileName).ToLowerInvariant();
    }

    private void AddEvent(HipsEvent hipsEvent)
    {
        _events.Enqueue(hipsEvent);
        while (_events.Count > MaxEvents && _events.TryDequeue(out _))
        {
            // Ring buffer: keep the newest events.
        }

        try
        {
            if (_options?.LogPath is { Length: > 0 } logPath)
            {
                var directory = Path.GetDirectoryName(logPath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var extra = new StringBuilder();
                if (!string.IsNullOrWhiteSpace(hipsEvent.ProcessPath))
                {
                    extra.Append("\tproc=").Append(Sanitize(hipsEvent.ProcessPath));
                }

                if (!string.IsNullOrWhiteSpace(hipsEvent.Target))
                {
                    extra.Append("\ttarget=").Append(Sanitize(hipsEvent.Target));
                }

                var line = $"{hipsEvent.Timestamp:O}\t{hipsEvent.Severity}\t{hipsEvent.RuleId}\t" +
                           $"{Sanitize(hipsEvent.Title)}\t{Sanitize(hipsEvent.Detail)}" +
                           $"{(hipsEvent.Blocked ? "\tblocked" : string.Empty)}{extra}{Environment.NewLine}";
                File.AppendAllText(logPath, line, Encoding.UTF8);
            }
        }
        catch
        {
            // Audit logging is best-effort; never break monitoring.
        }

        try
        {
            EventRaised?.Invoke(this, hipsEvent);
        }
        catch
        {
            // UI subscribers must not destabilize HIPS.
        }
    }

    private void AppendError(string message)
    {
        LastError = string.IsNullOrWhiteSpace(LastError) ? message : LastError + " | " + message;
    }

    private static string Sanitize(string value) =>
        value.Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');

    private void RaiseStateChanged()
    {
        try
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            // UI subscribers must not destabilize HIPS.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        Stop();
    }
}
