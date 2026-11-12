using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;
using Aegis.Core.Network;
using Aegis.Core.Remediation;
using Aegis.Core.Scanning;
using Aegis.Core.Service;
using Aegis.Core.Signatures;
using Aegis.Hips;
using Aegis.Sandbox;

namespace Aegis.Service;

public sealed class ProtectionHost : IDisposable
{
    private readonly CancellationTokenSource _cancellation = new();
    private readonly object _scannerLock = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentScans = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _threatLock = new();
    private readonly string? _explicitSeed;
    private ServiceThreatIncident? _activeThreat;
    private ServiceSettings _settings = new();
    private SignatureSnapshot? _snapshot;
    private AegisScanner? _scanner;
    private ScanOptions _scanOptions = ScanOptions.Default;
    private IReadOnlyList<string> _exclusions = Array.Empty<string>();
    private HipsService? _hips;
    private FileBlocker? _blocker;
    private NetworkIocBlocker? _networkBlocker;
    private RealtimeFileMonitor? _fileMonitor;
    private SpecialPathProbe? _specialPathProbe;
    private IdleScanService? _idleScan;
    private ContainmentService? _containment;
    private SandboxCoordinator? _sandbox;
    private Channel<ScanWorkItem>? _queue;
    private Task? _workers;
    private IpcServer? _ipc;
    private Timer? _signatureTimer;
    private long _scannedFiles;
    private long _threatsFound;
    private string? _lastError;
    private bool _disposed;

    public ProtectionHost(string? explicitSeed = null)
    {
        _explicitSeed = explicitSeed;
    }

    public async Task StartAsync()
    {
        Directory.CreateDirectory(ServicePaths.DataRoot);
        Directory.CreateDirectory(ServicePaths.LogsRoot);
        _blocker = new FileBlocker(ServicePaths.DataRoot);
        _settings = ServiceSettings.Load(ServicePaths.SettingsFile);
        _networkBlocker = new NetworkIocBlocker(ServicePaths.DataRoot);
        try
        {
            _networkBlocker.Restore(_settings.FirewallAutoBlockEnabled);
        }
        catch (Exception exception)
        {
            _lastError = "网络 IOC 封禁初始化失败：" + exception.Message;
        }

        _exclusions = BuildExclusions();
        _scanOptions = new ScanOptions
        {
            MaxFileSizeBytes = 512L * 1024 * 1024,
            MaxDegreeOfParallelism = 1,
            RunHeuristics = true,
            QueryCloud = false,
            CloudPolicy = CloudQueryPolicy.Never,
            UseDefaultExclusions = true,
            UserExclusions = _exclusions,
            AllowedHashes = Array.Empty<string>(),
            IncludeHiddenFiles = false
        };

        await LoadSignaturesAsync(_cancellation.Token).ConfigureAwait(false);

        _queue = Channel.CreateBounded<ScanWorkItem>(new BoundedChannelOptions(1024)
        {
            SingleReader = false,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropWrite
        });

        _hips = new HipsService();
        _hips.ProcessObserved += OnProcessObserved;
        _hips.EventRaised += OnHipsEventForThreat;
        ApplyHipsState();

        _containment = new ContainmentService(
            ScanForContainmentAsync,
            (path, reason) => _blocker?.Block(path, reason),
            _exclusions,
            hipsEvent => _hips?.ReportEvent(hipsEvent));

        _sandbox = new SandboxCoordinator(
            Path.Combine(ServicePaths.DataRoot, "Sandbox"),
            () => Volatile.Read(ref _snapshot),
            BuildSandboxOptions,
            LockFileFromSandbox,
            BlockNetworkFromSandbox,
            (pid, path, threat, source, score) => RecordActiveThreat(pid, path, threat, source, score),
            hipsEvent => _hips?.ReportEvent(hipsEvent),
            () => _exclusions);
        _sandbox.Start();

        _fileMonitor = new RealtimeFileMonitor(path => Enqueue(path, null));

        _specialPathProbe = new SpecialPathProbe(OnSpecialPathHit);
        _specialPathProbe.Update(Volatile.Read(ref _snapshot)?.SpecialPaths ?? SpecialPathMatcher.Empty);
        _specialPathProbe.Start();

        _idleScan = new IdleScanService(
            IdleScanService.DefaultTargets,
            ScanIdleFileAsync,
            () => _settings.IdleScanEnabled,
            () => _settings.IdleScanIdleMinutes,
            () => _exclusions);

        _workers = Task.WhenAll(
            Task.Run(() => ScanLoopAsync(_cancellation.Token), CancellationToken.None),
            Task.Run(() => ScanLoopAsync(_cancellation.Token), CancellationToken.None));

        _signatureTimer = new Timer(_ => _ = ReloadSignaturesAsync(), null, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(10));
        _ipc = new IpcServer(this);
        _ = _ipc.StartAsync(_cancellation.Token);
    }

    public async Task StopAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cancellation.Cancel();
        _sandbox?.Dispose();
        _sandbox = null;
        _containment?.Dispose();
        _containment = null;
        if (_hips is not null)
        {
            _hips.EventRaised -= OnHipsEventForThreat;
        }

        _specialPathProbe?.Dispose();
        _specialPathProbe = null;
        _idleScan?.Dispose();
        _idleScan = null;
        _fileMonitor?.Dispose();
        _fileMonitor = null;
        _signatureTimer?.Dispose();
        _signatureTimer = null;
        _queue?.Writer.TryComplete();

        if (_workers is not null)
        {
            try
            {
                await Task.WhenAny(_workers, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
            }
            catch
            {
                // Shutdown is best-effort.
            }
        }

        try
        {
            _hips?.Stop();
        }
        catch
        {
            // Best-effort teardown.
        }

        _hips?.Dispose();
        _hips = null;
        _blocker?.Dispose();
        _blocker = null;
        _cancellation.Dispose();
    }

    public ServiceStatus GetStatus()
    {
        var recent = _hips?.GetRecent(100).Select(MapEvent).ToList() ?? new List<ServiceEvent>();
        var snapshot = Volatile.Read(ref _snapshot);
        var sandbox = _sandbox?.GetStatus();
        return new ServiceStatus
        {
            ServiceRunning = !_disposed,
            HipsRunning = _hips?.IsRunning == true,
            HipsEnabled = _settings.HipsEnabled,
            ProcessMonitoringActive = _hips?.ProcessMonitoringActive == true,
            FileMonitoringActive = _hips?.FileMonitoringActive == true || _fileMonitor is not null,
            RegistryMonitoringActive = _hips?.RegistryMonitoringActive == true,
            RealtimeProtectionEnabled = _settings.RealtimeProtectionEnabled,
            ScanActiveProcesses = _settings.ScanActiveProcesses,
            BlockInjection = _settings.BlockInjection,
            BlockRegistry = _settings.BlockRegistry,
            BlockCritical = _settings.BlockCritical,
            IdleScanEnabled = _settings.IdleScanEnabled,
            IdleScanIdleMinutes = _settings.IdleScanIdleMinutes,
            IdleScanActive = _idleScan?.IsScanning == true,
            LastIdleScanAt = _idleScan?.LastScanAt,
            LastIdleScanFiles = _idleScan?.LastScanFiles ?? 0,
            LastIdleScanThreats = _idleScan?.LastScanThreats ?? 0,
            AutoTerminateProcesses = _settings.AutoTerminateProcesses,
            AutoDeleteMaliciousP7b = _settings.AutoDeleteMaliciousP7b,
            FirewallAutoBlockEnabled = _settings.FirewallAutoBlockEnabled,
            FirewallBlockedDomains = _networkBlocker?.DomainCount ?? 0,
            FirewallBlockedIps = _networkBlocker?.IpCount ?? 0,
            FirewallLastError = _networkBlocker?.LastError,
            SandboxSupported = sandbox?.Supported ?? false,
            SandboxAvailable = sandbox?.Available ?? false,
            SandboxEnabled = _settings.SandboxEnabled,
            SandboxAutoRemediate = _settings.SandboxAutoRemediate,
            SandboxEngineVersion = sandbox?.EngineVersion,
            SandboxQueueDepth = sandbox?.QueueDepth ?? 0,
            SandboxAnalyzing = sandbox?.Analyzing ?? false,
            SandboxAnalyzed = sandbox?.Analyzed ?? 0,
            SandboxMalicious = sandbox?.Malicious ?? 0,
            SandboxLastVerdict = sandbox?.LastVerdict,
            SandboxLastPath = sandbox?.LastPath,
            SandboxLastScore = sandbox?.LastScore ?? 0,
            SandboxLastAt = sandbox?.LastAt,
            SandboxLastError = sandbox?.LastError,
            LastError = _hips?.LastError ?? _lastError,
            EventCount = _hips?.EventCount ?? 0,
            ScannedFiles = Interlocked.Read(ref _scannedFiles),
            ThreatsFound = Interlocked.Read(ref _threatsFound),
            SignatureVersion = snapshot?.Version,
            YaraRuleCount = snapshot?.YaraRuleCount ?? 0,
            UpdatedAt = DateTimeOffset.UtcNow,
            RecentEvents = recent,
            WatchedPaths = _fileMonitor?.WatchedPaths.ToList() ?? new List<string>(),
            WatchErrors = _fileMonitor?.Errors.ToList() ?? new List<string>(),
            Profiles = UserProfileResolver.GetCached(TimeSpan.FromSeconds(20))
                .Select(profile => new ServiceUserProfile
                {
                    Sid = profile.Sid,
                    ProfilePath = profile.ProfilePath,
                    Desktop = profile.Desktop,
                    Downloads = profile.Downloads
                })
                .ToList(),
            BlockedFiles = _blocker?.Snapshot().ToList() ?? new List<ServiceBlockedFile>(),
            ActiveThreat = GetActiveThreat(),
            Containment = _containment?.GetStatus()
        };
    }

    private ServiceThreatIncident? GetActiveThreat()
    {
        lock (_threatLock)
        {
            if (_activeThreat is null)
            {
                return null;
            }

            return new ServiceThreatIncident
            {
                IncidentId = _activeThreat.IncidentId,
                DetectedAt = _activeThreat.DetectedAt,
                ProcessId = _activeThreat.ProcessId,
                ProcessName = _activeThreat.ProcessName,
                ProcessPath = _activeThreat.ProcessPath,
                ThreatName = _activeThreat.ThreatName,
                Evidence = _activeThreat.Evidence,
                Source = _activeThreat.Source,
                ProcessStillRunning = IsProcessRunningFrom(_activeThreat.ProcessId, _activeThreat.ProcessPath)
            };
        }
    }

    public bool StartContainment(int clientSessionId, out string error)
    {
        var incident = GetActiveThreat();
        if (incident is null || !incident.ProcessStillRunning)
        {
            error = "当前没有正在运行的活动恶意软件，已拒绝启动强力清除。";
            return false;
        }

        if (_containment is null)
        {
            error = "强力清除组件未初始化。";
            return false;
        }

        return _containment.Start(incident, clientSessionId, out error);
    }

    public bool AbortContainment(out string message)
    {
        if (_containment is null)
        {
            message = "强力清除组件未初始化。";
            return false;
        }

        return _containment.Abort(out message);
    }

    public ServiceBlockedFile? Block(string path, string reason = "manual") => _blocker?.Block(path, reason);

    public bool Unblock(string path) => _blocker?.Unblock(path) ?? false;

    public ServiceStatus ApplyConfiguration(ServiceConfiguration configuration)
    {
        _settings.Apply(configuration);
        try
        {
            _settings.Save(ServicePaths.SettingsFile);
        }
        catch (Exception exception)
        {
            _lastError = "保存服务设置失败：" + exception.Message;
        }

        ApplyHipsState();
        ApplyNetworkBlockState();
        return GetStatus();
    }

    private void ApplyNetworkBlockState()
    {
        try
        {
            _networkBlocker?.Restore(_settings.FirewallAutoBlockEnabled);
        }
        catch (Exception exception)
        {
            _lastError = "应用网络 IOC 封禁设置失败：" + exception.Message;
        }
    }

    private void ApplyHipsState()
    {
        if (_hips is null)
        {
            return;
        }

        try
        {
            var options = new HipsOptions
            {
                BlockCritical = _settings.BlockCritical,
                SelfExclusions = _exclusions,
                LogPath = Path.Combine(ServicePaths.LogsRoot, "hips.log")
            };

            _hips.DetectInjection = _settings.RealtimeProtectionEnabled;
            _hips.BlockInjection = _settings.BlockInjection;
            _hips.BlockRegistry = _settings.BlockRegistry;

            if (_settings.HipsEnabled)
            {
                if (_hips.IsRunning)
                {
                    _hips.UpdateOptions(options);
                }
                else
                {
                    _hips.Start(options);
                }
            }
            else if (_hips.IsRunning)
            {
                _hips.Stop();
            }
        }
        catch (Exception exception)
        {
            _lastError = "HIPS 启动失败：" + exception.Message;
        }
    }

    private void OnProcessObserved(object? sender, HipsProcessObservation observation)
    {
        if (!_settings.RealtimeProtectionEnabled || !_settings.ScanActiveProcesses)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(observation.ProcessPath))
        {
            DateTime? started = null;
            try
            {
                using var process = Process.GetProcessById(observation.ProcessId);
                started = process.StartTime;
            }
            catch
            {
                // Protected or already exited processes keep an unknown start time.
            }

            Enqueue(observation.ProcessPath, observation.ProcessId, started);
        }
    }

    private void OnHipsEventForThreat(object? sender, HipsEvent hipsEvent)
    {
        if (_disposed || hipsEvent.Severity < HipsSeverity.Critical)
        {
            return;
        }

        if (hipsEvent.RuleId is not ("HIPS.PROC.TOOL" or "HIPS.PROC.MODULE") ||
            string.IsNullOrWhiteSpace(hipsEvent.ProcessPath))
        {
            return;
        }

        int pid;
        if (hipsEvent.RuleId == "HIPS.PROC.MODULE")
        {
            pid = FindProcessIdByImage(hipsEvent.ProcessPath);
        }
        else if (!int.TryParse(hipsEvent.Target, out pid))
        {
            return;
        }

        if (pid > 0)
        {
            RecordActiveThreat(pid, hipsEvent.ProcessPath, hipsEvent.Title, hipsEvent.RuleId, 0);
        }
    }

    private void RecordActiveThreat(int pid, string path, string threatName, string source, int score)
    {
        if (!IsProcessRunningFrom(pid, path))
        {
            return;
        }

        lock (_threatLock)
        {
            if (_activeThreat is not null &&
                _activeThreat.ProcessId == pid &&
                string.Equals(_activeThreat.ProcessPath, path, StringComparison.OrdinalIgnoreCase))
            {
                _activeThreat.ThreatName = threatName;
                _activeThreat.Evidence = score > 0
                    ? $"{source} 判定为恶意（评分 {score}），进程正在运行"
                    : $"{source} 命中高危规则，进程正在运行";
                return;
            }

            _activeThreat = new ServiceThreatIncident
            {
                IncidentId = $"{pid}-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}",
                DetectedAt = DateTimeOffset.Now,
                ProcessId = pid,
                ProcessName = Path.GetFileNameWithoutExtension(path),
                ProcessPath = path,
                ThreatName = threatName,
                Evidence = score > 0
                    ? $"{source} 判定为恶意（评分 {score}），进程正在运行"
                    : $"{source} 命中高危规则，进程正在运行",
                Source = source,
                ProcessStillRunning = true
            };
        }
    }

    private static bool IsProcessRunningFrom(int pid, string path)
    {
        if (pid <= 0 || string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            var image = process.MainModule?.FileName;
            return !string.IsNullOrWhiteSpace(image) &&
                   string.Equals(Path.GetFullPath(image), Path.GetFullPath(path),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static int FindProcessIdByImage(string path)
    {
        try
        {
            var target = Path.GetFullPath(path);
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    try
                    {
                        var image = process.MainModule?.FileName;
                        if (!string.IsNullOrWhiteSpace(image) &&
                            string.Equals(Path.GetFullPath(image), target, StringComparison.OrdinalIgnoreCase))
                        {
                            return process.Id;
                        }
                    }
                    catch
                    {
                        // Protected processes deny module access.
                    }
                }
            }
        }
        catch
        {
            // Enumeration is best-effort.
        }

        return -1;
    }

    private async Task<FileScanResult?> ScanForContainmentAsync(string path, CancellationToken cancellationToken)
    {
        var scanner = Volatile.Read(ref _scanner);
        if (scanner is null)
        {
            return null;
        }

        try
        {
            return await scanner.ScanFileAsync(path, _scanOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private void OnSpecialPathHit(SpecialPathEntry entry, bool isDirectory)
    {
        if (_disposed)
        {
            return;
        }

        var label = string.IsNullOrWhiteSpace(entry.Label) ? "已知恶意路径" : entry.Label;
        var detail = isDirectory
            ? $"特殊检察命中：{label}（该路径为目录，疑似占位或伪装）"
            : $"特殊检察命中：{label}";
        if (!string.IsNullOrWhiteSpace(entry.Comment))
        {
            detail += "。" + entry.Comment;
        }

        if (!isDirectory && entry.Path.EndsWith(".p7b", StringComparison.OrdinalIgnoreCase))
        {
            _blocker?.Unblock(entry.Path);
            var inspection = P7bRemediator.Inspect(entry.Path);
            if (inspection.Verdict == P7bPolicyVerdict.Trusted)
            {
                _hips?.ReportEvent(new HipsEvent(
                    DateTimeOffset.Now,
                    "HIPS.IOC.P7B_TRUSTED",
                    "p7b 策略签名可信",
                    $"特殊路径发现 p7b 文件，但{inspection.Detail}，已跳过封锁与删除。",
                    HipsSeverity.Medium,
                    null,
                    null,
                    entry.Path,
                    false));
                return;
            }

            if (_settings.AutoDeleteMaliciousP7b)
            {
                var deleted = P7bRemediator.TryBackupAndDelete(entry.Path, ServicePaths.DataRoot, out var outcome);
                _hips?.ReportEvent(new HipsEvent(
                    DateTimeOffset.Now,
                    "HIPS.IOC.P7B_DELETED",
                    deleted ? "已删除恶意 p7b 策略" : "未能删除恶意 p7b 策略",
                    outcome,
                    HipsSeverity.Critical,
                    null,
                    null,
                    entry.Path,
                    deleted));
                if (deleted)
                {
                    return;
                }
            }
        }

        _hips?.ReportEvent(new HipsEvent(
            DateTimeOffset.Now,
            "HIPS.IOC.SPECIAL_PATH",
            "特殊路径命中",
            detail,
            HipsSeverity.Critical,
            null,
            null,
            entry.Path,
            false));

        if (!isDirectory && _settings.RealtimeProtectionEnabled)
        {
            EnqueueSpecialPath(entry.Path);
        }
    }

    private void EnqueueSpecialPath(string path)
    {
        if (_disposed || string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (_recentScans.TryGetValue(path, out var last) && now - last < TimeSpan.FromMinutes(2))
        {
            return;
        }

        _recentScans[path] = now;
        _queue?.Writer.TryWrite(new ScanWorkItem(path, null, null));
    }

    private void Enqueue(string path, int? processId, DateTime? processStartTime = null)
    {
        if (_disposed || !_settings.RealtimeProtectionEnabled || string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        if (!ShouldScan(path))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (_recentScans.TryGetValue(path, out var last) && now - last < TimeSpan.FromMinutes(2))
        {
            return;
        }

        _recentScans[path] = now;
        _queue?.Writer.TryWrite(new ScanWorkItem(path, processId, processStartTime));
    }

    private bool ShouldScan(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            foreach (var exclusion in _exclusions)
            {
                if (!string.IsNullOrWhiteSpace(exclusion) && IsUnder(path, exclusion))
                {
                    return false;
                }
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task ScanLoopAsync(CancellationToken cancellationToken)
    {
        var queue = _queue;
        if (queue is null)
        {
            return;
        }

        try
        {
            await foreach (var item in queue.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                await AnalyzeAndHandleAsync(item.Path, item.ProcessId, item.ProcessStartTime,
                        "HIPS.REALTIME.SCAN", cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    private async Task<bool> ScanIdleFileAsync(string path, CancellationToken cancellationToken)
    {
        var systemSoftware = IsSystemSoftwarePath(path);
        var result = await AnalyzeAndHandleAsync(path, null, null, "HIPS.IDLE.SCAN", cancellationToken,
                systemSoftware)
            .ConfigureAwait(false);
        if (result?.Verdict is not (ThreatVerdict.Malicious or ThreatVerdict.Pua))
        {
            return false;
        }

        return !systemSoftware || HasDecisiveEvidence(result);
    }

    private async Task<FileScanResult?> AnalyzeAndHandleAsync(string path, int? processId,
        DateTime? processStartTime, string ruleId, CancellationToken cancellationToken,
        bool requireDecisiveEvidence = false)
    {
        if (!await WaitForStableAsync(path, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var scanner = Volatile.Read(ref _scanner);
        if (scanner is null)
        {
            return null;
        }

        try
        {
            var result = await scanner.ScanFileAsync(path, _scanOptions, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _scannedFiles);
            try
            {
                _sandbox?.MaybeSubmit(result, processId, processStartTime, ruleId, requireDecisiveEvidence);
            }
            catch
            {
                // Sandbox submission is best-effort and must not break scanning.
            }

            if (result.Verdict is not (ThreatVerdict.Malicious or ThreatVerdict.Pua))
            {
                return result;
            }

            if (requireDecisiveEvidence && !HasDecisiveEvidence(result))
            {
                return result;
            }

            Interlocked.Increment(ref _threatsFound);
            var networkBlocked = 0;
            if (result.Verdict == ThreatVerdict.Malicious &&
                _settings.FirewallAutoBlockEnabled &&
                _networkBlocker is not null &&
                result.NetworkIndicators.Count > 0)
            {
                var change = _networkBlocker.Apply(result.NetworkIndicators);
                networkBlocked = change.TotalAdded;
            }

            var locked = false;
            if (_blocker is not null && result.Verdict == ThreatVerdict.Malicious)
            {
                var entry = _blocker.Block(path, result.ThreatName ?? result.VerdictText);
                locked = entry.AclApplied || entry.HandleHeld;
            }

            var terminated = false;
            var terminationDetail = string.Empty;
            if (result.Verdict == ThreatVerdict.Malicious &&
                _settings.AutoTerminateProcesses &&
                processId is int pid &&
                HasDecisiveEvidence(result))
            {
                terminated = ProcessRemediator.TryTerminate(pid, path, _exclusions, out terminationDetail);
            }

            var detail = $"{Path.GetFileName(path)} · {result.ThreatName ?? result.VerdictText}（评分 {result.Score}）";
            if (result.Verdict == ThreatVerdict.Malicious)
            {
                detail += locked ? "，已锁定（拒绝用户访问 + 独占占用）" : "，未能锁定文件";
            }

            if (networkBlocked > 0)
            {
                detail += $"，已自动封禁网络指标 {networkBlocked} 项";
            }

            if (terminated)
            {
                detail += $"，已终止进程 PID {processId}";
            }
            else if (terminationDetail.Length > 0)
            {
                detail += "，" + terminationDetail;
            }

            if (result.Verdict == ThreatVerdict.Malicious &&
                HasDecisiveEvidence(result) &&
                processId is int activePid)
            {
                RecordActiveThreat(activePid, path, result.ThreatName ?? result.VerdictText, ruleId, result.Score);
            }

            _hips?.ReportEvent(new HipsEvent(
                DateTimeOffset.Now,
                ruleId,
                ruleId == "HIPS.IDLE.SCAN" ? "闲时扫描发现威胁" : "实时扫描发现威胁",
                detail,
                result.Verdict == ThreatVerdict.Malicious ? HipsSeverity.Critical : HipsSeverity.High,
                path,
                null,
                path,
                locked || terminated));
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static bool HasDecisiveEvidence(FileScanResult result)
    {
        return result.Detections.Any(detection => detection.Source is
            DetectionSource.Hash or DetectionSource.PathIoc or DetectionSource.Yara or DetectionSource.BuiltInTest);
    }

    private static bool IsSystemSoftwarePath(string path)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        };

        foreach (var root in roots)
        {
            if (!string.IsNullOrWhiteSpace(root) && IsUnder(path, root))
            {
                return true;
            }
        }

        return false;
    }

    private static async Task<bool> WaitForStableAsync(string path, CancellationToken cancellationToken)
    {
        long previousLength = -1;
        for (var attempt = 0; attempt < 20; attempt++)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists)
                {
                    if (attempt == 0)
                    {
                        await Task.Delay(300, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    return false;
                }

                if (info.Length == previousLength)
                {
                    return info.Length > 0;
                }

                previousLength = info.Length;
            }
            catch
            {
                return false;
            }

            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }

        return File.Exists(path);
    }

    private async Task LoadSignaturesAsync(CancellationToken cancellationToken)
    {
        var seedDirectory = ServicePaths.ResolveSeedDirectory(_explicitSeed);
        if (seedDirectory is null)
        {
            _lastError = "找不到内置病毒库（Seed），实时扫描已停用。";
            return;
        }

        try
        {
            var locator = new SignatureLocator(seedDirectory);
            var snapshot = await locator.LoadBestAsync(cancellationToken).ConfigureAwait(false);
            if (snapshot is null)
            {
                _lastError = "没有可用的病毒库，实时扫描已停用。";
                return;
            }

            Volatile.Write(ref _snapshot, snapshot);
            Volatile.Write(ref _scanner, new AegisScanner(snapshot, null));
            _lastError = null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            _lastError = "病毒库加载失败：" + exception.Message;
        }
    }

    private async Task ReloadSignaturesAsync()
    {
        if (_disposed)
        {
            return;
        }

        var seedDirectory = ServicePaths.ResolveSeedDirectory(_explicitSeed);
        if (seedDirectory is null)
        {
            return;
        }

        try
        {
            var locator = new SignatureLocator(seedDirectory);
            var snapshot = await locator.LoadBestAsync(_cancellation.Token).ConfigureAwait(false);
            if (snapshot is null)
            {
                return;
            }

            var current = Volatile.Read(ref _snapshot);
            if (current is not null && string.Equals(current.Version, snapshot.Version, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            Volatile.Write(ref _snapshot, snapshot);
            Volatile.Write(ref _scanner, new AegisScanner(snapshot, null));
            _specialPathProbe?.Update(snapshot.SpecialPaths);
            _specialPathProbe?.Probe();
        }
        catch
        {
            // Keep the previous definitions on reload failure.
        }
    }

    private SandboxOptions BuildSandboxOptions() => new()
    {
        Enabled = _settings.SandboxEnabled,
        AutoRemediate = _settings.SandboxAutoRemediate,
        AutoBlockNetwork = _settings.SandboxAutoBlockNetwork,
        MaxRuntimeSeconds = _settings.SandboxMaxRunSeconds
    };

    private bool LockFileFromSandbox(string path, string reason)
    {
        try
        {
            var entry = _blocker?.Block(path, reason);
            return entry is not null && (entry.AclApplied || entry.HandleHeld);
        }
        catch
        {
            return false;
        }
    }

    private int BlockNetworkFromSandbox(IReadOnlyList<NetworkIndicator> indicators)
    {
        try
        {
            return _networkBlocker?.Apply(indicators).TotalAdded ?? 0;
        }
        catch
        {
            return 0;
        }
    }

    private static IReadOnlyList<string> BuildExclusions()
    {
        var exclusions = new List<string>
        {
            AppContext.BaseDirectory,
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..")),
            ServicePaths.DataRoot,
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WscGuard")
        };

        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(30)))
        {
            exclusions.Add(Path.Combine(profile.ProfilePath, "AppData", "Local", "NDAS"));
            exclusions.Add(Path.Combine(profile.ProfilePath, ".claude"));
            exclusions.Add(Path.Combine(profile.ProfilePath, ".dsh"));
            exclusions.Add(Path.Combine(profile.ProfilePath, "ioc-evidence"));
            exclusions.Add(Path.Combine(profile.ProfilePath, "blockpage"));
        }

        return exclusions
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool IsUnder(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var root = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
               path.Equals(directory, StringComparison.OrdinalIgnoreCase);
    }

    private static ServiceEvent MapEvent(HipsEvent hipsEvent) => new()
    {
        Timestamp = hipsEvent.Timestamp,
        RuleId = hipsEvent.RuleId,
        Title = hipsEvent.Title,
        Detail = hipsEvent.Detail,
        Severity = (int)hipsEvent.Severity,
        ProcessPath = hipsEvent.ProcessPath,
        CommandLine = hipsEvent.CommandLine,
        Target = hipsEvent.Target,
        Blocked = hipsEvent.Blocked
    };

    private readonly record struct ScanWorkItem(string Path, int? ProcessId, DateTime? ProcessStartTime);

    public void Dispose()
    {
        try
        {
            StopAsync().GetAwaiter().GetResult();
        }
        catch
        {
            // Best-effort teardown.
        }
    }
}
