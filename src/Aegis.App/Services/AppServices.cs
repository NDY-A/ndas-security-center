using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Aegis.Agent;
using Aegis.Agent.Security;
using Aegis.Core.Cloud;
using Aegis.Hips;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;
using Aegis.Core.Quarantine;
using Aegis.Core.Remediation;
using Aegis.Core.Scanning;
using Aegis.Core.Service;
using Aegis.Core.Signatures;

namespace Aegis.App.Services;

public sealed class AppServices : IAsyncDisposable
{
    public const string ProductName = "NDAS 安全中心";
    public const string ProductVersion = "rs_preelease-0.0.6.0a";

    private readonly object _initLock = new();
    private readonly object _scannerLock = new();
    private readonly SemaphoreSlim _updateGate = new(1, 1);
    private Task? _initialization;
    private SignatureRepository? _signatureRepository;
    private SignatureUpdater? _updater;
    private SecretFileStore? _cloudTokenStore;
    private AegisScanner? _scanner;
    private CloudReputationClient? _cloud;
    private SignatureSnapshot? _signatures;
    private HipsService? _hips;
    private ServiceClient? _serviceClient;
    private ServiceStatus? _serviceStatus;
    private bool _useService;
    private CancellationTokenSource? _servicePollCancellation;
    private Task? _servicePollTask;
    private bool _hasCloudToken;
    private bool _disposed;
    private CancellationTokenSource? _autoUpdateCancellation;
    private Task? _autoUpdateTask;
    private readonly SemaphoreSlim _realtimeScanGate = new(2, 2);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _realtimeScanCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _seenServiceEvents = new(StringComparer.Ordinal);
    private bool _serviceEventsInitialized;
    private CancellationTokenSource? _realtimeScanCancellation;

    public static AppServices Current { get; } = new();

    public AppSettings Settings { get; private set; } = new();

    public AppSettingsStore? SettingsStore { get; private set; }

    public ScanCoordinator Coordinator { get; } = new();

    public QuarantineService Quarantine { get; } = new();

    public AgentKeyStore? AgentKeyStore { get; private set; }

    public AgentApiHost? AgentApi { get; private set; }

    public bool IsInitialized { get; private set; }

    public string? InitializationError { get; private set; }

    public string? CloudTokenWarning { get; private set; }

    public string? AgentApiStartError { get; private set; }

    public string? HipsStartError { get; private set; }

    public string DataRoot => AppPaths.DataRoot;

    public string SeedDirectory { get; private set; } = string.Empty;

    public AegisScanner? Scanner => Volatile.Read(ref _scanner);

    public CloudReputationClient? Cloud => Volatile.Read(ref _cloud);

    public SignatureSnapshot? Signatures => Volatile.Read(ref _signatures);

    public HipsService? Hips => _hips;

    public bool UseService => _useService;

    public ServiceThreatIncident? ActiveThreat => _useService ? _serviceStatus?.ActiveThreat : null;

    public ServiceContainmentStatus? ContainmentStatus => _useService ? _serviceStatus?.Containment : null;

    public bool ContainmentSupported => _useService;

    public bool HipsRunning => _useService ? _serviceStatus?.HipsRunning == true : _hips?.IsRunning == true;

    public string? HipsLastError => _useService ? _serviceStatus?.LastError : _hips?.LastError;

    public ServiceStatus? HipsStatus => _useService ? _serviceStatus : BuildLocalServiceStatus();

    public IReadOnlyList<HipsEvent> HipsEvents => _useService
        ? (_serviceStatus?.RecentEvents ?? new List<ServiceEvent>()).Select(MapServiceEvent).ToArray()
        : _hips?.GetRecent(100) ?? Array.Empty<HipsEvent>();

    public int HipsEventCount => _useService ? _serviceStatus?.EventCount ?? 0 : _hips?.EventCount ?? 0;

    public bool HasCloudToken => _hasCloudToken;

    public DateTimeOffset? LastSignatureCheckAt { get; private set; }

    public bool LastSignatureCheckUpToDate { get; private set; }

    public string? LastSignatureCheckMessage { get; private set; }

    public bool AgentApiRunning => AgentApi?.IsRunning == true;

    public bool IsElevated => ElevationHelper.IsElevated;

    public string AgentApiBaseUrl => AgentApi?.BaseUrl ?? string.Empty;

    public string? AgentApiLastError => AgentApi?.LastError ?? AgentApiStartError;

    public event EventHandler? StateChanged;

    public Task InitializeAsync(string applicationDirectory)
    {
        lock (_initLock)
        {
            _initialization ??= InitializeCoreAsync(applicationDirectory);
            return _initialization;
        }
    }

    private async Task InitializeCoreAsync(string applicationDirectory)
    {
        try
        {
            AppPaths.MigrateLegacyData();
            AppPaths.EnsureDirectory(AppPaths.DataRoot);
            AppPaths.EnsureDirectory(AppPaths.SecretsRoot);
            AppPaths.EnsureDirectory(AppPaths.LogsRoot);

            SettingsStore = new AppSettingsStore(AppPaths.SettingsFile);
            Settings = await SettingsStore.LoadAsync().ConfigureAwait(false);
            ThreatReminderService.Configure(Settings.NotificationsEnabled);
            Coordinator.JobCompleted += OnScanJobCompleted;
            SeedDirectory = Path.Combine(applicationDirectory, "Seed");
            if (!Directory.Exists(SeedDirectory))
            {
                SeedDirectory = Path.Combine(applicationDirectory, "data", "seed");
            }

            _signatureRepository = new SignatureRepository(AppPaths.SignatureRoot, SeedDirectory);
            _signatures = await _signatureRepository.LoadAsync().ConfigureAwait(false);
            _updater = new SignatureUpdater(AppPaths.SignatureRoot);

            _cloudTokenStore = new SecretFileStore(Path.Combine(AppPaths.SecretsRoot, "cloud-api.key"));
            string? cloudToken = null;
            try
            {
                cloudToken = await _cloudTokenStore.ReadAsync().ConfigureAwait(false);
                _hasCloudToken = !string.IsNullOrWhiteSpace(cloudToken);
            }
            catch (Exception exception) when (exception is InvalidDataException or CryptographicException or IOException or System.ComponentModel.Win32Exception)
            {
                CloudTokenWarning = "已保存的云服务令牌无法读取，请重新输入。";
            }

            _cloud = CreateCloudClient(cloudToken);
            _scanner = new AegisScanner(_signatures, _cloud);

            _serviceClient = new ServiceClient();
            var serviceStatus = await TryGetServiceStatusAsync().ConfigureAwait(false);
            if (serviceStatus is not null)
            {
                _useService = true;
                _serviceStatus = serviceStatus;
                ApplyServiceStateToSettings(serviceStatus);
                if (ElevationHelper.IsElevated)
                {
                    try
                    {
                        var configured = await _serviceClient.ConfigureAsync(BuildServiceConfiguration()).ConfigureAwait(false);
                        if (configured is not null)
                        {
                            _serviceStatus = configured;
                            ApplyServiceStateToSettings(configured);
                        }
                    }
                    catch
                    {
                        // The service stays on its own persisted settings if configuration fails.
                    }
                }
            }
            else
            {
                StartLocalHips();
                HipsStartError = "独立防护服务未运行，已回退到进程内模式。请安装或启动 NDAS 防护服务。";
            }

            AgentKeyStore = new AgentKeyStore(AppPaths.SecretsRoot);
            AgentApi = CreateAgentApiHost();
            AgentApi.StateChanged += OnAgentApiStateChanged;

            AgentKeyMaterial? keyMaterial = null;
            try
            {
                keyMaterial = await AgentKeyStore.GetOrCreateAsync().ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is CryptographicException or IOException or InvalidDataException or System.ComponentModel.Win32Exception)
            {
                AgentApiStartError = "无法创建或读取本机自动化密钥。";
            }

            if (Settings.AgentApiEnabled && keyMaterial is not null)
            {
                try
                {
                    AgentApi.Start(keyMaterial.Secret);
                    AgentApiStartError = null;
                }
                catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    AgentApiStartError = exception.Message;
                }
            }

            AutoStartService.SetEnabled(Settings.AutoStartEnabled);

            IsInitialized = true;
            RaiseStateChanged();
            if (!Settings.RealtimeProtectionEnabled)
            {
                NotifyRealtimeProtectionOff();
            }

            if (_useService)
            {
                StartServicePolling();
            }

            _autoUpdateCancellation = new CancellationTokenSource();
            _autoUpdateTask = Task.Run(() => AutoUpdateLoopAsync(_autoUpdateCancellation.Token));

            if (!_useService && Settings.RealtimeProtectionEnabled && Settings.RealtimeScanActiveProcesses)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                        await ScanActiveProcessesAsync().ConfigureAwait(false);
                    }
                    catch
                    {
                        // Initial realtime scan is best-effort.
                    }
                });
            }
        }
        catch (Exception exception)
        {
            InitializationError = DescribeInitializationError(exception);
            RaiseStateChanged();
            throw;
        }
    }

    public async Task<SignatureUpdateResult> UpdateSignaturesAsync(IProgress<SignatureUpdateProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        EnsureReady();
        if (_updater is null || _signatureRepository is null)
        {
            throw new InvalidOperationException("病毒库更新器尚未初始化。");
        }

        await _updateGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var result = await _updater.UpdateAsync(progress, cancellationToken).ConfigureAwait(false);
            LastSignatureCheckAt = result.CheckedAt;
            LastSignatureCheckUpToDate = result.IsUpToDate;
            LastSignatureCheckMessage = result.Success
                ? result.IsUpToDate ? "安全智能是最新的。" : "安全智能已更新"
                : IsTimeoutFailure(result.Error) ? "无可用更新" : result.Error;

            if (result.Success && !result.IsUpToDate)
            {
                var snapshot = await _signatureRepository.LoadAsync(cancellationToken).ConfigureAwait(false);
                Volatile.Write(ref _signatures, snapshot);
                ReplaceScanner(snapshot);
            }

            RaiseStateChanged();
            return result;
        }
        finally
        {
            _updateGate.Release();
        }
    }

    private async Task AutoUpdateLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (Settings.AutoUpdateEnabled && IsInitialized)
                {
                    await UpdateSignaturesAsync(null, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception exception)
            {
                LastSignatureCheckAt = DateTimeOffset.UtcNow;
                LastSignatureCheckUpToDate = false;
                LastSignatureCheckMessage = "自动检查失败：" + exception.Message;
                RaiseStateChanged();
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(60), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public async Task SetAutoUpdateEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.AutoUpdateEnabled = enabled;
        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetThemeAsync(AppThemePreference theme)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.Theme = theme;
        var window = Aegis.App.App.MainWindow;
        window?.DispatcherQueue.TryEnqueue(() => window.ApplyTheme(theme));
        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public ScanJob StartScan(ScanProfileKind profile, string? customPath = null)
    {
        EnsureReady();
        var scanner = Scanner ?? throw new InvalidOperationException("扫描引擎尚未初始化。");
        var options = CreateScanOptions();
        var request = profile switch
        {
            ScanProfileKind.Quick => ScanRequest.Quick(options),
            ScanProfileKind.Full => ScanRequest.Full(options),
            ScanProfileKind.Custom when !string.IsNullOrWhiteSpace(customPath) => ScanRequest.Custom(customPath, options),
            _ => throw new ArgumentException("自定义扫描必须提供路径。", nameof(customPath))
        };

        return Coordinator.Start(scanner, request);
    }

    public ScanOptions CreateScanOptions()
    {
        var policy = Settings.CloudPolicy;
        var queryCloud = Settings.CloudEnabled && (Scanner?.Cloud.IsConfigured ?? false);
        var exclusions = Settings.Exclusions
            .Concat(GetSelfExclusions())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(256)
            .ToArray();
        return new ScanOptions
        {
            MaxFileSizeBytes = Math.Clamp(Settings.MaxFileSizeBytes, 1024 * 1024, 2L * 1024 * 1024 * 1024),
            MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount / 2, 2, 4),
            RunHeuristics = true,
            QueryCloud = queryCloud,
            CloudPolicy = policy,
            UseDefaultExclusions = Settings.UseDefaultExclusions,
            UserExclusions = exclusions,
            AllowedHashes = Settings.AllowedHashes.ToArray(),
            IncludeHiddenFiles = true
        };
    }

    private static IEnumerable<string> GetSelfExclusions()
    {
        var baseDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (baseDirectory.Length > 0)
        {
            yield return baseDirectory;
        }

        yield return AppPaths.DataRoot;
        if (Directory.Exists(AppPaths.LegacyDataRoot))
        {
            yield return AppPaths.LegacyDataRoot;
        }

        var directory = baseDirectory.Length > 0 ? new DirectoryInfo(baseDirectory) : null;
        for (var depth = 0; depth < 8 && directory is not null; depth++, directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Aegis.sln")))
            {
                yield return directory.FullName;
                break;
            }
        }
    }

    public async Task SaveScanSettingsAsync(long maxFileSizeBytes, bool useDefaultExclusions,
        IReadOnlyList<string> exclusions, IReadOnlyList<string> allowedHashes)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.MaxFileSizeBytes = Math.Clamp(maxFileSizeBytes, 1024 * 1024, 2L * 1024 * 1024 * 1024);
        Settings.UseDefaultExclusions = useDefaultExclusions;
        Settings.Exclusions = exclusions
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(256)
            .ToList();
        Settings.AllowedHashes = allowedHashes
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim().ToLowerInvariant())
            .Where(value => value.Length == 64 && value.All(character => char.IsAsciiHexDigit(character)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(512)
            .ToList();
        await SaveSettingsAsync().ConfigureAwait(false);
        _hips?.UpdateOptions(CreateHipsOptions());
    }

    public async Task AllowHashAsync(string sha256)
    {
        EnsureReady();
        EnsureElevatedSettings();
        var normalized = sha256?.Trim().ToLowerInvariant() ?? string.Empty;
        if (normalized.Length != 64 || !normalized.All(character => char.IsAsciiHexDigit(character)))
        {
            throw new ArgumentException("SHA-256 必须是 64 位十六进制字符串。", nameof(sha256));
        }

        if (!Settings.AllowedHashes.Contains(normalized, StringComparer.OrdinalIgnoreCase))
        {
            Settings.AllowedHashes.Add(normalized);
        }

        await SaveSettingsAsync().ConfigureAwait(false);
    }

    public async Task ApplyCloudSettingsAsync(bool enabled, string endpoint, CloudQueryPolicy policy, string? newApiKey, bool clearApiKey)
    {
        EnsureReady();
        EnsureElevatedSettings();
        if (_cloudTokenStore is null)
        {
            throw new InvalidOperationException("云安全服务尚未初始化。");
        }

        var normalizedEndpoint = NormalizeEndpoint(endpoint, enabled);
        if (!string.IsNullOrWhiteSpace(newApiKey))
        {
            await _cloudTokenStore.WriteAsync(newApiKey.Trim()).ConfigureAwait(false);
            _hasCloudToken = true;
            CloudTokenWarning = null;
        }
        else if (clearApiKey)
        {
            await _cloudTokenStore.DeleteAsync().ConfigureAwait(false);
            _hasCloudToken = false;
        }

        string? token = null;
        if (_hasCloudToken)
        {
            token = await _cloudTokenStore.ReadAsync().ConfigureAwait(false);
        }

        Settings.CloudEnabled = enabled;
        Settings.CloudEndpoint = normalizedEndpoint;
        Settings.CloudPolicy = policy;
        await SaveSettingsAsync().ConfigureAwait(false);

        var oldCloud = _cloud;
        var newCloud = CreateCloudClient(token);
        Volatile.Write(ref _cloud, newCloud);
        ReplaceScanner(Signatures ?? throw new InvalidOperationException("病毒库尚未加载。"));
        oldCloud?.Dispose();
        RaiseStateChanged();
    }

    public async Task<CloudHealthResult> TestCloudAsync(CancellationToken cancellationToken = default)
    {
        var cloud = Cloud;
        if (cloud is null)
        {
            return new CloudHealthResult(false, "云安全服务尚未初始化。");
        }

        return await cloud.CheckHealthAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SetAgentApiEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        if (AgentApi is null || AgentKeyStore is null)
        {
            throw new InvalidOperationException("自动化接口尚未初始化。");
        }

        if (enabled)
        {
            var key = await AgentKeyStore.GetOrCreateAsync().ConfigureAwait(false);
            AgentApi.Start(key.Secret);
            AgentApiStartError = null;
        }
        else
        {
            await AgentApi.StopAsync().ConfigureAwait(false);
        }

        Settings.AgentApiEnabled = enabled;
        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task<AgentKeyMetadata?> GetAgentKeyMetadataAsync()
    {
        return AgentKeyStore is null ? null : await AgentKeyStore.GetMetadataAsync().ConfigureAwait(false);
    }

    public async Task<string> RevealAgentKeyAsync()
    {
        if (AgentKeyStore is null)
        {
            throw new InvalidOperationException("自动化接口尚未初始化。");
        }

        return await AgentKeyStore.RevealAsync().ConfigureAwait(false);
    }

    public async Task<AgentKeyMaterial> RotateAgentKeyAsync()
    {
        if (AgentKeyStore is null)
        {
            throw new InvalidOperationException("自动化接口尚未初始化。");
        }

        var material = await AgentKeyStore.RotateAsync().ConfigureAwait(false);
        AgentApi?.UpdateKey(material.Secret);
        RaiseStateChanged();
        return material;
    }

    public async Task SaveSettingsAsync()
    {
        if (SettingsStore is null)
        {
            throw new InvalidOperationException("设置存储尚未初始化。");
        }

        EnsureElevatedSettings();
        await SettingsStore.SaveAsync(Settings).ConfigureAwait(false);
        RaiseStateChanged();
    }

    private AgentApiHost CreateAgentApiHost()
    {
        var options = new AgentApiOptions
        {
            Port = Settings.AgentApiPort,
            MaxConcurrentRequests = 8,
            RequestTimeout = TimeSpan.FromSeconds(20)
        };

        return new AgentApiHost(options, Coordinator, () => Scanner, CreateScanOptions, _hips,
            () => _useService ? _serviceStatus : null);
    }

    private HipsOptions CreateHipsOptions() => new()
    {
        BlockCritical = Settings.HipsBlockCritical,
        SelfExclusions = GetHipsExclusions()
            .Concat(Settings.Exclusions)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray(),
        LogPath = Path.Combine(AppPaths.LogsRoot, "hips.log")
    };

    private static IEnumerable<string> GetHipsExclusions()
    {
        foreach (var path in GetSelfExclusions())
        {
            yield return path;
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        yield return Path.Combine(profile, ".claude");
        yield return Path.Combine(profile, ".dsh");
        yield return Path.Combine(profile, "ioc-evidence");
        yield return Path.Combine(profile, "blockpage");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WscGuard");
    }

    private void StartLocalHips()
    {
        _hips = new HipsService();
        _hips.EventRaised += OnHipsEvent;
        _hips.StateChanged += OnHipsStateChanged;
        _hips.ProcessObserved += OnHipsProcessObserved;
        _hips.DetectInjection = Settings.RealtimeProtectionEnabled;
        _hips.BlockInjection = Settings.RealtimeBlockInjection;
        _hips.BlockRegistry = Settings.RealtimeBlockRegistry;
        if (Settings.HipsEnabled)
        {
            _ = Task.Run(() =>
            {
                try
                {
                    _hips.Start(CreateHipsOptions());
                }
                catch (Exception exception)
                {
                    HipsStartError = exception.Message;
                    RaiseStateChanged();
                }
            });
        }
    }

    private async Task<ServiceStatus?> TryGetServiceStatusAsync()
    {
        try
        {
            return _serviceClient is null ? null : await _serviceClient.GetStatusAsync().ConfigureAwait(false);
        }
        catch
        {
            return null;
        }
    }

    private void ApplyServiceStateToSettings(ServiceStatus status)
    {
        Settings.HipsEnabled = status.HipsEnabled;
        Settings.HipsBlockCritical = status.BlockCritical;
        Settings.RealtimeProtectionEnabled = status.RealtimeProtectionEnabled;
        Settings.RealtimeScanActiveProcesses = status.ScanActiveProcesses;
        Settings.RealtimeBlockInjection = status.BlockInjection;
        Settings.RealtimeBlockRegistry = status.BlockRegistry;

        // An older service does not report the new fields; keep local values instead of
        // clobbering them with defaults while app and service versions are mixed.
        if (status.IdleScanIdleMinutes > 0)
        {
            Settings.IdleScanEnabled = status.IdleScanEnabled;
            Settings.IdleScanIdleMinutes = status.IdleScanIdleMinutes;
            Settings.AutoTerminateProcesses = status.AutoTerminateProcesses;
            Settings.AutoDeleteMaliciousP7b = status.AutoDeleteMaliciousP7b;
        }

        if (status.SandboxSupported)
        {
            Settings.SandboxEnabled = status.SandboxEnabled;
            Settings.SandboxAutoRemediate = status.SandboxAutoRemediate;
        }
    }

    private ServiceConfiguration BuildServiceConfiguration() => new()
    {
        HipsEnabled = Settings.HipsEnabled,
        BlockCritical = Settings.HipsBlockCritical,
        RealtimeProtectionEnabled = Settings.RealtimeProtectionEnabled,
        ScanActiveProcesses = Settings.RealtimeScanActiveProcesses,
        BlockInjection = Settings.RealtimeBlockInjection,
        BlockRegistry = Settings.RealtimeBlockRegistry,
        IdleScanEnabled = Settings.IdleScanEnabled,
        IdleScanIdleMinutes = Settings.IdleScanIdleMinutes,
        AutoTerminateProcesses = Settings.AutoTerminateProcesses,
        AutoDeleteMaliciousP7b = Settings.AutoDeleteMaliciousP7b,
        FirewallAutoBlockEnabled = Settings.FirewallAutoBlockEnabled,
        SandboxEnabled = Settings.SandboxEnabled,
        SandboxAutoRemediate = Settings.SandboxAutoRemediate,
        SandboxMaxRunSeconds = Settings.SandboxMaxRunSeconds
    };

    private async Task ApplyServiceConfigurationAsync()
    {
        if (!_useService || _serviceClient is null)
        {
            return;
        }

        var status = await _serviceClient.ConfigureAsync(BuildServiceConfiguration()).ConfigureAwait(false);
        if (status is null)
        {
            throw new InvalidOperationException("无法连接 NDAS 防护服务，请确认服务正在运行。");
        }

        if (status.LastError is { Length: > 0 } error && error.Contains("管理员", StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException(error);
        }

        _serviceStatus = status;
    }

    private void StartServicePolling()
    {
        if (_serviceClient is null || _servicePollTask is not null)
        {
            return;
        }

        _servicePollCancellation = new CancellationTokenSource();
        var token = _servicePollCancellation.Token;
        _servicePollTask = Task.Run(async () =>
        {
            var fingerprint = string.Empty;
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var status = await _serviceClient.GetStatusAsync(token).ConfigureAwait(false);
                    if (status is not null)
                    {
                        var next = $"{status.EventCount}|{status.HipsRunning}|{status.HipsEnabled}|{status.ScannedFiles}|{status.ThreatsFound}|{status.SignatureVersion}|{status.LastError}|{status.IdleScanActive}|{status.LastIdleScanAt}|{status.LastIdleScanFiles}"
                                   + $"|{status.ActiveThreat?.IncidentId}|{status.ActiveThreat?.ProcessStillRunning}"
                                   + $"|{status.Containment?.Active}|{status.Containment?.State}|{status.Containment?.Phase}"
                                   + $"|{status.Containment?.FilesScanned}|{status.Containment?.ThreatsFound}"
                                   + $"|{status.Containment?.GuardSweepKills}|{status.Containment?.ShutdownPending}"
                                   + $"|{status.Containment?.LastError}|{status.Containment?.Actions.Count}"
                                   + $"|{status.SandboxAvailable}|{status.SandboxQueueDepth}|{status.SandboxAnalyzing}"
                                   + $"|{status.SandboxAnalyzed}|{status.SandboxMalicious}|{status.SandboxLastVerdict}"
                                   + $"|{status.SandboxLastAt}|{status.SandboxLastError}";
                        _serviceStatus = status;
                        NotifyForNewServiceEvents(status);
                        if (!string.Equals(next, fingerprint, StringComparison.Ordinal))
                        {
                            fingerprint = next;
                            RaiseStateChanged();
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    // Transient pipe errors are retried on the next tick.
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }, token);
    }

    private ServiceStatus? BuildLocalServiceStatus()
    {
        if (_hips is null)
        {
            return null;
        }

        return new ServiceStatus
        {
            ServiceRunning = true,
            HipsRunning = _hips.IsRunning,
            HipsEnabled = Settings.HipsEnabled,
            ProcessMonitoringActive = _hips.ProcessMonitoringActive,
            FileMonitoringActive = _hips.FileMonitoringActive,
            RegistryMonitoringActive = _hips.RegistryMonitoringActive,
            RealtimeProtectionEnabled = Settings.RealtimeProtectionEnabled,
            ScanActiveProcesses = Settings.RealtimeScanActiveProcesses,
            BlockInjection = Settings.RealtimeBlockInjection,
            BlockRegistry = Settings.RealtimeBlockRegistry,
            BlockCritical = Settings.HipsBlockCritical,
            IdleScanEnabled = Settings.IdleScanEnabled,
            IdleScanIdleMinutes = Settings.IdleScanIdleMinutes,
            AutoTerminateProcesses = Settings.AutoTerminateProcesses,
            AutoDeleteMaliciousP7b = Settings.AutoDeleteMaliciousP7b,
            FirewallAutoBlockEnabled = Settings.FirewallAutoBlockEnabled,
            FirewallLastError = Settings.FirewallAutoBlockEnabled ? "需要 NDAS 防护服务才能写入 hosts 和防火墙规则。" : null,
            SandboxSupported = false,
            SandboxAvailable = false,
            SandboxEnabled = Settings.SandboxEnabled,
            SandboxAutoRemediate = Settings.SandboxAutoRemediate,
            SandboxLastError = "高熵样本沙箱分析需要 NDAS 防护服务。",
            LastError = _hips.LastError,
            EventCount = _hips.EventCount,
            UpdatedAt = DateTimeOffset.UtcNow
        };
    }

    private void NotifyForNewServiceEvents(ServiceStatus status)
    {
        var events = status.RecentEvents;
        if (!_serviceEventsInitialized)
        {
            foreach (var serviceEvent in events)
            {
                _seenServiceEvents.Add(ServiceEventKey(serviceEvent));
            }

            _serviceEventsInitialized = true;
            return;
        }

        foreach (var serviceEvent in events)
        {
            var key = ServiceEventKey(serviceEvent);
            if (!_seenServiceEvents.Add(key))
            {
                continue;
            }

            if (!Settings.NotificationsEnabled)
            {
                continue;
            }

            if (serviceEvent.RuleId.Equals("HIPS.SANDBOX.SUBMITTED", StringComparison.OrdinalIgnoreCase))
            {
                NotificationService.ShowWarning("正在沙箱分析", serviceEvent.Detail);
                continue;
            }

            if (serviceEvent.RuleId.Equals("HIPS.SANDBOX.UNAVAILABLE", StringComparison.OrdinalIgnoreCase))
            {
                NotificationService.ShowWarning("沙箱组件不可用", serviceEvent.Detail);
                continue;
            }

            if (!IsThreatEvent(serviceEvent.RuleId, serviceEvent.Severity))
            {
                continue;
            }

            ThreatReminderService.Report(key, serviceEvent.Title, serviceEvent.Detail, serviceEvent.Blocked);
        }

        if (_seenServiceEvents.Count > 2000)
        {
            _seenServiceEvents.Clear();
            foreach (var serviceEvent in events)
            {
                _seenServiceEvents.Add(ServiceEventKey(serviceEvent));
            }
        }
    }

    private void OnScanJobCompleted(object? sender, ScanJob job)
    {
        try
        {
            if (!Settings.NotificationsEnabled || job.Summary is not { } summary)
            {
                return;
            }

            var threats = summary.Detections
                .Where(detection => detection.Verdict is ThreatVerdict.Malicious or ThreatVerdict.Pua
                    or ThreatVerdict.Attention)
                .ToArray();
            if (threats.Length == 0)
            {
                return;
            }

            var key = "scan:" + job.Id;
            if (threats.Length == 1)
            {
                var threat = threats[0];
                ThreatReminderService.Report(key,
                    "扫描发现威胁：" + (threat.ThreatName ?? threat.VerdictText),
                    $"{threat.FilePath}（评分 {threat.Score}）", handled: false);
                return;
            }

            var names = string.Join("、", threats.Take(3).Select(threat => threat.FileName));
            var suffix = threats.Length > 3 ? $" 等 {threats.Length} 个文件" : string.Empty;
            ThreatReminderService.Report(key, $"扫描发现 {threats.Length} 个威胁", names + suffix,
                handled: false);
        }
        catch
        {
            // Notification reporting must not affect scan bookkeeping.
        }
    }

    private static string ServiceEventKey(ServiceEvent serviceEvent) =>
        $"{serviceEvent.Timestamp:O}|{serviceEvent.RuleId}|{serviceEvent.Target}";

    private static bool IsThreatEvent(string ruleId, int severity)
    {
        if (ruleId.Equals("HIPS.IOC.P7B_TRUSTED", StringComparison.OrdinalIgnoreCase) ||
            ruleId.Equals("HIPS.SANDBOX.SUBMITTED", StringComparison.OrdinalIgnoreCase) ||
            ruleId.Equals("HIPS.SANDBOX.UNAVAILABLE", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (ruleId.StartsWith("HIPS.SANDBOX.RESULT", StringComparison.OrdinalIgnoreCase))
        {
            return severity >= (int)HipsSeverity.Medium;
        }

        return ruleId.StartsWith("HIPS.REALTIME", StringComparison.OrdinalIgnoreCase) ||
               ruleId.StartsWith("HIPS.IDLE", StringComparison.OrdinalIgnoreCase) ||
               ruleId.StartsWith("HIPS.IOC", StringComparison.OrdinalIgnoreCase) ||
               ruleId.StartsWith("HIPS.PROC", StringComparison.OrdinalIgnoreCase);
    }

    private static HipsEvent MapServiceEvent(ServiceEvent serviceEvent) => new(
        serviceEvent.Timestamp,
        serviceEvent.RuleId,
        serviceEvent.Title,
        serviceEvent.Detail,
        (HipsSeverity)serviceEvent.Severity,
        serviceEvent.ProcessPath,
        serviceEvent.CommandLine,
        serviceEvent.Target,
        serviceEvent.Blocked);

    public async Task<ServiceContainmentStatus?> StartContainmentAsync(CancellationToken cancellationToken = default)
    {
        EnsureReady();
        if (!_useService || _serviceClient is null)
        {
            throw new InvalidOperationException("高威胁强力清除需要 NDAS 防护服务（LocalSystem）。");
        }

        var status = await _serviceClient.StartContainmentAsync(cancellationToken).ConfigureAwait(false);
        if (status is null)
        {
            throw new InvalidOperationException("无法连接 NDAS 防护服务。");
        }

        if (status.Containment is null)
        {
            throw new InvalidOperationException("NDAS 防护服务版本过旧，请升级服务后再使用强力清除。");
        }

        if (status.Containment is not { Active: true } && status.LastError is { Length: > 0 } error)
        {
            throw new InvalidOperationException(error);
        }

        _serviceStatus = status;
        RaiseStateChanged();
        return status.Containment;
    }

    public async Task<ServiceContainmentStatus?> AbortContainmentAsync(CancellationToken cancellationToken = default)
    {
        EnsureReady();
        if (!_useService || _serviceClient is null)
        {
            throw new InvalidOperationException("取消强力清除需要 NDAS 防护服务。");
        }

        var status = await _serviceClient.AbortContainmentAsync(cancellationToken).ConfigureAwait(false);
        if (status is null)
        {
            throw new InvalidOperationException("无法连接 NDAS 防护服务。");
        }

        if (status.Containment is { State: not ContainmentStates.Cancelled } &&
            status.LastError is { Length: > 0 } error)
        {
            throw new InvalidOperationException(error);
        }

        _serviceStatus = status;
        RaiseStateChanged();
        return status.Containment;
    }

    public async Task SetHipsEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.HipsEnabled = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
            await SaveSettingsAsync().ConfigureAwait(false);
            RaiseStateChanged();
            return;
        }

        if (_hips is null)
        {
            _hips = new HipsService();
            _hips.EventRaised += OnHipsEvent;
            _hips.StateChanged += OnHipsStateChanged;
            _hips.ProcessObserved += OnHipsProcessObserved;
        }

        if (enabled)
        {
            _hips.BlockCritical = Settings.HipsBlockCritical;
            await Task.Run(() => _hips.Start(CreateHipsOptions())).ConfigureAwait(false);
            HipsStartError = null;
        }
        else
        {
            _hips.Stop();
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetHipsBlockCriticalAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.HipsBlockCritical = enabled;
        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
            await SaveSettingsAsync().ConfigureAwait(false);
            RaiseStateChanged();
            return;
        }

        if (_hips is not null)
        {
            _hips.BlockCritical = enabled;
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    private void OnHipsEvent(object? sender, HipsEvent hipsEvent)
    {
        RaiseStateChanged();
        if (!Settings.NotificationsEnabled)
        {
            return;
        }

        if (IsThreatEvent(hipsEvent.RuleId, (int)hipsEvent.Severity))
        {
            var key = $"{hipsEvent.Timestamp:O}|{hipsEvent.RuleId}|{hipsEvent.Target}|{hipsEvent.ProcessPath}";
            ThreatReminderService.Report(key, hipsEvent.Title, hipsEvent.Detail, hipsEvent.Blocked);
        }
        else if (hipsEvent.Severity == HipsSeverity.Critical)
        {
            NotificationService.ShowThreat(hipsEvent.Title, hipsEvent.Detail);
        }
    }

    private void OnHipsStateChanged(object? sender, EventArgs e) => RaiseStateChanged();

    private void OnHipsProcessObserved(object? sender, HipsProcessObservation observation)
    {
        if (!Settings.RealtimeProtectionEnabled || !Settings.RealtimeScanActiveProcesses)
        {
            return;
        }

        var path = observation.ProcessPath;
        if (string.IsNullOrWhiteSpace(path) || IsSelfOrSystemPath(path))
        {
            return;
        }

        _ = ScanProcessPathAsync(path, observation.ProcessId,
            observation.ProcessName ?? Path.GetFileName(path));
    }

    private async Task ScanActiveProcessesAsync()
    {
        if (!IsInitialized || !Settings.RealtimeProtectionEnabled || !Settings.RealtimeScanActiveProcesses)
        {
            return;
        }

        _realtimeScanCancellation?.Cancel();
        _realtimeScanCancellation?.Dispose();
        var cancellation = new CancellationTokenSource();
        _realtimeScanCancellation = cancellation;
        var token = cancellation.Token;

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (token.IsCancellationRequested)
                {
                    break;
                }

                string? path = null;
                try
                {
                    path = process.MainModule?.FileName;
                }
                catch
                {
                    // Protected system processes cannot be inspected.
                }

                if (string.IsNullOrWhiteSpace(path) || IsSelfOrSystemPath(path))
                {
                    continue;
                }

                try
                {
                    await ScanProcessPathAsync(path, process.Id, process.ProcessName, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private async Task ScanProcessPathAsync(string path, int processId, string processName,
        CancellationToken cancellationToken = default)
    {
        var scanner = Scanner;
        if (scanner is null || !File.Exists(path) || IsSelfOrSystemPath(path))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (_realtimeScanCache.TryGetValue(path, out var lastScan) &&
            now - lastScan < TimeSpan.FromMinutes(5))
        {
            return;
        }

        _realtimeScanCache[path] = now;
        try
        {
            await _realtimeScanGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        try
        {
            var result = await scanner.ScanFileAsync(path, CreateScanOptions(), cancellationToken).ConfigureAwait(false);
            if (result.Verdict is not (ThreatVerdict.Malicious or ThreatVerdict.Pua))
            {
                return;
            }

            var strongEvidence = result.Detections.Any(detection =>
                detection.Source is DetectionSource.Hash or DetectionSource.Cloud or DetectionSource.BuiltInTest or DetectionSource.Yara or DetectionSource.PathIoc);
            if (!strongEvidence && IsSignedExecutable(path))
            {
                return;
            }

            var blocked = false;
            var detail = $"{result.VerdictText}：{result.ThreatName ?? Path.GetFileName(path)}（评分 {result.Score}）";
            var shouldTerminate = result.Verdict == ThreatVerdict.Malicious &&
                                  (Settings.HipsBlockCritical ||
                                   (Settings.AutoTerminateProcesses && strongEvidence));
            if (shouldTerminate)
            {
                var exclusions = GetSelfExclusions().Concat(Settings.Exclusions).ToArray();
                if (ProcessRemediator.TryTerminate(processId, path, exclusions, out var terminationDetail))
                {
                    blocked = true;
                    detail += "，已终止进程。";
                }
                else if (Settings.AutoTerminateProcesses)
                {
                    detail += "，" + terminationDetail;
                }
            }

            _hips?.ReportEvent(new HipsEvent(DateTimeOffset.Now, "HIPS.REALTIME.SCAN",
                "实时防护发现威胁", detail,
                result.Verdict == ThreatVerdict.Malicious ? HipsSeverity.Critical : HipsSeverity.High,
                path, null, $"PID {processId} {processName}", blocked));

            RaiseStateChanged();
        }
        catch (OperationCanceledException)
        {
            // Cancellation during shutdown or reconfiguration.
        }
        catch
        {
            // Realtime scanning must never destabilize the app.
        }
        finally
        {
            _realtimeScanGate.Release();
        }
    }

    private static bool IsSignedExecutable(string path)
    {
        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(path);
            return certificate is not null;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsSelfOrSystemPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        foreach (var exclusion in GetSelfExclusions())
        {
            var root = exclusion.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                       Path.DirectorySeparatorChar;
            if (path.Equals(exclusion, StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return windows.Length > 0 && path.StartsWith(windows, StringComparison.OrdinalIgnoreCase);
    }

    public async Task SetRealtimeProtectionEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.RealtimeProtectionEnabled = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
            await SaveSettingsAsync().ConfigureAwait(false);
            if (!enabled)
            {
                NotifyRealtimeProtectionOff();
            }

            RaiseStateChanged();
            return;
        }

        if (_hips is not null)
        {
            _hips.DetectInjection = enabled;
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        if (enabled)
        {
            _ = Task.Run(ScanActiveProcessesAsync);
        }
        else
        {
            _realtimeScanCancellation?.Cancel();
            NotifyRealtimeProtectionOff();
        }

        RaiseStateChanged();
    }

    private void NotifyRealtimeProtectionOff()
    {
        if (!Settings.NotificationsEnabled)
        {
            return;
        }

        NotificationService.ShowWarning("NDAS 防病毒", "NDAS防病毒已停止保护设备，需要立即开启实时防护");
    }

    public async Task SetRealtimeScanActiveProcessesAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.RealtimeScanActiveProcesses = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
            await SaveSettingsAsync().ConfigureAwait(false);
            RaiseStateChanged();
            return;
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        if (enabled && Settings.RealtimeProtectionEnabled)
        {
            _ = Task.Run(ScanActiveProcessesAsync);
        }

        RaiseStateChanged();
    }

    public async Task SetRealtimeBlockInjectionAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.RealtimeBlockInjection = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
            await SaveSettingsAsync().ConfigureAwait(false);
            RaiseStateChanged();
            return;
        }

        if (_hips is not null)
        {
            _hips.BlockInjection = enabled;
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetRealtimeBlockRegistryAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.RealtimeBlockRegistry = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
            await SaveSettingsAsync().ConfigureAwait(false);
            RaiseStateChanged();
            return;
        }

        if (_hips is not null)
        {
            _hips.BlockRegistry = enabled;
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetAutoTerminateProcessesAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.AutoTerminateProcesses = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetIdleScanEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.IdleScanEnabled = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetAutoDeleteMaliciousP7bAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.AutoDeleteMaliciousP7b = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetFirewallAutoBlockAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.FirewallAutoBlockEnabled = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetSandboxEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.SandboxEnabled = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetSandboxAutoRemediateAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.SandboxAutoRemediate = enabled;

        if (_useService)
        {
            await ApplyServiceConfigurationAsync().ConfigureAwait(false);
        }

        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetNotificationsEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.NotificationsEnabled = enabled;
        ThreatReminderService.Configure(enabled);
        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    public async Task SetAutoStartEnabledAsync(bool enabled)
    {
        EnsureReady();
        EnsureElevatedSettings();
        Settings.AutoStartEnabled = enabled;
        AutoStartService.SetEnabled(enabled);
        await SaveSettingsAsync().ConfigureAwait(false);
        RaiseStateChanged();
    }

    private CloudReputationClient CreateCloudClient(string? token)
    {
        return new CloudReputationClient(new CloudOptions
        {
            Enabled = Settings.CloudEnabled,
            Endpoint = Settings.CloudEndpoint,
            ApiKey = token,
            QueryPolicy = Settings.CloudPolicy,
            Timeout = TimeSpan.FromSeconds(4)
        });
    }

    private void ReplaceScanner(SignatureSnapshot snapshot)
    {
        var cloud = Cloud;
        if (cloud is null)
        {
            return;
        }

        var next = new AegisScanner(snapshot, cloud);
        lock (_scannerLock)
        {
            Volatile.Write(ref _scanner, next);
        }
    }

    private static string NormalizeEndpoint(string endpoint, bool enabled)
    {
        var trimmed = endpoint?.Trim() ?? string.Empty;
        if (!enabled && trimmed.Length == 0)
        {
            return string.Empty;
        }

        if (trimmed.Length == 0 ||
            !Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("https" or "http") ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            (uri.Scheme == "http" && !uri.IsLoopback))
        {
            throw new ArgumentException("云服务地址必须使用 HTTPS；本机回环地址可使用 HTTP。", nameof(endpoint));
        }

        return uri.AbsoluteUri.TrimEnd('/');
    }

    private void OnAgentApiStateChanged(object? sender, EventArgs e) => RaiseStateChanged();

    private void EnsureReady()
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException(InitializationError ?? "安全中心尚未初始化。");
        }
    }

    private static void EnsureElevatedSettings()
    {
        if (!ElevationHelper.IsElevated)
        {
            throw new UnauthorizedAccessException("更改设置需要管理员权限。请以管理员身份重新启动 NDAS。");
        }
    }

    private static bool IsTimeoutFailure(string? message) =>
        !string.IsNullOrWhiteSpace(message) &&
        (message.Contains("超时", StringComparison.OrdinalIgnoreCase) ||
         message.Contains("timeout", StringComparison.OrdinalIgnoreCase) ||
         message.Contains("timed out", StringComparison.OrdinalIgnoreCase));

    private void RaiseStateChanged()
    {
        try
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
        catch
        {
            // UI failures must not destabilize the engine.
        }
    }

    private static string DescribeInitializationError(Exception exception) => exception switch
    {
        UnauthorizedAccessException => "没有写入 NDAS 数据目录的权限。",
        DirectoryNotFoundException => "找不到病毒库或应用数据目录。",
        InvalidDataException => exception.Message,
        IOException => "初始化时发生文件 I/O 错误。",
        _ => exception.Message
    };

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _autoUpdateCancellation?.Cancel();
        if (_autoUpdateTask is not null)
        {
            try
            {
                await _autoUpdateTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected during shutdown.
            }
        }

        _autoUpdateCancellation?.Dispose();
        _servicePollCancellation?.Cancel();
        if (_servicePollTask is not null)
        {
            try
            {
                await Task.WhenAny(_servicePollTask, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);
            }
            catch
            {
                // Polling shutdown is best-effort.
            }
        }

        _servicePollCancellation?.Dispose();
        _realtimeScanCancellation?.Cancel();
        _realtimeScanCancellation?.Dispose();
        if (_hips is not null)
        {
            _hips.ProcessObserved -= OnHipsProcessObserved;
        }

        if (AgentApi is not null)
        {
            AgentApi.StateChanged -= OnAgentApiStateChanged;
            await AgentApi.DisposeAsync().ConfigureAwait(false);
        }

        Coordinator.Dispose();
        Cloud?.Dispose();
        _hips?.Dispose();
        _updateGate.Dispose();
        _realtimeScanGate.Dispose();
    }
}
