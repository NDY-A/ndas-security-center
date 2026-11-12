using Aegis.App.Services;
using Aegis.Core.Quarantine;
using Aegis.Core.Scanning;
using Aegis.Hips;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Aegis.App.Views;

public sealed partial class HipsPage : Page
{
    private bool _subscribed;
    private bool _attached;
    private bool _ready;
    private bool _suppressToggles;
    private bool _suppressTheme;
    private bool _themeReady;
    private bool _settingsLoaded;

    public HipsPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        _attached = true;
        if (!_subscribed)
        {
            App.Services.StateChanged += OnStateChanged;
            _subscribed = true;
        }

        if (!App.Services.IsInitialized)
        {
            try
            {
                await App.Services.InitializeAsync(AppContext.BaseDirectory);
            }
            catch
            {
                // The page renders the initialization error below.
            }
        }

        _ready = true;
        if (!_settingsLoaded)
        {
            _settingsLoaded = true;
            LoadSettingsUI();
            DispatcherQueue.TryEnqueue(() => _themeReady = true);
        }

        RefreshStatus();
        RefreshQuarantine();
    }

    private void BreadcrumbRoot_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("dashboard");

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _attached = false;
        _ready = false;
        if (_subscribed)
        {
            App.Services.StateChanged -= OnStateChanged;
            _subscribed = false;
        }
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        if (_attached)
        {
            DispatcherQueue.TryEnqueue(RefreshStatus);
        }
    }

    private void LoadSettingsUI()
    {
        var services = App.Services;
        var settings = services.Settings;

        _suppressToggles = true;
        try
        {
            HipsToggle.IsOn = settings.HipsEnabled;
            BlockToggle.IsOn = settings.HipsBlockCritical;
            RealtimeToggle.IsOn = settings.RealtimeProtectionEnabled;
            ScanActiveToggle.IsOn = settings.RealtimeScanActiveProcesses;
            AutoTerminateToggle.IsOn = settings.AutoTerminateProcesses;
            BlockInjectionToggle.IsOn = settings.RealtimeBlockInjection;
            BlockRegistryToggle.IsOn = settings.RealtimeBlockRegistry;
            IdleScanToggle.IsOn = settings.IdleScanEnabled;
            AutoDeleteP7bToggle.IsOn = settings.AutoDeleteMaliciousP7b;
            FirewallBlockToggle.IsOn = settings.FirewallAutoBlockEnabled;
            SandboxToggle.IsOn = settings.SandboxEnabled;
            SandboxRemediateToggle.IsOn = settings.SandboxAutoRemediate;
            NotificationsToggle.IsOn = settings.NotificationsEnabled;
            AutoStartToggle.IsOn = settings.AutoStartEnabled;
        }
        finally
        {
            _suppressToggles = false;
        }

        _suppressTheme = true;
        try
        {
            ThemeBox.SelectedIndex = settings.Theme switch
            {
                AppThemePreference.Light => 1,
                AppThemePreference.Dark => 2,
                _ => 0
            };
        }
        finally
        {
            _suppressTheme = false;
        }

        MaxFileSizeBox.Value = Math.Round(Math.Clamp(settings.MaxFileSizeBytes, 1024 * 1024, 2L * 1024 * 1024 * 1024) / 1048576d, 0);
        DefaultExclusionsToggle.IsOn = settings.UseDefaultExclusions;
        ExclusionsBox.Text = string.Join(Environment.NewLine, settings.Exclusions);
        AllowedHashesBox.Text = string.Join(Environment.NewLine, settings.AllowedHashes);
        ElevationInfo.IsOpen = !ElevationHelper.IsElevated;

        DataRootText.Text = "数据目录：" + services.DataRoot;
        SettingsFileText.Text = "设置文件：" + Path.Combine(services.DataRoot, "settings.json");
        VersionText.Text = $"NDAS {AppServices.ProductVersion} · 引擎 {AegisScanner.EngineVersion}";
        RefreshStatus();
    }

    private void RefreshStatus()
    {
        if (!_attached)
        {
            return;
        }

        var services = App.Services;
        var status = services.HipsStatus;
        UpdateSandboxStatus(services, status);
        RealtimeOffWarning.Visibility = services.IsInitialized && !services.Settings.RealtimeProtectionEnabled
            ? Visibility.Visible
            : Visibility.Collapsed;
        RealtimeStatusText.Text = !services.IsInitialized
            ? "安全引擎正在初始化。"
            : services.Settings.RealtimeProtectionEnabled
                ? services.UseService
                    ? "已启用：由 LocalSystem 防护服务扫描新启动程序、活动程序和桌面/下载新增文件。"
                    : "已启用：新启动程序和活动程序会做启发式扫描。"
                : "实时防护已关闭。";
        AutoStartStatusText.Text = !services.IsInitialized
            ? "—"
            : AutoStartService.IsEnabled()
                ? "已注册登录启动（--background，隐藏到托盘运行）。"
                : "未注册登录启动。";

        if (!services.IsInitialized)
        {
            StatusText.Text = "不可用";
            MonitorText.Text = services.HipsStartError ?? services.InitializationError ?? "安全引擎正在初始化。";
            EventCountText.Text = "0";
            CriticalCountText.Text = "0";
            LastErrorText.Text = services.HipsLastError ?? "—";
            EventList.ItemsSource = null;
            EventList.Visibility = Visibility.Collapsed;
            EmptyEventsPanel.Visibility = Visibility.Visible;
            return;
        }

        StatusText.Text = status?.HipsRunning == true
            ? "监控中"
            : services.Settings.HipsEnabled ? "未运行" : "已停用";
        MonitorText.Text = status is null
            ? "HIPS 尚未初始化。"
            : $"进程 {(status.ProcessMonitoringActive ? "开" : "关")} · 文件 {(status.FileMonitoringActive ? "开" : "关")} · 注册表 {(status.RegistryMonitoringActive ? "开" : "关")}"
              + (services.UseService ? " · LocalSystem 服务" : string.Empty);
        LastErrorText.Text = status?.LastError is { Length: > 0 } error
            ? "错误：" + error
            : services.HipsStartError ?? (services.UseService ? "由 NDAS 防护服务（LocalSystem）提供保护。" : "行为监控只记录本机事件。");
        IdleScanStatusText.Text = !services.UseService
            ? "闲时扫描：需要安装并运行 NDAS 防护服务。"
            : status is null
                ? "闲时扫描：—"
                : !status.IdleScanEnabled
                    ? "闲时扫描：已关闭。"
                    : status.IdleScanIdleMinutes <= 0
                        ? "闲时扫描：需要将 NDAS 防护服务升级到 0.0.2.0a。"
                        : status.IdleScanActive
                            ? "闲时扫描：正在扫描（系统空闲中）。"
                            : status.LastIdleScanAt is { } lastScan
                                ? $"闲时扫描：上次 {lastScan.ToLocalTime():MM-dd HH:mm}，扫描 {status.LastIdleScanFiles:N0} 个文件、发现 {status.LastIdleScanThreats:N0} 项。"
                                : $"闲时扫描：等待系统空闲 {status.IdleScanIdleMinutes} 分钟。";
        SignatureSourceText.Text = services.Signatures is null
            ? "安全智能：尚未加载"
            : "安全智能来源：" + services.Signatures.Source;

        var recent = services.HipsEvents;
        EventCountText.Text = services.HipsEventCount.ToString("N0");
        CriticalCountText.Text = recent.Count(hipsEvent => hipsEvent.Severity == HipsSeverity.Critical).ToString("N0");

        var rows = recent.Select(HipsEventRow.From).ToArray();
        EventList.ItemsSource = rows;
        EventList.Visibility = rows.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyEventsPanel.Visibility = rows.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateSandboxStatus(AppServices services, Aegis.Core.Service.ServiceStatus? status)
    {
        if (!services.IsInitialized)
        {
            SandboxStatusText.Text = "沙箱分析：安全引擎正在初始化。";
            return;
        }

        if (!services.UseService)
        {
            SandboxStatusText.Text = "沙箱分析：需要安装并运行 NDAS 防护服务（由 LocalSystem 服务执行）。";
            return;
        }

        if (status is null)
        {
            SandboxStatusText.Text = "沙箱分析：—";
            return;
        }

        if (!status.SandboxSupported)
        {
            SandboxStatusText.Text = "沙箱分析：需要将 NDAS 防护服务升级到 0.0.4.0a。";
            return;
        }

        if (!status.SandboxEnabled)
        {
            SandboxStatusText.Text = "沙箱分析：已关闭。";
            return;
        }

        if (!status.SandboxAvailable)
        {
            SandboxStatusText.Text = "沙箱分析：组件不可用"
                                     + (status.SandboxLastError is { Length: > 0 } error ? "（" + error + "）" : "。");
            return;
        }

        var parts = new List<string> { "引擎 " + status.SandboxEngineVersion };
        if (status.SandboxAnalyzing)
        {
            parts.Add("正在分析");
        }
        else if (status.SandboxQueueDepth > 0)
        {
            parts.Add($"排队 {status.SandboxQueueDepth}");
        }

        parts.Add($"已分析 {status.SandboxAnalyzed:N0}");
        parts.Add($"判定恶意 {status.SandboxMalicious:N0}");
        var text = "沙箱分析：" + string.Join(" · ", parts);
        if (status.SandboxLastAt is { } lastAt)
        {
            var path = string.IsNullOrWhiteSpace(status.SandboxLastPath)
                ? string.Empty
                : " " + Path.GetFileName(status.SandboxLastPath);
            text += $"\n最近 {lastAt.ToLocalTime():MM-dd HH:mm}{path} · {status.SandboxLastVerdict}（评分 {status.SandboxLastScore}）";
        }

        if (status.SandboxLastError is { Length: > 0 } lastError)
        {
            text += "\n错误：" + lastError;
        }

        SandboxStatusText.Text = text;
    }

    private async void SandboxToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || SandboxToggle.IsOn == App.Services.Settings.SandboxEnabled)
        {
            return;
        }

        var enabled = SandboxToggle.IsOn;
        try
        {
            await App.Services.SetSandboxEnabledAsync(enabled);
            ShowSandboxInfo(InfoBarSeverity.Informational,
                enabled ? "高熵样本沙箱分析已开启" : "高熵样本沙箱分析已关闭",
                enabled
                    ? "实时/闲时扫描发现高熵未知 PE 时，会排队交给内置 Speakeasy 模拟器做行为分析。"
                    : "高熵未知样本不再提交沙箱，只按本地启发式处理。");
        }
        catch (Exception exception)
        {
            ShowSandboxInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(SandboxToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void SandboxRemediateToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready ||
            SandboxRemediateToggle.IsOn == App.Services.Settings.SandboxAutoRemediate)
        {
            return;
        }

        var enabled = SandboxRemediateToggle.IsOn;
        try
        {
            await App.Services.SetSandboxAutoRemediateAsync(enabled);
            ShowSandboxInfo(enabled ? InfoBarSeverity.Warning : InfoBarSeverity.Informational,
                enabled ? "沙箱自动处置已开启" : "沙箱结果只告警",
                enabled
                    ? "沙箱判定恶意后会自动锁定文件、终止关联进程并封禁已知恶意网络指标。"
                    : "沙箱判定恶意时只记录事件，不自动锁定/终止。");
        }
        catch (Exception exception)
        {
            ShowSandboxInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(SandboxRemediateToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void HipsToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || HipsToggle.IsOn == App.Services.Settings.HipsEnabled)
        {
            return;
        }

        var enabled = HipsToggle.IsOn;
        try
        {
            await App.Services.SetHipsEnabledAsync(enabled);
            ShowInfo(InfoBarSeverity.Success, enabled ? "HIPS 已启用" : "HIPS 已停用",
                enabled ? "正在监控进程、文件和自启动项。" : "行为事件不再产生。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "切换失败", exception.Message);
            RevertToggle(HipsToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void BlockToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || BlockToggle.IsOn == App.Services.Settings.HipsBlockCritical)
        {
            return;
        }

        var enabled = BlockToggle.IsOn;
        try
        {
            await App.Services.SetHipsBlockCriticalAsync(enabled);
            ShowInfo(enabled ? InfoBarSeverity.Warning : InfoBarSeverity.Informational,
                enabled ? "高危自动终止已开启" : "已切回仅告警",
                enabled ? "Critical 规则会尝试终止进程；系统目录和 NDAS 自身会被跳过。" : "HIPS 只记录事件，不终止进程。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(BlockToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void RealtimeToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || RealtimeToggle.IsOn == App.Services.Settings.RealtimeProtectionEnabled)
        {
            return;
        }

        var enabled = RealtimeToggle.IsOn;
        try
        {
            await App.Services.SetRealtimeProtectionEnabledAsync(enabled);
            ShowRealtimeInfo(enabled ? InfoBarSeverity.Success : InfoBarSeverity.Informational,
                enabled ? "实时防护已启用" : "实时防护已关闭",
                enabled ? "新启动程序和活动程序会做启发式扫描。" : "不再实时扫描进程。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "切换失败", exception.Message);
            RevertToggle(RealtimeToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void ScanActiveToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || ScanActiveToggle.IsOn == App.Services.Settings.RealtimeScanActiveProcesses)
        {
            return;
        }

        var enabled = ScanActiveToggle.IsOn;
        try
        {
            await App.Services.SetRealtimeScanActiveProcessesAsync(enabled);
            ShowRealtimeInfo(InfoBarSeverity.Informational, enabled ? "活动程序扫描已开启" : "活动程序扫描已关闭",
                enabled ? "会扫描新启动和当前活动的用户程序。" : "只监控行为，不主动扫描进程。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(ScanActiveToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void AutoTerminateToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || AutoTerminateToggle.IsOn == App.Services.Settings.AutoTerminateProcesses)
        {
            return;
        }

        var enabled = AutoTerminateToggle.IsOn;
        try
        {
            await App.Services.SetAutoTerminateProcessesAsync(enabled);
            ShowRealtimeInfo(enabled ? InfoBarSeverity.Warning : InfoBarSeverity.Informational,
                enabled ? "恶意进程自动终止已开启" : "已切回仅告警",
                enabled ? "进程扫描命中强证据（哈希/路径 IOC/YARA）时会终止对应进程；系统关键进程与排除项会被跳过。" : "发现恶意程序时只告警并锁定文件，不终止进程。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(AutoTerminateToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void IdleScanToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || IdleScanToggle.IsOn == App.Services.Settings.IdleScanEnabled)
        {
            return;
        }

        var enabled = IdleScanToggle.IsOn;
        try
        {
            await App.Services.SetIdleScanEnabledAsync(enabled);
            ShowRealtimeInfo(InfoBarSeverity.Informational, enabled ? "闲时扫描已开启" : "闲时扫描已关闭",
                enabled ? "系统空闲约 10 分钟后会扫描用户桌面/下载/启动、公用桌面及 Program Files、ProgramData；用户恢复操作时自动中止。" : "不再在空闲时自动扫描。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(IdleScanToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void AutoDeleteP7bToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || AutoDeleteP7bToggle.IsOn == App.Services.Settings.AutoDeleteMaliciousP7b)
        {
            return;
        }

        var enabled = AutoDeleteP7bToggle.IsOn;
        try
        {
            await App.Services.SetAutoDeleteMaliciousP7bAsync(enabled);
            ShowRealtimeInfo(enabled ? InfoBarSeverity.Warning : InfoBarSeverity.Informational,
                enabled ? "恶意 p7b 自动删除已开启" : "p7b 仅告警",
                enabled ? "仅在策略签名无效/不受信任或包含 Enabled:Disabled 时备份并删除；可信签名策略与目录占位不动。" : "发现恶意 SiPolicy.p7b 时只告警，不删除文件。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(AutoDeleteP7bToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void FirewallBlockToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || FirewallBlockToggle.IsOn == App.Services.Settings.FirewallAutoBlockEnabled)
        {
            return;
        }

        var enabled = FirewallBlockToggle.IsOn;
        try
        {
            await App.Services.SetFirewallAutoBlockAsync(enabled);
            ShowRealtimeInfo(enabled ? InfoBarSeverity.Warning : InfoBarSeverity.Informational,
                enabled ? "网络指标自动封禁已开启" : "网络指标自动封禁已关闭",
                enabled ? "扫描命中恶意域名/IP 后，防护服务会写入 hosts 回环并创建 NDAS-IOC-* 防火墙规则；关闭后会自动删除 NDAS 自己创建的条目。" : "已删除 NDAS 自己创建的网络封禁条目，不再自动写 hosts/防火墙。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(FirewallBlockToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void BlockInjectionToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || BlockInjectionToggle.IsOn == App.Services.Settings.RealtimeBlockInjection)
        {
            return;
        }

        var enabled = BlockInjectionToggle.IsOn;
        try
        {
            await App.Services.SetRealtimeBlockInjectionAsync(enabled);
            ShowRealtimeInfo(InfoBarSeverity.Warning, enabled ? "注入/侧载拦截已开启" : "注入/侧载拦截已关闭",
                enabled ? "发现用户目录 DLL 注入/侧载时会尝试终止目标进程。" : "只告警，不终止进程。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(BlockInjectionToggle, !enabled);
        }
    }

    private async void BlockRegistryToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || BlockRegistryToggle.IsOn == App.Services.Settings.RealtimeBlockRegistry)
        {
            return;
        }

        var enabled = BlockRegistryToggle.IsOn;
        try
        {
            await App.Services.SetRealtimeBlockRegistryAsync(enabled);
            ShowRealtimeInfo(InfoBarSeverity.Warning, enabled ? "注册表自启动保护已开启" : "注册表自启动保护已关闭",
                enabled ? "可疑 Run/RunOnce 值会被回滚。" : "只告警，不回滚注册表。");
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(BlockRegistryToggle, !enabled);
        }
    }

    private async void NotificationsToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || NotificationsToggle.IsOn == App.Services.Settings.NotificationsEnabled)
        {
            return;
        }

        try
        {
            await App.Services.SetNotificationsEnabledAsync(NotificationsToggle.IsOn);
        }
        catch (Exception exception)
        {
            ShowRealtimeInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(NotificationsToggle, !NotificationsToggle.IsOn);
        }
    }

    private async void AutoStartToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggles || !_ready || AutoStartToggle.IsOn == App.Services.Settings.AutoStartEnabled)
        {
            return;
        }

        var enabled = AutoStartToggle.IsOn;
        try
        {
            await App.Services.SetAutoStartEnabledAsync(enabled);
            var actual = AutoStartService.IsEnabled();
            ShowAutoStartInfo(actual == enabled ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
                enabled ? "自动启动已设置" : "自动启动已关闭",
                actual == enabled ? "登录时会在后台托盘启动 NDAS 安全服务。" : "注册表写入失败，请检查权限。");
        }
        catch (Exception exception)
        {
            ShowAutoStartInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
            RevertToggle(AutoStartToggle, !enabled);
        }

        RefreshStatus();
    }

    private async void SaveScan_Click(object sender, RoutedEventArgs e)
    {
        if (double.IsNaN(MaxFileSizeBox.Value))
        {
            ShowScanInfo(InfoBarSeverity.Warning, "值无效", "请填写 1–2048 之间的单文件大小上限。");
            return;
        }

        try
        {
            var megabytes = Math.Clamp(MaxFileSizeBox.Value, 1, 2048);
            var bytes = (long)(megabytes * 1024 * 1024);
            var exclusions = ExclusionsBox.Text
                .Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .ToArray();
            var allowedHashes = AllowedHashesBox.Text
                .Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0)
                .ToArray();

            await App.Services.SaveScanSettingsAsync(bytes, DefaultExclusionsToggle.IsOn, exclusions, allowedHashes);
            ShowScanInfo(InfoBarSeverity.Success, "扫描设置已保存",
                $"单文件上限 {megabytes:F0} MiB，排除项 {App.Services.Settings.Exclusions.Count} 条，允许哈希 {App.Services.Settings.AllowedHashes.Count} 条。");
        }
        catch (Exception exception)
        {
            ShowScanInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
        }
    }

    private void RestartElevated_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ElevationHelper.RestartElevated();
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "提权失败", exception.Message);
        }
    }

    private void RefreshQuarantine()
    {
        var rows = App.Services.Quarantine.GetEntries()
            .Select(QuarantineRow.From)
            .ToArray();
        QuarantineList.ItemsSource = rows;
        QuarantineList.Visibility = rows.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyQuarantinePanel.Visibility = rows.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        QuarantineCountText.Text = $"{rows.Length} 项";
    }

    private async void RestoreQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not QuarantineRow row)
        {
            return;
        }

        if (!await ConfirmAsync("还原隔离文件",
                $"将 {row.FileName} 还原到：{row.OriginalPath}？原位置已有同名文件时会失败。", "还原"))
        {
            return;
        }

        try
        {
            await App.Services.Quarantine.RestoreAsync(row.Id);
            ShowQuarantineInfo(InfoBarSeverity.Success, "已还原", row.FileName + " 已还原到原位置。");
        }
        catch (Exception exception)
        {
            ShowQuarantineInfo(InfoBarSeverity.Error, "还原失败", exception.Message);
        }

        RefreshQuarantine();
    }

    private async void DeleteQuarantine_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not QuarantineRow row)
        {
            return;
        }

        if (!await ConfirmAsync("永久删除隔离文件",
                $"永久删除 {row.FileName}？此操作不可撤销，无法还原。", "永久删除"))
        {
            return;
        }

        try
        {
            await App.Services.Quarantine.DeleteAsync(row.Id);
            ShowQuarantineInfo(InfoBarSeverity.Informational, "已删除", row.FileName + " 已从隔离区永久删除。");
        }
        catch (Exception exception)
        {
            ShowQuarantineInfo(InfoBarSeverity.Error, "删除失败", exception.Message);
        }

        RefreshQuarantine();
    }

    private async Task<bool> ConfirmAsync(string title, string message, string primaryText)
    {
        var dialog = new ContentDialog
        {
            Title = title,
            Content = message,
            PrimaryButtonText = primaryText,
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot
        };
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async void Theme_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressTheme || !_themeReady || !App.Services.IsInitialized)
        {
            return;
        }

        var theme = ThemeBox.SelectedIndex switch
        {
            1 => AppThemePreference.Light,
            2 => AppThemePreference.Dark,
            _ => AppThemePreference.System
        };

        if (theme == App.Services.Settings.Theme)
        {
            return;
        }

        try
        {
            await App.Services.SetThemeAsync(theme);
        }
        catch (Exception exception)
        {
            ShowScanInfo(InfoBarSeverity.Error, "主题切换失败", exception.Message);
        }
    }

    private void RevertToggle(ToggleSwitch toggle, bool value)
    {
        _suppressToggles = true;
        try
        {
            toggle.IsOn = value;
        }
        finally
        {
            _suppressToggles = false;
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        HipsInfo.Severity = severity;
        HipsInfo.Title = title;
        HipsInfo.Message = message;
        HipsInfo.IsOpen = true;
    }

    private void ShowSandboxInfo(InfoBarSeverity severity, string title, string message)
    {
        SandboxInfo.Severity = severity;
        SandboxInfo.Title = title;
        SandboxInfo.Message = message;
        SandboxInfo.IsOpen = true;
    }

    private void ShowRealtimeInfo(InfoBarSeverity severity, string title, string message)
    {
        RealtimeInfo.Severity = severity;
        RealtimeInfo.Title = title;
        RealtimeInfo.Message = message;
        RealtimeInfo.IsOpen = true;
    }

    private void ShowScanInfo(InfoBarSeverity severity, string title, string message)
    {
        ScanInfo.Severity = severity;
        ScanInfo.Title = title;
        ScanInfo.Message = message;
        ScanInfo.IsOpen = true;
    }

    private void ShowAutoStartInfo(InfoBarSeverity severity, string title, string message)
    {
        AutoStartInfo.Severity = severity;
        AutoStartInfo.Title = title;
        AutoStartInfo.Message = message;
        AutoStartInfo.IsOpen = true;
    }

    private void ShowQuarantineInfo(InfoBarSeverity severity, string title, string message)
    {
        QuarantineInfo.Severity = severity;
        QuarantineInfo.Title = title;
        QuarantineInfo.Message = message;
        QuarantineInfo.IsOpen = true;
    }
}

public sealed class QuarantineRow
{
    public required string Id { get; init; }
    public required string FileName { get; init; }
    public required string Detail { get; init; }
    public required string OriginalPath { get; init; }

    public static QuarantineRow From(QuarantineEntry entry) => new()
    {
        Id = entry.Id,
        FileName = entry.FileName,
        Detail = $"{VerdictText(entry.Verdict)} · {entry.ThreatName ?? "未知威胁"} · 评分 {entry.Score} · " +
                 $"{entry.QuarantinedAt.ToLocalTime():MM-dd HH:mm}",
        OriginalPath = entry.OriginalPath
    };

    private static string VerdictText(Aegis.Core.Models.ThreatVerdict verdict) => verdict switch
    {
        Aegis.Core.Models.ThreatVerdict.Malicious => "恶意",
        Aegis.Core.Models.ThreatVerdict.Pua => "PUA",
        Aegis.Core.Models.ThreatVerdict.Attention => "重点关注",
        Aegis.Core.Models.ThreatVerdict.Suspicious => "可疑",
        _ => verdict.ToString()
    };
}

public sealed class HipsEventRow
{
    public required string SeverityText { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required string RuleId { get; init; }
    public required string TimeText { get; init; }
    public required Brush BadgeBackground { get; init; }
    public required Brush BadgeForeground { get; init; }

    public static HipsEventRow From(HipsEvent hipsEvent)
    {
        var (backgroundKey, foregroundKey, fallbackBackground, fallbackForeground) = hipsEvent.Severity switch
        {
            HipsSeverity.Critical => ("AegisDangerSoftBrush", "AegisDangerTextBrush",
                Color.FromArgb(255, 253, 231, 233), Color.FromArgb(255, 138, 28, 16)),
            HipsSeverity.High => ("AegisWarningSoftBrush", "AegisWarningTextBrush",
                Color.FromArgb(255, 255, 244, 206), Color.FromArgb(255, 107, 64, 0)),
            HipsSeverity.Medium => ("AegisWarningSoftBrush", "AegisWarningTextBrush",
                Color.FromArgb(255, 255, 244, 206), Color.FromArgb(255, 107, 64, 0)),
            _ => ("AegisAccentSoftBrush", "AegisAccentTextBrush",
                Color.FromArgb(255, 232, 241, 251), Color.FromArgb(255, 15, 108, 189))
        };

        var detail = hipsEvent.Detail;
        if (!string.IsNullOrWhiteSpace(hipsEvent.CommandLine))
        {
            detail += " 命令行：" + hipsEvent.CommandLine;
        }
        else if (!string.IsNullOrWhiteSpace(hipsEvent.ProcessPath))
        {
            detail += " 进程：" + hipsEvent.ProcessPath;
        }

        if (hipsEvent.Blocked)
        {
            detail += " · 已拦截";
        }

        return new HipsEventRow
        {
            SeverityText = hipsEvent.Severity switch
            {
                HipsSeverity.Critical => "严重",
                HipsSeverity.High => "高危",
                HipsSeverity.Medium => "中危",
                HipsSeverity.Low => "低危",
                _ => "信息"
            },
            Title = hipsEvent.Title,
            Detail = detail,
            RuleId = hipsEvent.RuleId,
            TimeText = hipsEvent.Timestamp.ToLocalTime().ToString("HH:mm:ss"),
            BadgeBackground = BrushResource(backgroundKey, fallbackBackground),
            BadgeForeground = BrushResource(foregroundKey, fallbackForeground)
        };
    }

    private static Brush BrushResource(string key, Color fallback)
    {
        if (Application.Current.Resources.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }

        return new SolidColorBrush(fallback);
    }
}
