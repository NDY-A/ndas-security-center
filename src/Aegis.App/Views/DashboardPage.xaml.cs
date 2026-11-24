using Aegis.App.Services;
using Aegis.Core.Models;
using Aegis.Core.Scanning;
using Aegis.Core.Service;
using Aegis.Hips;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace Aegis.App.Views;

public sealed partial class DashboardPage : Page
{
    private bool _subscribed;

    public DashboardPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!_subscribed)
        {
            App.Services.StateChanged += OnStateChanged;
            App.PostRemediationScanRequested += OnPostRemediationRequested;
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

        RefreshDashboard();
        TryStartPostRemediationScan();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_subscribed)
        {
            App.Services.StateChanged -= OnStateChanged;
            App.PostRemediationScanRequested -= OnPostRemediationRequested;
            _subscribed = false;
        }
    }

    private void OnPostRemediationRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(TryStartPostRemediationScan);

    private void TryStartPostRemediationScan()
    {
        if (App.TryConsumePostRemediationScan())
        {
            App.MainWindow?.NavigateTo("scan", "quick");
        }
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            RefreshDashboard();
            TryStartPostRemediationScan();
        });
    }

    private void RefreshDashboard()
    {
        var services = App.Services;
        if (!services.IsInitialized)
        {
            StatusTitle.Text = services.InitializationError is null ? "正在初始化安全引擎…" : "安全引擎初始化失败";
            StatusSubtitle.Text = services.InitializationError ?? "正在加载本地病毒库和启发式规则。";
            SignatureVersionText.Text = "—";
            SignatureCountsText.Text = "尚未加载";
            CloudStateText.Text = "不可用";
            CloudDetailText.Text = "等待引擎初始化";
            AgentStateText.Text = "不可用";
            AgentEndpointText.Text = "等待引擎初始化";
            RealtimeStateText.Text = "不可用";
            RealtimeDetailText.Text = "等待引擎初始化";
            BigScanText.Text = "尚未运行扫描。";
            HistorySummaryText.Text = "尚未加载";
            BigQuarantineText.Text = "尚未加载";
            ThreatIcon.Foreground = BrushResource("AegisIconBrush", Color.FromArgb(255, 15, 108, 189));
            ThreatStatusBadge.Background = BrushResource("AegisSuccessBrush", Color.FromArgb(255, 16, 124, 16));
            ThreatStatusIcon.Glyph = "";
            RefreshContainment();
            return;
        }

        var signatures = services.Signatures;
        var last = services.Coordinator.GetRecent(20)
            .Where(job => job.Summary is not null)
            .OrderByDescending(job => job.Summary!.CompletedAt)
            .FirstOrDefault();
        var active = services.Coordinator.GetRunning().FirstOrDefault();
        var scanThreats = (active?.Progress?.Detections ?? 0) > 0 ||
                          (last?.Summary is { } summaryForThreats && HasOutstandingThreats(summaryForThreats));
        var loggedThreat = services.ActiveThreat is not null ||
                           services.HipsEvents.Any(IsLoggedThreat);
        var hasThreats = scanThreats || loggedThreat;

        ThreatIcon.Foreground = BrushResource("AegisIconBrush", Color.FromArgb(255, 15, 108, 189));
        ThreatStatusBadge.Background = hasThreats
            ? BrushResource("AegisDangerBrush", Color.FromArgb(255, 196, 43, 28))
            : BrushResource("AegisSuccessBrush", Color.FromArgb(255, 16, 124, 16));
        ThreatStatusIcon.Glyph = hasThreats ? "" : "";

        if (active is not null)
        {
            StatusTitle.Text = active.State == ScanJobState.Queued ? "扫描任务排队中" : "正在扫描本机";
            StatusSubtitle.Text = active.Progress is null
                ? "引擎正在准备扫描。"
                : $"已扫描 {active.Progress.FilesScanned:N0} 个文件，发现 {active.Progress.Detections} 个风险项。";
        }
        else
        {
            StatusTitle.Text = hasThreats ? "发现威胁" : "无需执行任何操作";
            StatusSubtitle.Text = hasThreats
                ? scanThreats
                    ? "请打开病毒和威胁防护页面查看风险项。"
                    : "防护日志中已确认威胁，请查看保护历史。"
                : "你的设备受到 NDAS 保护。";
        }

        SignatureVersionText.Text = Truncate(signatures?.Version ?? "—", 26);
        SignatureCountsText.Text = signatures is null
            ? "尚未加载"
            : $"{signatures.HashCount:N0} 哈希 · {signatures.DomainCount:N0} 域名 · {signatures.IpCount:N0} IP"
              + (signatures.IsSeed ? " · 内置种子库" : " · 已更新");

        var cloud = services.Cloud;
        CloudStateText.Text = cloud?.IsConfigured == true ? "已启用" : "未配置";
        CloudDetailText.Text = cloud?.IsConfigured == true
            ? "只上传文件 SHA-256，用于信誉查询。"
            : "在“保护更新”中配置云服务端点。";

        AgentStateText.Text = services.AgentApiRunning ? "监听中" : services.Settings.AgentApiEnabled ? "未运行" : "已停用";
        AgentEndpointText.Text = services.AgentApiRunning
            ? services.AgentApiBaseUrl
            : services.AgentApiLastError ?? "仅限本机回环接口";

        BigScanText.Text = last?.Summary is { } lastSummary
            ? FormatScanLine(lastSummary)
            : "尚未运行扫描。建议先运行一次快速扫描。";
        RealtimeStateText.Text = services.Settings.RealtimeProtectionEnabled ? "已开启" : "已关闭";
        RealtimeDetailText.Text = services.Settings.RealtimeProtectionEnabled
            ? services.HipsRunning ? "HIPS 正在监控进程、文件与注册表。" : "实时防护已开启，HIPS 未运行。"
            : "实时防护已关闭，你的设备易受攻击。";

        var criticalEvents = services.HipsEvents.Count(hipsEvent => hipsEvent.Severity == HipsSeverity.Critical);
        HistorySummaryText.Text = services.HipsEventCount > 0
            ? $"{services.HipsEventCount:N0} 条事件 · {criticalEvents:N0} 条严重"
            : "暂无防护事件。";

        var quarantined = services.Quarantine.GetEntries().Count();
        BigQuarantineText.Text = quarantined > 0 ? $"{quarantined} 项隔离文件" : "隔离区为空。";

        RefreshContainment();
    }

    private void RefreshContainment()
    {
        var services = App.Services;
        var threat = services.ActiveThreat;
        var containment = services.ContainmentStatus;
        var threatRunning = threat?.ProcessStillRunning == true;
        var active = containment?.Active == true;
        var hasRun = containment is not null && containment.State != ContainmentStates.Idle;

        if (!threatRunning && !active && !hasRun)
        {
            ContainmentCard.Visibility = Visibility.Collapsed;
            return;
        }

        ContainmentCard.Visibility = Visibility.Visible;
        ContainmentButton.Visibility = threatRunning && !active ? Visibility.Visible : Visibility.Collapsed;
        AbortContainmentButton.Visibility = active ? Visibility.Visible : Visibility.Collapsed;

        if (threat is not null)
        {
            ThreatTitleText.Text = string.IsNullOrWhiteSpace(threat.ThreatName)
                ? "检测到活动恶意软件"
                : threat.ThreatName;
            ThreatDetailText.Text =
                $"{threat.ProcessName}（PID {threat.ProcessId}）· {threat.ProcessPath}\n"
                + $"{threat.Evidence} · 检测于 {threat.DetectedAt:HH:mm:ss}";
        }
        else
        {
            ThreatTitleText.Text = "高威胁强力清除";
            ThreatDetailText.Text = "强力清除流程进行中。";
        }

        var supported = services.ContainmentSupported;
        ContainmentButton.IsEnabled = supported;
        ContainmentButton.Content = supported ? "启动高威胁强力清除" : "需要防护服务";
        ContainmentHintText.Text = supported
            ? "强力清除只针对正在运行的活动恶意软件。执行时会关闭当前会话中所有非系统必需进程（未保存的工作会丢失），持续清扫新进程，扫描系统关键位置，备份并修复一次引导，完成后强制关机；下次登录会自动打开 NDAS 并快速扫描。"
            : "高威胁强力清除需要 NDAS 防护服务（LocalSystem）。当前为本地模式，无法启动。";

        if (hasRun)
        {
            ContainmentProgressPanel.Visibility = Visibility.Visible;
            ContainmentPhaseText.Text = string.IsNullOrWhiteSpace(containment!.Phase) ? "处理中…" : containment.Phase;
            ContainmentMetricsText.Text =
                $"关键文件 {containment.CriticalFilesScanned:N0} · 处置 {containment.ThreatsRemediated:N0} · "
                + $"终止进程 {containment.TerminatedProcesses:N0} · 锁定清扫 {containment.GuardSweepKills:N0}";
            var lastAction = containment.Actions.Count > 0
                ? containment.Actions[^1]
                : containment.LastError ?? string.Empty;
            ContainmentActionText.Text = lastAction;
            ContainmentProgressBar.IsIndeterminate = active;
        }
        else
        {
            ContainmentProgressPanel.Visibility = Visibility.Collapsed;
        }
    }

    private async void StartContainment_Click(object sender, RoutedEventArgs e)
    {
        if (!App.Services.ContainmentSupported)
        {
            ShowInfo(InfoBarSeverity.Warning, "需要防护服务",
                "高威胁强力清除需要 NDAS 防护服务（LocalSystem）。");
            return;
        }

        var threat = App.Services.ActiveThreat;
        if (threat is null || !threat.ProcessStillRunning)
        {
            ShowInfo(InfoBarSeverity.Warning, "没有活动威胁",
                "当前没有正在运行的活动恶意软件，强力清除已取消。");
            RefreshDashboard();
            return;
        }

        if (!await ConfirmContainmentAsync(threat))
        {
            return;
        }

        if (!ElevationHelper.IsElevated)
        {
            bool launched;
            try
            {
                launched = ElevationHelper.TryLaunchContainRequest();
            }
            catch (Exception exception)
            {
                ShowInfo(InfoBarSeverity.Error, "无法请求管理员权限", exception.Message);
                return;
            }

            ShowInfo(launched ? InfoBarSeverity.Informational : InfoBarSeverity.Warning,
                launched ? "等待管理员授权" : "已取消",
                launched
                    ? "已请求管理员权限，允许后会自动开始强力清除。"
                    : "未获得管理员授权，强力清除没有启动。");
            return;
        }

        try
        {
            await App.Services.StartContainmentAsync();
            ShowInfo(InfoBarSeverity.Informational, "强力清除已启动",
                "正在关闭非系统必需进程并扫描系统关键位置。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "无法启动强力清除", exception.Message);
        }

        RefreshDashboard();
    }

    private async void AbortContainment_Click(object sender, RoutedEventArgs e)
    {
        if (!await ConfirmAsync("取消强力清除",
                "取消后会解除进程锁定；已完成的扫描和引导修复不会回滚，也不会强制关机。", "取消清除"))
        {
            return;
        }

        try
        {
            await App.Services.AbortContainmentAsync();
            ShowInfo(InfoBarSeverity.Informational, "已取消", "强力清除已取消，进程锁定已解除。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "无法取消强力清除", exception.Message);
        }

        RefreshDashboard();
    }

    private async Task<bool> ConfirmContainmentAsync(ServiceThreatIncident threat)
    {
        var acknowledge = new CheckBox
        {
            Content = "我明白将关闭当前会话中所有非系统必需的用户程序，未保存的工作会立即丢失。",
            Margin = new Thickness(0, 12, 0, 0)
        };
        var content = new StackPanel { Spacing = 8 };
        content.Children.Add(new TextBlock
        {
            Text = $"即将对 {threat.ProcessName}（PID {threat.ProcessId}）执行高威胁强力清除：",
            TextWrapping = TextWrapping.Wrap
        });
        content.Children.Add(new TextBlock
        {
            Text = "• 关闭当前会话中所有非系统必需进程，并持续清扫新启动的进程（用户态尽力而为，不是内核级拦截）。\n"
                   + "• 扫描启动项、驱动目录、系统目录近期可执行文件、ProgramData 与临时目录。\n"
                   + "• 备份 BCD 并修复一次引导，不触碰 MBR 和其他系统的引导项。\n"
                   + "• 完成后强制关机；下次登录会自动打开 NDAS 并快速扫描。",
            TextWrapping = TextWrapping.Wrap
        });
        content.Children.Add(acknowledge);

        var dialog = new ContentDialog
        {
            Title = "高威胁强力清除",
            Content = content,
            PrimaryButtonText = "开始强力清除",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
            IsPrimaryButtonEnabled = false,
            XamlRoot = XamlRoot
        };
        acknowledge.Checked += (_, _) => dialog.IsPrimaryButtonEnabled = true;
        acknowledge.Unchecked += (_, _) => dialog.IsPrimaryButtonEnabled = false;
        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private void QuickScan_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("scan", "quick");

    private void NavigateUpdate_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("update");

    private void NavigateHips_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("hips");

    private void NavigateHistory_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("history");

    private void NavigateAutomation_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("automation");

    private void NavigateScan_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("scan");

    private void StatusCard_Tapped(object sender, TappedRoutedEventArgs e)
    {
        if (IsInsideCardButton(e.OriginalSource) || FindTaggedCard(e.OriginalSource) is not { Tag: string tag })
        {
            return;
        }

        switch (tag)
        {
            case "update":
                App.MainWindow?.NavigateTo("update");
                break;
            case "hips":
                App.MainWindow?.NavigateTo("hips");
                break;
            case "history":
                App.MainWindow?.NavigateTo("history");
                break;
            case "automation":
                App.MainWindow?.NavigateTo("automation");
                break;
            case "scan":
                App.MainWindow?.NavigateTo("scan");
                break;
        }
    }

    private static Border? FindTaggedCard(object? source)
    {
        var element = source as DependencyObject;
        while (element is not null)
        {
            if (element is Border { Tag: string })
            {
                return (Border)element;
            }

            element = VisualTreeHelper.GetParent(element);
        }

        return null;
    }

    private static bool IsInsideCardButton(object? source)
    {
        var element = source as DependencyObject;
        while (element is not null)
        {
            if (element is ButtonBase)
            {
                return true;
            }

            if (element is Border { Tag: string })
            {
                return false;
            }

            element = VisualTreeHelper.GetParent(element);
        }

        return false;
    }

    private static void ShowInfo(InfoBarSeverity severity, string title, string message) =>
        App.MainWindow?.ShowGlobalMessage(severity, title, message);

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

    private static bool IsLoggedThreat(HipsEvent hipsEvent) =>
        hipsEvent.Severity == HipsSeverity.Critical;

    private static bool HasOutstandingThreats(ScanSummary summary) =>
        summary.Detections.Any(IsOutstandingFinding);

    private static bool IsOutstandingFinding(FileScanResult finding)
    {
        if (finding.Verdict is not (ThreatVerdict.Malicious or ThreatVerdict.Pua or ThreatVerdict.Attention or ThreatVerdict.Suspicious))
        {
            return false;
        }

        if (App.Services.Settings.AllowedHashes.Contains(finding.Sha256, StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            return File.Exists(finding.FilePath);
        }
        catch
        {
            return true;
        }
    }

    private static string FormatScanLine(ScanSummary summary)
    {
        var local = summary.CompletedAt.ToLocalTime();
        var when = local.Date == DateTimeOffset.Now.Date ? $"今天 {local:HH:mm}" : $"{local:MM-dd HH:mm}";
        var parts = new List<string>();
        if (summary.MaliciousCount > 0) parts.Add($"{summary.MaliciousCount} 个恶意项");
        if (summary.PuaCount > 0) parts.Add($"{summary.PuaCount} 个 PUA");
        if (summary.AttentionCount > 0) parts.Add($"{summary.AttentionCount} 个重点关注");
        if (summary.SuspiciousCount > 0) parts.Add($"{summary.SuspiciousCount} 个可疑项");
        var result = summary.Cancelled ? "已取消" : parts.Count > 0 ? string.Join(" / ", parts) : "未发现威胁";
        return $"{when} · 扫描 {summary.FilesScanned:N0} 个文件 · {result}";
    }

    private static Brush BrushResource(string key, Color fallback)
    {
        if (Application.Current.Resources.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }

        return new SolidColorBrush(fallback);
    }

    private static string Truncate(string value, int length) => value.Length <= length ? value : value[..length] + "…";
}
