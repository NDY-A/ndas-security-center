using Aegis.App.Services;
using Aegis.Core.Models;
using Aegis.Core.Scanning;
using Aegis.Hips;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage.Pickers;
using Windows.UI;

namespace Aegis.App.Views;

public sealed partial class ScanPage : Page
{
    private ScanJob? _activeJob;
    private bool _subscribed;
    private bool _autoStart;

    public ScanPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        _autoStart = e.Parameter is string value && string.Equals(value, "quick", StringComparison.OrdinalIgnoreCase);
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
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

        RefreshPage();
        RefreshScanState();
        SyncJobs();
        TryAutoStart();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_subscribed)
        {
            App.Services.StateChanged -= OnStateChanged;
            _subscribed = false;
        }

        DetachJob();
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            RefreshPage();
            RefreshScanState();
            SyncJobs();
            TryAutoStart();
        });
    }

    private void TryAutoStart()
    {
        if (!_autoStart || !App.Services.IsInitialized || _activeJob is { State: ScanJobState.Queued or ScanJobState.Running })
        {
            return;
        }

        _autoStart = false;
        ProfileSelector.SelectedIndex = 0;
        StartSelectedScan();
        ScanCard.StartBringIntoView();
    }

    private void RefreshPage()
    {
        var services = App.Services;
        if (!services.IsInitialized)
        {
            ScanHeroTitle.Text = services.InitializationError is null ? "正在初始化安全引擎…" : "安全引擎初始化失败";
            ScanHeroDetail.Text = services.InitializationError ?? "正在加载本地病毒库和启发式规则。";
            ScanBadgeBorder.Background = BrushResource("AegisSuccessBrush", Color.FromArgb(255, 16, 124, 16));
            ScanBadgeIcon.Glyph = "";
            ScanRealtimeText.Text = "等待引擎初始化。";
            ScanDbStateText.Text = "尚未加载";
            ScanDbVersionText.Text = "—";
            ScanQuarantineText.Text = "尚未加载";
            return;
        }

        var last = services.Coordinator.GetRecent(20)
            .Where(job => job.Summary is not null)
            .OrderByDescending(job => job.Summary!.CompletedAt)
            .FirstOrDefault();
        var active = services.Coordinator.GetRunning().FirstOrDefault();
        var scanThreats = (active?.Progress?.Detections ?? 0) > 0 ||
                          (last?.Summary is { } summaryForThreats && HasOutstandingThreats(summaryForThreats));
        var loggedThreat = services.ActiveThreat is not null ||
                           services.HipsEvents.Any(hipsEvent => hipsEvent.Severity == HipsSeverity.Critical);
        var hasThreats = scanThreats || loggedThreat;

        ScanBadgeBorder.Background = hasThreats
            ? BrushResource("AegisDangerBrush", Color.FromArgb(255, 196, 43, 28))
            : BrushResource("AegisSuccessBrush", Color.FromArgb(255, 16, 124, 16));
        ScanBadgeIcon.Glyph = hasThreats ? "" : "";
        StartButton.Content = hasThreats ? "执行操作" : "快速扫描";

        if (active is not null)
        {
            ScanHeroTitle.Text = active.State == ScanJobState.Queued ? "扫描任务排队中" : "正在扫描本机";
            ScanHeroDetail.Text = active.Progress is null
                ? "引擎正在准备扫描。"
                : $"已扫描 {active.Progress.FilesScanned:N0} 个文件，发现 {active.Progress.Detections} 个风险项。";
        }
        else if (hasThreats)
        {
            ScanHeroTitle.Text = "发现威胁";
            ScanHeroDetail.Text = scanThreats
                ? "请检查下方保护历史记录中的风险项。"
                : "防护日志中已确认威胁，请检查保护历史记录。";
        }
        else
        {
            ScanHeroTitle.Text = "无需执行任何操作";
            ScanHeroDetail.Text = "你的设备受到 NDAS 保护。";
        }

        var signatures = services.Signatures;
        ScanDbStateText.Text = signatures is null
            ? "尚未加载"
            : signatures.IsSeed ? "病毒库可用（内置种子库）。" : "病毒库是最新的。";
        ScanDbVersionText.Text = signatures is null ? "—" : $"病毒库 {signatures.Version}";
        ScanRealtimeText.Text = services.Settings.RealtimeProtectionEnabled
            ? services.HipsRunning ? "实时防护已开启，HIPS 正在监控。" : "实时防护已开启，HIPS 未运行。"
            : "实时防护已关闭，你的设备易受攻击。";

        var quarantined = services.Quarantine.GetEntries().Count();
        ScanQuarantineText.Text = quarantined > 0 ? $"{quarantined} 项隔离文件" : "隔离区为空。";
    }

    private void RefreshScanState()
    {
        if (!App.Services.IsInitialized)
        {
            StatusText.Text = App.Services.InitializationError ?? "正在初始化安全引擎…";
            StartButton.IsEnabled = false;
            CancelButton.IsEnabled = false;
            return;
        }

        if (_activeJob is null)
        {
            StatusText.Text = "选择范围后开始扫描。";
            StartButton.IsEnabled = true;
            CancelButton.IsEnabled = false;
        }

        UpdateProfileControls();
    }

    private void SyncJobs()
    {
        var target = App.Services.Coordinator.GetRunning().FirstOrDefault()
                     ?? App.Services.Coordinator.GetRecent(1).FirstOrDefault();
        if (target is not null && !ReferenceEquals(target, _activeJob))
        {
            AttachJob(target);
        }
    }

    private void BreadcrumbRoot_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("dashboard");

    private void NavigateUpdate_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("update");

    private void NavigateHips_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("hips");

    private void NavigateProviders_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("providers");

    private void NavigateHistory_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("history");

    private void ScrollToScanOptions_Click(object sender, RoutedEventArgs e) => ScanOptionsCard.StartBringIntoView();

    private void Profile_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CustomPathBox is null || BrowseButton is null)
        {
            return;
        }

        UpdateProfileControls();
    }

    private void UpdateProfileControls()
    {
        if (CustomPathBox is null || BrowseButton is null)
        {
            return;
        }

        var custom = ProfileSelector.SelectedIndex == 2;
        CustomPathBox.IsEnabled = custom;
        BrowseButton.IsEnabled = custom;
    }

    private async void Browse_Click(object sender, RoutedEventArgs e)
    {
        if (App.MainWindow is null)
        {
            return;
        }

        var picker = new FolderPicker
        {
            SuggestedStartLocation = PickerLocationId.Desktop
        };
        picker.FileTypeFilter.Add("*");
        WinRT.Interop.InitializeWithWindow.Initialize(
            picker,
            WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow));

        var folder = await picker.PickSingleFolderAsync();
        if (folder is not null)
        {
            CustomPathBox.Text = folder.Path;
        }
    }

    private void StartScan_Click(object sender, RoutedEventArgs e)
    {
        StartSelectedScan();
    }

    private void StartSelectedScan()
    {
        if (!App.Services.IsInitialized)
        {
            ShowInfo(InfoBarSeverity.Warning, "尚未就绪", App.Services.InitializationError ?? "安全引擎正在初始化。");
            return;
        }

        var profile = ProfileSelector.SelectedIndex switch
        {
            1 => ScanProfileKind.Full,
            2 => ScanProfileKind.Custom,
            _ => ScanProfileKind.Quick
        };
        var path = CustomPathBox.Text?.Trim();
        if (profile == ScanProfileKind.Custom && string.IsNullOrWhiteSpace(path))
        {
            ShowInfo(InfoBarSeverity.Warning, "需要路径", "自定义扫描需要填写文件或文件夹路径。");
            return;
        }

        try
        {
            var job = App.Services.StartScan(profile, path);
            ScanInfo.IsOpen = false;
            AttachJob(job);
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "无法启动扫描", exception.Message);
        }
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e)
    {
        _activeJob?.Cancel();
    }

    private void AttachJob(ScanJob job)
    {
        if (ReferenceEquals(_activeJob, job))
        {
            UpdateFromJob(job);
            return;
        }

        DetachJob();
        _activeJob = job;
        job.Changed += OnJobChanged;
        UpdateFromJob(job);
    }

    private void DetachJob()
    {
        if (_activeJob is null)
        {
            return;
        }

        _activeJob.Changed -= OnJobChanged;
        _activeJob = null;
    }

    private void OnJobChanged(object? sender, EventArgs e)
    {
        if (sender is ScanJob job)
        {
            DispatcherQueue.TryEnqueue(() => UpdateFromJob(job));
        }
    }

    private void UpdateFromJob(ScanJob job)
    {
        if (!ReferenceEquals(_activeJob, job))
        {
            return;
        }

        var running = job.State is ScanJobState.Queued or ScanJobState.Running;
        StartButton.IsEnabled = !running;
        CancelButton.IsEnabled = running;
        ScanProgressBar.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        ScanProgressBar.IsIndeterminate = true;

        StatusText.Text = job.State switch
        {
            ScanJobState.Queued => "扫描任务排队中…",
            ScanJobState.Running => "正在扫描…",
            ScanJobState.Completed => "扫描完成。",
            ScanJobState.Cancelled => "扫描已取消。",
            ScanJobState.Failed => "扫描失败。",
            _ => "准备中…"
        };

        ProgressTitle.Text = job.State switch
        {
            ScanJobState.Queued => "扫描排队中",
            ScanJobState.Running => "正在扫描",
            ScanJobState.Completed => "扫描完成",
            ScanJobState.Cancelled => "扫描已取消",
            ScanJobState.Failed => "扫描失败",
            _ => "准备中"
        };

        if (job.Progress is { } progress)
        {
            FilesScannedText.Text = progress.FilesScanned.ToString("N0");
            DetectionsText.Text = progress.Detections.ToString("N0");
            ProgressDetail.Text = string.IsNullOrWhiteSpace(progress.CurrentPath)
                ? "引擎正在整理结果…"
                : progress.CurrentPath;
        }
        else if (!running)
        {
            ProgressDetail.Text = job.State == ScanJobState.Queued ? "等待执行…" : "没有更多进度信息。";
        }

        if (job.Error is { } error)
        {
            ProgressDetail.Text = error;
            ShowInfo(InfoBarSeverity.Error, "扫描失败", error);
            return;
        }

        if (job.Summary is { } summary)
        {
            FilesScannedText.Text = summary.FilesScanned.ToString("N0");
            DetectionsText.Text = (summary.MaliciousCount + summary.SuspiciousCount).ToString("N0");
            ProgressDetail.Text = $"用时 {summary.Duration.TotalSeconds:F1} 秒 · 扫描 {summary.FilesScanned:N0} 个文件 · 病毒库 {summary.SignatureVersion}";

            var severity = summary.MaliciousCount > 0
                ? InfoBarSeverity.Error
                : summary.PuaCount > 0 || summary.AttentionCount > 0 || summary.SuspiciousCount > 0
                    ? InfoBarSeverity.Warning
                    : summary.Cancelled
                        ? InfoBarSeverity.Informational
                        : InfoBarSeverity.Success;
            ShowInfo(severity, summary.StatusText,
                $"扫描 {summary.FilesScanned:N0} 个文件，发现 {summary.MaliciousCount:N0} 个恶意项、{summary.PuaCount:N0} 个 PUA、{summary.AttentionCount:N0} 个重点关注项、{summary.SuspiciousCount:N0} 个可疑项。" +
                (summary.Detections.Count > 0 ? " 详情请查看“保护历史记录”。" : string.Empty));
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        ScanInfo.Severity = severity;
        ScanInfo.Title = title;
        ScanInfo.Message = message;
        ScanInfo.IsOpen = true;
    }

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

    private static Brush BrushResource(string key, Color fallback)
    {
        if (Application.Current.Resources.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }

        return new SolidColorBrush(fallback);
    }
}
