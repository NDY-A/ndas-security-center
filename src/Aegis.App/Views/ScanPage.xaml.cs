using Aegis.App.Services;
using Aegis.Core.Models;
using Aegis.Core.Scanning;
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

        RefreshState();

        var job = App.Services.Coordinator.GetRunning().FirstOrDefault()
                  ?? App.Services.Coordinator.GetRecent(1).FirstOrDefault();
        if (job is not null)
        {
            AttachJob(job);
        }

        if (_autoStart && App.Services.IsInitialized && _activeJob is null)
        {
            _autoStart = false;
            ProfileSelector.SelectedIndex = 0;
            StartSelectedScan();
        }
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
            RefreshState();
            if (_autoStart && App.Services.IsInitialized && _activeJob is null)
            {
                _autoStart = false;
                ProfileSelector.SelectedIndex = 0;
                StartSelectedScan();
            }
        });
    }

    private void RefreshState()
    {
        if (!App.Services.IsInitialized)
        {
            StatusText.Text = App.Services.InitializationError ?? "正在初始化安全引擎…";
            StartButton.IsEnabled = false;
            return;
        }

        if (_activeJob is null)
        {
            StatusText.Text = "选择范围后开始扫描。";
            StartButton.IsEnabled = true;
        }

        UpdateProfileControls();
    }

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

    private void BreadcrumbRoot_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("dashboard");

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

        if (job.Progress is { } progress)
        {
            FilesScannedText.Text = progress.FilesScanned.ToString("N0");
            DetectionsText.Text = progress.Detections.ToString("N0");
            SkippedText.Text = progress.Skipped.ToString("N0");
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
            ProgressTitle.Text = "扫描失败";
            ProgressDetail.Text = error;
            ShowInfo(InfoBarSeverity.Error, "扫描失败", error);
            return;
        }

        if (job.Summary is { } summary)
        {
            FilesScannedText.Text = summary.FilesScanned.ToString("N0");
            DetectionsText.Text = (summary.MaliciousCount + summary.SuspiciousCount).ToString("N0");
            SkippedText.Text = summary.FilesSkipped.ToString("N0");
            ProgressTitle.Text = summary.StatusText;
            ProgressDetail.Text = $"用时 {summary.Duration.TotalSeconds:F1} 秒 · 扫描 {summary.FilesScanned:N0} 个文件 · 病毒库 {summary.SignatureVersion}";

            var rows = summary.Detections
                .Select(ScanFindingRow.From)
                .ToArray();
            ResultsList.ItemsSource = rows;
            ResultsList.Visibility = rows.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
            EmptyResultsPanel.Visibility = rows.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

            var severity = summary.MaliciousCount > 0
                ? InfoBarSeverity.Error
                : summary.PuaCount > 0 || summary.AttentionCount > 0 || summary.SuspiciousCount > 0
                    ? InfoBarSeverity.Warning
                    : summary.Cancelled
                        ? InfoBarSeverity.Informational
                        : InfoBarSeverity.Success;
            ShowInfo(severity, summary.StatusText,
                $"扫描 {summary.FilesScanned:N0} 个文件，发现 {summary.MaliciousCount:N0} 个恶意项、{summary.PuaCount:N0} 个 PUA、{summary.AttentionCount:N0} 个重点关注项、{summary.SuspiciousCount:N0} 个可疑项。");
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        ScanInfo.Severity = severity;
        ScanInfo.Title = title;
        ScanInfo.Message = message;
        ScanInfo.IsOpen = true;
    }
}

public sealed class ScanFindingRow
{
    public required string VerdictText { get; init; }
    public required string Title { get; init; }
    public required string FilePath { get; init; }
    public required string Detail { get; init; }
    public required string ScoreText { get; init; }
    public required Brush BadgeBackground { get; init; }
    public required Brush BadgeForeground { get; init; }

    public static ScanFindingRow From(FileScanResult finding)
    {
        var detection = finding.Detections.FirstOrDefault();
        var malicious = finding.Verdict == ThreatVerdict.Malicious;
        var attention = finding.Verdict == ThreatVerdict.Attention;
        return new ScanFindingRow
        {
            VerdictText = finding.VerdictText,
            Title = finding.ThreatName ?? detection?.Name ?? "启发式发现",
            FilePath = finding.FilePath,
            Detail = detection is null
                ? string.Join(" · ", finding.Notes.Take(2))
                : $"{detection.RuleId} · {detection.Description}",
            ScoreText = $"评分 {finding.Score}",
            BadgeBackground = malicious
                ? BrushResource("AegisDangerSoftBrush", Color.FromArgb(255, 253, 231, 233))
                : attention
                    ? BrushResource("AegisAccentSoftBrush", Color.FromArgb(255, 232, 241, 251))
                    : BrushResource("AegisWarningSoftBrush", Color.FromArgb(255, 255, 244, 206)),
            BadgeForeground = malicious
                ? BrushResource("AegisDangerTextBrush", Color.FromArgb(255, 138, 28, 16))
                : attention
                    ? BrushResource("AegisAccentTextBrush", Color.FromArgb(255, 15, 108, 189))
                    : BrushResource("AegisWarningTextBrush", Color.FromArgb(255, 107, 64, 0))
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
