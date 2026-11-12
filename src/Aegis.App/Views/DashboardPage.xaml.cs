using System.ComponentModel;
using Aegis.App.Services;
using Aegis.Core.Models;
using Aegis.Core.Scanning;
using Aegis.Core.Service;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Storage.Pickers;
using Windows.UI;

namespace Aegis.App.Views;

public sealed partial class DashboardPage : Page
{
    private ScanJob? _activeJob;
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
        RefreshScanState();
        SyncJobs();
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

        DetachJob();
    }

    private void OnPostRemediationRequested(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(TryStartPostRemediationScan);

    private void TryStartPostRemediationScan()
    {
        if (!App.Services.IsInitialized || !App.TryConsumePostRemediationScan())
        {
            return;
        }

        if (_activeJob is { State: ScanJobState.Queued or ScanJobState.Running })
        {
            return;
        }

        ProfileSelector.SelectedIndex = 0;
        ShowInfo(InfoBarSeverity.Informational, "复查扫描",
            "强力清除完成后的自动复查扫描已启动。");
        StartSelectedScan();
        ScanCard.StartBringIntoView();
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            RefreshDashboard();
            RefreshScanState();
            SyncJobs();
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
            LastScanText.Text = "尚未运行扫描。";
            RefreshContainment();
            return;
        }

        var signatures = services.Signatures;
        var last = services.Coordinator.GetRecent(20)
            .Where(job => job.Summary is not null)
            .OrderByDescending(job => job.Summary!.CompletedAt)
            .FirstOrDefault();
        var active = services.Coordinator.GetRunning().FirstOrDefault();
        var hasThreats = (active?.Progress?.Detections ?? 0) > 0 ||
                         (last?.Summary is { } summaryForThreats && HasOutstandingThreats(summaryForThreats));

        HeroCard.Background = hasThreats
            ? BrushResource("AegisDangerHeroBrush", Color.FromArgb(255, 164, 38, 44))
            : BrushResource("AegisHeroBrush", Color.FromArgb(255, 15, 108, 189));
        HeroCheck.Visibility = hasThreats ? Visibility.Collapsed : Visibility.Visible;
        HeroAlert.Visibility = hasThreats ? Visibility.Visible : Visibility.Collapsed;
        HeroCheck.Stroke = new SolidColorBrush(Color.FromArgb(255, 124, 242, 155));
        HeroAlert.Stroke = new SolidColorBrush(Color.FromArgb(255, 255, 255, 255));

        if (active is not null)
        {
            StatusTitle.Text = active.State == ScanJobState.Queued ? "扫描任务排队中" : "正在扫描本机";
            StatusSubtitle.Text = active.Progress is null
                ? "引擎正在准备扫描。"
                : $"已扫描 {active.Progress.FilesScanned:N0} 个文件，发现 {active.Progress.Detections} 个风险项。";
        }
        else
        {
            StatusTitle.Text = "威胁和防护状态";
            StatusSubtitle.Text = hasThreats
                ? "发现威胁，请检查下方扫描结果中的风险项。"
                : "无需执行任何操作。";
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

        LastScanText.Text = last?.Summary is { } lastSummary
            ? FormatScanLine(lastSummary)
            : "尚未运行扫描。建议先运行一次快速扫描。";

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

    private void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        if (_activeJob is { State: ScanJobState.Queued or ScanJobState.Running })
        {
            ScanCard.StartBringIntoView();
            return;
        }

        ProfileSelector.SelectedIndex = 0;
        StartSelectedScan();
        if (_activeJob is not null)
        {
            ScanCard.StartBringIntoView();
        }
    }

    private void CheckUpdates_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("update");

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
            LastScanText.Text = FormatScanLine(summary);

            var rows = summary.Detections
                .Select(CreateRow)
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

    private async void QuarantineFinding_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ScanResultRow row)
        {
            return;
        }

        if (!await ConfirmAsync("隔离文件",
                $"将 {row.Result.FileName} 移入 NDAS 隔离区？可在“威胁和防护设置 > 隔离区”还原。", "隔离"))
        {
            return;
        }

        try
        {
            await App.Services.Quarantine.QuarantineAsync(row.Result);
            row.MarkHandled("已隔离");
            ShowInfo(InfoBarSeverity.Success, "已隔离", row.Result.FileName + " 已移入隔离区。");
            RefreshDashboard();
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "隔离失败", exception.Message);
        }
    }

    private async void DeleteFinding_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ScanResultRow row)
        {
            return;
        }

        if (!await ConfirmAsync("永久删除文件",
                $"永久删除 {row.Result.FileName}？此操作不可撤销，文件不会进入回收站。", "永久删除"))
        {
            return;
        }

        try
        {
            var attributes = File.GetAttributes(row.Result.FilePath);
            if ((attributes & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(row.Result.FilePath, attributes & ~FileAttributes.ReadOnly);
            }

            File.Delete(row.Result.FilePath);
            row.MarkHandled("已删除");
            ShowInfo(InfoBarSeverity.Informational, "已删除", row.Result.FileName + " 已永久删除。");
            RefreshDashboard();
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "删除失败", exception.Message);
        }
    }

    private async void AllowFinding_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ScanResultRow row)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(row.Result.Sha256))
        {
            ShowInfo(InfoBarSeverity.Warning, "无法允许", "这个发现项没有可用的 SHA-256。");
            return;
        }

        if (!await ConfirmAsync("允许此文件",
                $"将 {row.Result.FileName} 的 SHA-256 加入白名单？之后扫描和实时防护都会跳过此文件。", "允许"))
        {
            return;
        }

        try
        {
            await App.Services.AllowHashAsync(row.Result.Sha256);
            row.MarkHandled("已允许");
            ShowInfo(InfoBarSeverity.Success, "已加入白名单", row.Result.FileName + " 以后会被扫描和实时防护跳过。");
            RefreshDashboard();
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "加入白名单失败", exception.Message);
        }
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

    private static ScanResultRow CreateRow(FileScanResult finding)
    {
        var row = ScanResultRow.From(finding);
        if (App.Services.Settings.AllowedHashes.Contains(finding.Sha256, StringComparer.OrdinalIgnoreCase))
        {
            row.MarkHandled("已允许");
        }
        else if (!File.Exists(finding.FilePath))
        {
            row.MarkHandled("文件已不存在");
        }

        return row;
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

public sealed class ScanResultRow : INotifyPropertyChanged
{
    private string? _actionStatus;

    public required FileScanResult Result { get; init; }
    public required string VerdictText { get; init; }
    public required string Title { get; init; }
    public required string FilePath { get; init; }
    public required string Detail { get; init; }
    public required string ScoreText { get; init; }
    public required Brush BadgeBackground { get; init; }
    public required Brush BadgeForeground { get; init; }

    public string ActionStatus => _actionStatus ?? string.Empty;

    public Visibility ActionsVisibility => _actionStatus is null ? Visibility.Visible : Visibility.Collapsed;

    public Visibility StatusVisibility => _actionStatus is null ? Visibility.Collapsed : Visibility.Visible;

    public event PropertyChangedEventHandler? PropertyChanged;

    public void MarkHandled(string status)
    {
        _actionStatus = status;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ActionStatus)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(ActionsVisibility)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(StatusVisibility)));
    }

    public static ScanResultRow From(FileScanResult finding)
    {
        var detection = finding.Detections.FirstOrDefault();
        var malicious = finding.Verdict == ThreatVerdict.Malicious;
        var attention = finding.Verdict == ThreatVerdict.Attention;
        return new ScanResultRow
        {
            Result = finding,
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
