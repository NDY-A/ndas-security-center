using Aegis.App.Services;
using Aegis.Core.Models;
using Aegis.Core.Scanning;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Aegis.App.Views;

public sealed partial class ProtectionHistoryPage : Page
{
    private bool _subscribed;

    public ProtectionHistoryPage()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        RefreshHistory();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!_subscribed)
        {
            App.Services.StateChanged += OnStateChanged;
            App.Services.Coordinator.JobCompleted += OnJobCompleted;
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
                // 页面会展示初始化错误。
            }
        }

        RefreshHistory();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_subscribed)
        {
            App.Services.StateChanged -= OnStateChanged;
            App.Services.Coordinator.JobCompleted -= OnJobCompleted;
            _subscribed = false;
        }
    }

    private void OnStateChanged(object? sender, EventArgs e) =>
        DispatcherQueue.TryEnqueue(RefreshHistory);

    private void OnJobCompleted(object? sender, ScanJob job) =>
        DispatcherQueue.TryEnqueue(RefreshHistory);

    private void RefreshHistory()
    {
        var services = App.Services;
        if (!services.IsInitialized)
        {
            FindingsSummaryText.Text = services.InitializationError ?? "安全引擎正在初始化。";
            FindingsList.ItemsSource = null;
            FindingsList.Visibility = Visibility.Collapsed;
            EmptyFindingsPanel.Visibility = Visibility.Visible;
            EventsSummaryText.Text = "还没有主动防护事件。";
            EventsList.ItemsSource = null;
            EventsList.Visibility = Visibility.Collapsed;
            EmptyEventsPanel.Visibility = Visibility.Visible;
            return;
        }

        var findings = new List<ScanResultRow>();
        var scanCount = 0;
        foreach (var job in services.Coordinator.GetRecent(100)
                     .Where(job => job.Summary is not null)
                     .OrderByDescending(job => job.Summary!.CompletedAt))
        {
            var summary = job.Summary!;
            scanCount++;
            foreach (var finding in summary.Detections)
            {
                findings.Add(CreateRow(finding, summary.CompletedAt));
            }
        }

        FindingsList.ItemsSource = findings;
        FindingsList.Visibility = findings.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyFindingsPanel.Visibility = findings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        FindingsSummaryText.Text = scanCount == 0
            ? "尚未运行扫描。"
            : findings.Count == 0
                ? $"最近 {scanCount} 次扫描未发现威胁。"
                : $"最近 {scanCount} 次扫描共 {findings.Count} 个发现项。";

        var eventRows = services.HipsEvents.Select(HipsEventRow.From).ToArray();
        EventsList.ItemsSource = eventRows;
        EventsList.Visibility = eventRows.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        EmptyEventsPanel.Visibility = eventRows.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        EventsSummaryText.Text = eventRows.Length == 0
            ? "还没有主动防护事件。"
            : $"共 {eventRows.Length} 条事件。";
    }

    private static ScanResultRow CreateRow(FileScanResult finding, DateTimeOffset completedAt)
    {
        var row = ScanResultRow.From(finding, completedAt);
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

    private void BreadcrumbRoot_Click(object sender, RoutedEventArgs e) =>
        App.MainWindow?.NavigateTo("dashboard");

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        HistoryInfo.Severity = severity;
        HistoryInfo.Title = title;
        HistoryInfo.Message = message;
        HistoryInfo.IsOpen = true;
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
}
