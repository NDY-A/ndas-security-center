using Aegis.App.Services;
using Aegis.Core.Models;
using Aegis.Core.Signatures;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Aegis.App.Views;

public sealed partial class UpdatePage : Page
{
    private bool _subscribed;
    private bool _attached;
    private bool _updating;
    private bool _autoUpdateLoaded;
    private bool _cloudLoaded;
    private bool _suppressAutoUpdateToggle;
    private CancellationTokenSource? _cancellation;

    public UpdatePage()
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

        if (!_autoUpdateLoaded && App.Services.IsInitialized)
        {
            _autoUpdateLoaded = true;
            _suppressAutoUpdateToggle = true;
            try
            {
                AutoUpdateToggle.IsOn = App.Services.Settings.AutoUpdateEnabled;
            }
            finally
            {
                _suppressAutoUpdateToggle = false;
            }
        }

        RefreshCurrent();
    }

    private void BreadcrumbRoot_Click(object sender, RoutedEventArgs e) => App.MainWindow?.NavigateTo("dashboard");

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _attached = false;
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
            DispatcherQueue.TryEnqueue(RefreshCurrent);
        }
    }

    private void RefreshCurrent()
    {
        var services = App.Services;
        if (!_cloudLoaded && services.IsInitialized)
        {
            _cloudLoaded = true;
            LoadCloudSettings();
        }

        if (!services.IsInitialized)
        {
            VersionText.Text = "安全智能版本：—";
            CreatedText.Text = "版本创建时间：—";
            LastUpdatedText.Text = "上次更新时间：—";
            StateText.Text = services.InitializationError ?? "安全引擎正在初始化。";
            CountsText.Text = "—";
            SourceText.Text = "—";
            FreshnessInfo.IsOpen = false;
            UpdateButton.IsEnabled = false;
            return;
        }

        var signatures = services.Signatures;
        if (signatures is null)
        {
            VersionText.Text = "安全智能版本：—";
            CreatedText.Text = "版本创建时间：—";
            LastUpdatedText.Text = "上次更新时间：—";
            StateText.Text = "安全智能定义尚未加载。";
            CountsText.Text = "—";
            SourceText.Text = "—";
            FreshnessInfo.IsOpen = false;
            UpdateButton.IsEnabled = true;
            return;
        }

        VersionText.Text = "安全智能版本：" + signatures.Version;
        CreatedText.Text = "版本创建时间：" + signatures.FetchedAt.ToLocalTime().ToString("yyyy/M/d H:mm");
        var lastUpdate = services.LastSignatureCheckAt ?? signatures.FetchedAt;
        LastUpdatedText.Text = "上次更新时间：" + lastUpdate.ToLocalTime().ToString("yyyy/M/d H:mm");
        StateText.Text = signatures.IsSeed ? "当前使用内置种子库" : "当前安全智能已更新";
        CountsText.Text = $"{signatures.HashCount:N0} 哈希 · {signatures.DomainCount:N0} 域名 · {signatures.IpCount:N0} IP · {signatures.YaraRuleCount:N0} YARA"
                          + (signatures.Warnings.Count > 0 ? $" · {signatures.Warnings.Count} 条警告" : string.Empty);
        SourceText.Text = "来源：" + signatures.Source;

        var definitionIsFresh = (DateTimeOffset.UtcNow - signatures.FetchedAt).TotalDays <= 5;
        var checkSucceeded = services.LastSignatureCheckUpToDate ||
                             (services.LastSignatureCheckMessage?.StartsWith("安全智能已更新", StringComparison.Ordinal) ?? false) ||
                             (services.LastSignatureCheckMessage?.StartsWith("已更新到", StringComparison.Ordinal) ?? false);
        if (services.LastSignatureCheckAt is null)
        {
            FreshnessInfo.IsOpen = false;
        }
        else if (checkSucceeded && definitionIsFresh)
        {
            FreshnessInfo.Severity = InfoBarSeverity.Success;
            FreshnessInfo.Title = "安全智能是最新的。";
            FreshnessInfo.Message = string.Empty;
            FreshnessInfo.IsOpen = true;
        }
        else if (!definitionIsFresh)
        {
            FreshnessInfo.Severity = InfoBarSeverity.Warning;
            FreshnessInfo.Title = "安全智能可能已过期";
            FreshnessInfo.Message =
                $"上次定义 {signatures.FetchedAt.ToLocalTime():yyyy/M/d H:mm}，已超过 5 天，建议立即检查更新。";
            FreshnessInfo.IsOpen = true;
        }
        else
        {
            FreshnessInfo.Severity = InfoBarSeverity.Warning;
            FreshnessInfo.Title = "上次检查未完成";
            FreshnessInfo.Message = services.LastSignatureCheckMessage ?? "请重试检查更新。";
            FreshnessInfo.IsOpen = true;
        }

        LastCheckText.Text = services.LastSignatureCheckAt is { } checkedAt
            ? $"上次检查：{checkedAt.ToLocalTime():yyyy/M/d H:mm} · "
              + (services.LastSignatureCheckUpToDate ? "安全智能是最新的" : services.LastSignatureCheckMessage ?? "检查完成")
            : "尚未自动检查；开启后每 60 分钟检查一次。";
        if (!_updating)
        {
            StatusText.Text = string.Empty;
        }

        UpdateButton.IsEnabled = !_updating;
    }

    private async void AutoUpdateToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressAutoUpdateToggle || !_autoUpdateLoaded ||
            AutoUpdateToggle.IsOn == App.Services.Settings.AutoUpdateEnabled)
        {
            return;
        }

        try
        {
            await App.Services.SetAutoUpdateEnabledAsync(AutoUpdateToggle.IsOn);
            ShowInfo(InfoBarSeverity.Informational, "自动检查已" + (AutoUpdateToggle.IsOn ? "开启" : "关闭"),
                AutoUpdateToggle.IsOn ? "每 60 分钟检查一次安全智能；需要应用保持运行。" : "不会再自动检查安全智能。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
        }
    }

    private async void Update_Click(object sender, RoutedEventArgs e)
    {
        if (_updating)
        {
            return;
        }

        if (!App.Services.IsInitialized)
        {
            ShowInfo(InfoBarSeverity.Warning, "尚未就绪", "安全引擎还在初始化。");
            return;
        }

        _updating = true;
        _cancellation = new CancellationTokenSource();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cancellation.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        UpdateButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        UpdateProgressBar.Visibility = Visibility.Visible;
        UpdateProgressBar.Value = 0;
        UpdateInfo.IsOpen = false;
        StatusText.Text = "正在连接更新源…";

        var progress = new Progress<SignatureUpdateProgress>(update =>
        {
            if (!_attached)
            {
                return;
            }

            DispatcherQueue.TryEnqueue(() =>
            {
                if (!_attached)
                {
                    return;
                }

                StatusText.Text = update.Message;
                UpdateProgressBar.Value = Math.Clamp(update.Percent, 0, 100);
            });
        });

        try
        {
            var result = await App.Services.UpdateSignaturesAsync(progress, timeout.Token);
            if (_attached)
            {
                UpdateProgressBar.Value = result.Success ? 100 : UpdateProgressBar.Value;
                if (result.Success && result.IsUpToDate)
                {
                    StatusText.Text = "安全智能是最新的。";
                }
                else if (result.Success)
                {
                    ShowInfo(InfoBarSeverity.Success, "安全智能已更新", string.Empty);
                    StatusText.Text = "更新完成。";
                }
                else if (IsTimeoutFailure(result.Error))
                {
                    ShowInfo(InfoBarSeverity.Informational, "无可用更新", string.Empty);
                    StatusText.Text = "无可用更新";
                }
                else
                {
                    ShowInfo(InfoBarSeverity.Error, "更新失败", result.Error ?? "更新源没有返回有效数据。");
                    StatusText.Text = result.Error ?? "更新失败。";
                }
            }
        }
        catch (OperationCanceledException)
        {
            if (_attached)
            {
                if (_cancellation.IsCancellationRequested)
                {
                    ShowInfo(InfoBarSeverity.Informational, "已取消", "安全智能更新已取消，当前版本未受影响。");
                    StatusText.Text = "更新已取消。";
                }
                else
                {
                    ShowInfo(InfoBarSeverity.Informational, "无可用更新", string.Empty);
                    StatusText.Text = "无可用更新";
                }
            }
        }
        catch (Exception exception)
        {
            if (_attached)
            {
                ShowInfo(InfoBarSeverity.Error, "更新失败", exception.Message);
                StatusText.Text = exception.Message;
            }
        }
        finally
        {
            _updating = false;
            _cancellation?.Dispose();
            _cancellation = null;
            if (_attached)
            {
                CancelButton.IsEnabled = false;
                UpdateProgressBar.Visibility = Visibility.Collapsed;
                RefreshCurrent();
            }
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cancellation?.Cancel();
    }

    private void LoadCloudSettings()
    {
        var services = App.Services;
        var settings = services.Settings;

        CloudEnabledToggle.IsOn = settings.CloudEnabled;
        CloudEndpointBox.Text = settings.CloudEndpoint;
        CloudApiKeyBox.Password = string.Empty;
        ClearCloudKeyCheck.IsChecked = false;
        CloudPolicyBox.SelectedIndex = settings.CloudPolicy switch
        {
            CloudQueryPolicy.Never => 0,
            CloudQueryPolicy.ExecutablesAndScripts => 2,
            CloudQueryPolicy.All => 3,
            _ => 1
        };
        CloudKeyStateText.Text = services.HasCloudToken
            ? "云端密钥已保存（DPAPI，当前用户）。"
            : "云端密钥未保存。";
    }

    private async void SaveCloud_Click(object sender, RoutedEventArgs e)
    {
        if (!App.Services.IsInitialized)
        {
            ShowCloudInfo(InfoBarSeverity.Warning, "尚未就绪", "安全引擎还在初始化。");
            return;
        }

        try
        {
            var policy = CloudPolicyBox.SelectedIndex switch
            {
                0 => CloudQueryPolicy.Never,
                2 => CloudQueryPolicy.ExecutablesAndScripts,
                3 => CloudQueryPolicy.All,
                _ => CloudQueryPolicy.SuspiciousOnly
            };

            await App.Services.ApplyCloudSettingsAsync(
                CloudEnabledToggle.IsOn,
                CloudEndpointBox.Text,
                policy,
                CloudApiKeyBox.Password,
                ClearCloudKeyCheck.IsChecked == true);

            CloudApiKeyBox.Password = string.Empty;
            ClearCloudKeyCheck.IsChecked = false;
            LoadCloudSettings();
            ShowCloudInfo(InfoBarSeverity.Success, "云设置已保存",
                CloudEnabledToggle.IsOn ? "后续扫描会按策略查询云信誉。" : "云查询已关闭。");
        }
        catch (Exception exception)
        {
            ShowCloudInfo(InfoBarSeverity.Error, "保存失败", exception.Message);
        }
    }

    private async void TestCloud_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var result = await App.Services.TestCloudAsync();
            ShowCloudInfo(result.Ok ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
                result.Ok ? "云服务可用" : "云服务不可用", result.Message);
        }
        catch (Exception exception)
        {
            ShowCloudInfo(InfoBarSeverity.Error, "测试失败", exception.Message);
        }
    }

    private void ShowCloudInfo(InfoBarSeverity severity, string title, string message)
    {
        CloudInfo.Severity = severity;
        CloudInfo.Title = title;
        CloudInfo.Message = message;
        CloudInfo.IsOpen = true;
    }

    private static bool IsTimeoutFailure(string? message) =>
        !string.IsNullOrWhiteSpace(message) &&
        (message.Contains("超时", StringComparison.OrdinalIgnoreCase) ||
         message.Contains("timeout", StringComparison.OrdinalIgnoreCase) ||
         message.Contains("timed out", StringComparison.OrdinalIgnoreCase));

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        UpdateInfo.Severity = severity;
        UpdateInfo.Title = title;
        UpdateInfo.Message = message;
        UpdateInfo.IsOpen = true;
    }
}
