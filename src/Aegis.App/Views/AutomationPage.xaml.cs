using Aegis.Agent.Security;
using Aegis.App.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;

namespace Aegis.App.Views;

public sealed partial class AutomationPage : Page
{
    private bool _subscribed;
    private bool _attached;
    private bool _ready;
    private bool _suppressToggle;

    public AutomationPage()
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
        await RefreshAsync();
    }

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
            DispatcherQueue.TryEnqueue(() => _ = RefreshAsync());
        }
    }

    private async Task RefreshAsync()
    {
        if (!_attached)
        {
            return;
        }

        var services = App.Services;
        _suppressToggle = true;
        try
        {
            EnableToggle.IsOn = services.IsInitialized && services.Settings.AgentApiEnabled;
        }
        finally
        {
            _suppressToggle = false;
        }

        if (!services.IsInitialized)
        {
            StatusText.Text = "不可用";
            BaseUrlText.Text = services.InitializationError ?? "安全引擎正在初始化。";
            PortText.Text = "—";
            RequestsText.Text = "0";
            UptimeText.Text = "—";
            LastErrorText.Text = services.AgentApiLastError ?? "—";
            KeyHintText.Text = "—";
            KeyMetaText.Text = "—";
            return;
        }

        var api = services.AgentApi;
        StatusText.Text = services.AgentApiRunning ? "监听中" : services.Settings.AgentApiEnabled ? "未运行" : "已停用";
        BaseUrlText.Text = services.AgentApiRunning ? services.AgentApiBaseUrl : "接口当前没有监听。";
        PortText.Text = (api?.Port > 0 ? api.Port : services.Settings.AgentApiPort).ToString();
        RequestsText.Text = (api?.RequestCount ?? 0).ToString("N0");
        UptimeText.Text = FormatUptime(api?.Uptime ?? TimeSpan.Zero);
        LastErrorText.Text = services.AgentApiLastError is { Length: > 0 } error
            ? "错误：" + error
            : services.AgentApiRunning
                ? "仅接受本机回环请求；无 CORS，无分块请求体。"
                : "启用后才会监听回环端口。";

        var metadata = await services.GetAgentKeyMetadataAsync();
        if (!_attached)
        {
            return;
        }

        if (metadata is null)
        {
            KeyHintText.Text = "尚未生成密钥。";
            KeyMetaText.Text = "启用接口时会自动创建 DPAPI 保护的密钥。";
        }
        else
        {
            KeyHintText.Text = "aeg_agent_••••••••••••" + metadata.Hint;
            KeyMetaText.Text = $"KeyId {ShortId(metadata.KeyId)} · 创建 {metadata.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm} · 轮换 {metadata.RotatedAt.ToLocalTime():yyyy-MM-dd HH:mm}";
        }
    }

    private async void EnableToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggle || !_ready)
        {
            return;
        }

        var enabled = EnableToggle.IsOn;
        try
        {
            await App.Services.SetAgentApiEnabledAsync(enabled);
            ShowInfo(InfoBarSeverity.Success, enabled ? "接口已启用" : "接口已停用",
                enabled ? "本机 agent 可以通过 Bearer 密钥访问扫描接口。" : "回环端口已停止监听。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "切换失败", exception.Message);
            _suppressToggle = true;
            try
            {
                EnableToggle.IsOn = !enabled;
            }
            finally
            {
                _suppressToggle = false;
            }
        }

        await RefreshAsync();
    }

    private async void ShowKey_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var key = await App.Services.RevealAgentKeyAsync();
            KeyTextBox.Text = key;
            KeyTextBox.Visibility = Visibility.Visible;
            ShowInfo(InfoBarSeverity.Warning, "密钥已显示", "只在本机使用；关闭页面后不会自动清除剪贴板。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "无法读取密钥", exception.Message);
        }
    }

    private async void CopyKey_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var key = await App.Services.RevealAgentKeyAsync();
            var package = new DataPackage();
            package.SetText(key);
            Clipboard.SetContent(package);
            Clipboard.Flush();
            ShowInfo(InfoBarSeverity.Success, "已复制", "密钥已写入剪贴板。");
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "复制失败", exception.Message);
        }
    }

    private async void RotateKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ContentDialog
        {
            Title = "轮换自动化密钥？",
            Content = "现有 agent 会立即失效，需要使用新密钥重新连接。",
            PrimaryButtonText = "轮换",
            CloseButtonText = "取消",
            DefaultButton = ContentDialogButton.Close,
            XamlRoot = XamlRoot
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        try
        {
            var material = await App.Services.RotateAgentKeyAsync();
            KeyTextBox.Text = material.Secret;
            KeyTextBox.Visibility = Visibility.Visible;
            ShowInfo(InfoBarSeverity.Success, "密钥已轮换", "请把新密钥更新到本机 agent。");
            await RefreshAsync();
        }
        catch (Exception exception)
        {
            ShowInfo(InfoBarSeverity.Error, "轮换失败", exception.Message);
        }
    }

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        AgentInfo.Severity = severity;
        AgentInfo.Title = title;
        AgentInfo.Message = message;
        AgentInfo.IsOpen = true;
    }

    private static string FormatUptime(TimeSpan uptime)
    {
        if (uptime <= TimeSpan.Zero)
        {
            return "—";
        }

        return uptime.TotalHours >= 1
            ? $"{(int)uptime.TotalHours}h {uptime.Minutes}m"
            : $"{uptime.Minutes}m {uptime.Seconds}s";
    }

    private static string ShortId(string value) => value.Length <= 10 ? value : value[..10] + "…";
}
