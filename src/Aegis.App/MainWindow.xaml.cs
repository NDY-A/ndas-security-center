using System.Runtime.InteropServices;
using Aegis.App.Services;
using Aegis.App.Views;
using Aegis.Core.Infrastructure;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Graphics;

namespace Aegis.App;

public sealed partial class MainWindow : Window
{
    private const int SW_HIDE = 0;
    private const int SW_RESTORE = 9;

    private bool _suppressNavigation;
    private TrayIconService? _trayIcon;
    private AppWindow? _appWindow;
    private bool _exitRequested;
    private bool _trayHintShown;

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    public MainWindow()
    {
        InitializeComponent();
        Title = "NDAS 安全中心";
        TryResize();
        TrySetIcon();
        InitializeTrayIcon();
        Closed += OnClosed;
    }

    private void Nav_Loaded(object sender, RoutedEventArgs e)
    {
        if (ContentFrame.Content is not null)
        {
            return;
        }

        _suppressNavigation = true;
        try
        {
            Nav.SelectedItem = Nav.MenuItems.OfType<NavigationViewItem>().FirstOrDefault(item => item.Tag as string == "dashboard");
            ContentFrame.Navigate(typeof(DashboardPage));
        }
        finally
        {
            _suppressNavigation = false;
        }
    }

    private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (_suppressNavigation || args.SelectedItem is not NavigationViewItem item || item.Tag is not string tag)
        {
            return;
        }

        var pageType = ResolvePage(tag);
        if (pageType is not null)
        {
            ContentFrame.Navigate(pageType);
        }
    }

    public void NavigateTo(string tag, object? parameter = null)
    {
        var pageType = ResolvePage(tag);
        if (pageType is null)
        {
            return;
        }

        var item = Nav.MenuItems
            .Concat(Nav.FooterMenuItems)
            .OfType<NavigationViewItem>()
            .FirstOrDefault(candidate => string.Equals(candidate.Tag as string, tag, StringComparison.OrdinalIgnoreCase));

        _suppressNavigation = true;
        try
        {
            if (item is not null)
            {
                Nav.SelectedItem = item;
            }

            ContentFrame.Navigate(pageType, parameter);
        }
        finally
        {
            _suppressNavigation = false;
        }
    }

    public void ShowGlobalMessage(InfoBarSeverity severity, string title, string message)
    {
        GlobalInfo.Severity = severity;
        GlobalInfo.Title = title;
        GlobalInfo.Message = message;
        GlobalInfo.IsOpen = true;
    }

    public void ApplyTheme(AppThemePreference theme)
    {
        if (Content is FrameworkElement root)
        {
            root.RequestedTheme = theme switch
            {
                AppThemePreference.Light => ElementTheme.Light,
                AppThemePreference.Dark => ElementTheme.Dark,
                _ => ElementTheme.Default
            };
        }
    }

    private static Type? ResolvePage(string tag) => tag switch
    {
        "dashboard" => typeof(DashboardPage),
        "hips" => typeof(HipsPage),
        "update" => typeof(UpdatePage),
        "automation" => typeof(AutomationPage),
        _ => null
    };

    private void TryResize()
    {
        try
        {
            var handle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(handle);
            var appWindow = AppWindow.GetFromWindowId(windowId);
            appWindow.Resize(new SizeInt32(1200, 800));
        }
        catch
        {
            // A fixed size is a convenience; older shells may reject it.
        }
    }

    private void TrySetIcon()
    {
        try
        {
            var handle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(handle);
            var appWindow = AppWindow.GetFromWindowId(windowId);
            var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "Aegis.ico");
            if (File.Exists(iconPath))
            {
                appWindow.SetIcon(iconPath);
            }
        }
        catch
        {
            // The executable icon is still embedded; the window icon is best-effort.
        }
    }

    private void InitializeTrayIcon()
    {
        try
        {
            var handle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(handle);
            _appWindow = AppWindow.GetFromWindowId(windowId);

            var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "Aegis.ico");
            _trayIcon = new TrayIconService(iconPath, "NDAS 安全中心（后台运行中）", ShowFromTray, RequestExit);
            _appWindow.Closing += OnAppWindowClosing;
        }
        catch (Exception exception)
        {
            _trayIcon = null;
            LogTrayFailure(exception);
            ShowGlobalMessage(InfoBarSeverity.Warning, "托盘图标不可用", "后台托盘初始化失败，关闭主窗口将直接退出程序。");
        }
    }

    private void OnAppWindowClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (_exitRequested || _trayIcon is null)
        {
            return;
        }

        args.Cancel = true;
        HideToTray(showHint: true);
    }

    private void HideToTray(bool showHint)
    {
        try
        {
            var handle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            ShowWindow(handle, SW_HIDE);

            if (showHint && !_trayHintShown)
            {
                _trayHintShown = true;
                _trayIcon?.ShowNotification("NDAS 仍在后台运行", "双击托盘图标可重新打开主界面，退出请使用托盘菜单。");
            }
        }
        catch
        {
            // The window may already be gone during shutdown.
        }
    }

    public void ShowFromTray()
    {
        try
        {
            var handle = WinRT.Interop.WindowNative.GetWindowHandle(this);
            ShowWindow(handle, SW_RESTORE);
            SetForegroundWindow(handle);
            ThreatReminderService.AcknowledgeAll();
        }
        catch
        {
            // Showing the window is best-effort.
        }
    }

    private void RequestExit()
    {
        _exitRequested = true;
        _trayIcon?.Dispose();
        _trayIcon = null;
        Close();
    }

    private static void LogTrayFailure(Exception exception)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.LogsRoot);
            File.AppendAllText(
                Path.Combine(AppPaths.LogsRoot, "ui-errors.log"),
                $"{DateTimeOffset.UtcNow:u} TrayIcon: {exception}{Environment.NewLine}");
        }
        catch
        {
            // Logging is best-effort only.
        }
    }

    public void ApplyStartupMode()
    {
        if (App.PostRemediationScanPending)
        {
            ShowFromTray();
            return;
        }

        if (!Environment.GetCommandLineArgs().Any(argument =>
                string.Equals(argument, "--background", StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        HideToTray(showHint: false);
    }

    private void OnClosed(object sender, WindowEventArgs args)
    {
        _trayIcon?.Dispose();
        _trayIcon = null;
        App.ShutdownSingleInstance();
        _ = DisposeServicesAsync();
    }

    private static async Task DisposeServicesAsync()
    {
        try
        {
            await App.Services.DisposeAsync();
        }
        catch
        {
            // The process is exiting; shutdown errors are not actionable.
        }
    }
}
