using Aegis.App.Services;
using Aegis.Core.Infrastructure;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Aegis.App;

public partial class App : Application
{
    public static MainWindow? MainWindow { get; private set; }

    public static AppServices Services => AppServices.Current;

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        NotificationService.Initialize();
        MainWindow = new MainWindow();
        MainWindow.Activate();
        MainWindow.ApplyStartupMode();
        _ = InitializeServicesAsync();
    }

    private static async Task InitializeServicesAsync()
    {
        try
        {
            await Services.InitializeAsync(AppContext.BaseDirectory);
            MainWindow?.DispatcherQueue.TryEnqueue(() => MainWindow?.ApplyTheme(Services.Settings.Theme));
        }
        catch (Exception exception)
        {
            var message = Services.InitializationError ?? exception.Message;
            MainWindow?.ShowGlobalMessage(InfoBarSeverity.Error, "安全中心初始化失败", message);
        }
    }

    private static void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        try
        {
            Directory.CreateDirectory(AppPaths.LogsRoot);
            File.AppendAllText(
                Path.Combine(AppPaths.LogsRoot, "ui-errors.log"),
                $"{DateTimeOffset.UtcNow:u} {e.Exception.GetType().FullName}: {e.Exception.Message}{Environment.NewLine}");
        }
        catch
        {
            // UI error logging is best-effort only.
        }

        MainWindow?.ShowGlobalMessage(InfoBarSeverity.Error, "界面异常", "界面操作发生异常，已阻止应用退出。异常类型已写入本机日志。");
    }
}
