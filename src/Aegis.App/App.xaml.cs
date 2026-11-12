using Aegis.App.Services;
using Aegis.Core.Infrastructure;
using Aegis.Core.Service;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Aegis.App;

public partial class App : Application
{
    private static SingleInstanceService? _singleInstance;

    public static MainWindow? MainWindow { get; private set; }

    public static AppServices Services => AppServices.Current;

    public static bool PostRemediationScanPending { get; private set; }

    public static event EventHandler? PostRemediationScanRequested;

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        var arguments = Environment.GetCommandLineArgs().Skip(1).ToArray();
        if (arguments.Contains("--contain-request", StringComparer.OrdinalIgnoreCase))
        {
            // Elevated helper: send the containment request and exit without a window.
            _ = RunContainRequestAsync();
            return;
        }

        var postRemediation = arguments.Contains("--post-remediation-scan", StringComparer.OrdinalIgnoreCase);
        var background = arguments.Contains("--background", StringComparer.OrdinalIgnoreCase);

        var singleInstance = new SingleInstanceService();
        if (!singleInstance.TryAcquire())
        {
            var command = postRemediation ? "post-remediation-scan" : background ? "noop" : "show";
            SingleInstanceService.TrySend(command);
            Environment.Exit(0);
            return;
        }

        _singleInstance = singleInstance;
        singleInstance.CommandReceived += OnInstanceCommand;

        PostRemediationScanPending = postRemediation;

        NotificationService.Initialize();
        MainWindow = new MainWindow();
        MainWindow.Activate();
        MainWindow.ApplyStartupMode();
        _ = InitializeServicesAsync();
    }

    private static void OnInstanceCommand(object? sender, string command)
    {
        var window = MainWindow;
        if (window is null)
        {
            return;
        }

        window.DispatcherQueue.TryEnqueue(() =>
        {
            switch (command)
            {
                case "post-remediation-scan":
                    PostRemediationScanPending = true;
                    MainWindow?.ShowFromTray();
                    MainWindow?.NavigateTo("dashboard");
                    PostRemediationScanRequested?.Invoke(null, EventArgs.Empty);
                    break;
                case "show":
                    MainWindow?.ShowFromTray();
                    break;
            }
        });
    }

    public static void ShutdownSingleInstance()
    {
        _singleInstance?.Dispose();
        _singleInstance = null;
    }

    public static bool TryConsumePostRemediationScan()
    {
        if (!PostRemediationScanPending)
        {
            return false;
        }

        PostRemediationScanPending = false;
        return true;
    }

    private static async Task RunContainRequestAsync()
    {
        try
        {
            var client = new ServiceClient();
            var status = await client.StartContainmentAsync().ConfigureAwait(false);
            LogContainRequest(status is null
                ? "失败：无法连接 NDAS 防护服务。"
                : status.Containment is { Active: true }
                    ? "已发送强力清除请求。"
                    : "失败：" + (status.LastError ?? "服务未启动强力清除。"));
        }
        catch (Exception exception)
        {
            LogContainRequest("失败：" + exception.Message);
        }
        finally
        {
            Environment.Exit(0);
        }
    }

    private static void LogContainRequest(string message)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.LogsRoot);
            File.AppendAllText(Path.Combine(AppPaths.LogsRoot, "contain-helper.log"),
                $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}");
        }
        catch
        {
            // Helper logging is best-effort only.
        }
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
