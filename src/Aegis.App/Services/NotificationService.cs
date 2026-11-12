using Aegis.Core.Infrastructure;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace Aegis.App.Services;

public static class NotificationService
{
    private static bool _registered;

    public static bool IsRegistered => _registered;

    public static void Initialize()
    {
        try
        {
            // AppNotificationManager requires handlers to be attached before Register().
            AppNotificationManager.Default.NotificationInvoked += OnNotificationInvoked;
            AppNotificationManager.Default.Register();
            _registered = true;
            Log("AppNotification registered");
        }
        catch (Exception exception)
        {
            _registered = false;
            Log("AppNotification register failed: " + exception.GetType().Name + ": " + exception.Message);
        }
    }

    private static void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.LogsRoot);
            File.AppendAllText(
                Path.Combine(AppPaths.LogsRoot, "notifications.log"),
                $"{DateTimeOffset.UtcNow:u} {message}{Environment.NewLine}");
        }
        catch
        {
            // Best-effort only.
        }
    }

    private static void OnNotificationInvoked(AppNotificationManager sender, AppNotificationActivatedEventArgs args)
    {
        try
        {
            var window = Aegis.App.App.MainWindow;
            if (window is null)
            {
                return;
            }

            window.DispatcherQueue.TryEnqueue(() =>
            {
                ThreatReminderService.AcknowledgeAll();
                window.ShowFromTray();
            });
        }
        catch
        {
            // Notification activation is best-effort.
        }
    }

    public static void ShowWarning(string title, string message)
    {
        if (_registered)
        {
            try
            {
                var notification = new AppNotificationBuilder()
                    .AddText(title)
                    .AddText(message)
                    .AddButton(new AppNotificationButton("打开 NDAS").AddArgument("action", "open"))
                    .BuildNotification();
                AppNotificationManager.Default.Show(notification);
                Log("show warning: " + title);
                return;
            }
            catch (Exception exception)
            {
                Log("show warning failed: " + exception.GetType().Name + ": " + exception.Message);
            }
        }
        else
        {
            Log("show warning skipped (not registered): " + title);
        }

        try
        {
            Aegis.App.App.MainWindow?.ShowGlobalMessage(InfoBarSeverity.Warning, title, message);
        }
        catch
        {
            // Notifications are best-effort.
        }
    }

    public static void ShowThreat(string title, string message)
    {
        if (_registered)
        {
            try
            {
                var notification = new AppNotificationBuilder()
                    .AddText("威胁和防护状态")
                    .AddText(title)
                    .AddText(message)
                    .AddButton(new AppNotificationButton("打开 NDAS").AddArgument("action", "open"))
                    .BuildNotification();
                AppNotificationManager.Default.Show(notification);
                Log("show threat: " + title);
                return;
            }
            catch (Exception exception)
            {
                Log("show threat failed: " + exception.GetType().Name + ": " + exception.Message);
            }
        }
        else
        {
            Log("show threat skipped (not registered): " + title);
        }

        try
        {
            Aegis.App.App.MainWindow?.ShowGlobalMessage(InfoBarSeverity.Error, title, message);
        }
        catch
        {
            // Notifications are best-effort.
        }
    }
}
