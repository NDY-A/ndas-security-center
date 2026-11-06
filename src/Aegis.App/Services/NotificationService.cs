using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.AppNotifications;
using Microsoft.Windows.AppNotifications.Builder;

namespace Aegis.App.Services;

public static class NotificationService
{
    private static bool _registered;

    public static void Initialize()
    {
        try
        {
            AppNotificationManager.Default.Register();
            AppNotificationManager.Default.NotificationInvoked += OnNotificationInvoked;
            _registered = true;
        }
        catch
        {
            _registered = false;
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
                return;
            }
            catch
            {
                // Fall through to the in-app notification.
            }
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
                return;
            }
            catch
            {
                // Fall through to the in-app notification.
            }
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
