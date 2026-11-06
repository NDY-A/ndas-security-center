using System.Collections.Concurrent;

namespace Aegis.App.Services;

public static class ThreatReminderService
{
    private const int MaxRepeats = 30;
    private static readonly TimeSpan RepeatInterval = TimeSpan.FromMinutes(1);
    private static readonly ConcurrentDictionary<string, PendingThreat> Pending = new(StringComparer.Ordinal);
    private static readonly ConcurrentDictionary<string, byte> Seen = new(StringComparer.Ordinal);
    private static readonly object TimerLock = new();
    private static Timer? _timer;
    private static bool _enabled = true;

    public static void Configure(bool enabled)
    {
        lock (TimerLock)
        {
            _enabled = enabled;
            if (!enabled)
            {
                Pending.Clear();
                _timer?.Dispose();
                _timer = null;
            }
        }
    }

    public static void Report(string key, string title, string message, bool handled)
    {
        if (!_enabled)
        {
            return;
        }

        EnsureTimer();
        if (!Seen.TryAdd(key, 0))
        {
            if (handled)
            {
                Pending.TryRemove(key, out _);
            }

            return;
        }

        if (Seen.Count > 2000)
        {
            Seen.Clear();
            Seen.TryAdd(key, 0);
        }

        NotificationService.ShowThreat(title, message);
        if (handled)
        {
            Pending.TryRemove(key, out _);
        }
        else
        {
            Pending[key] = new PendingThreat(title, message, DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow, 0);
        }
    }

    public static void AcknowledgeAll() => Pending.Clear();

    public static int PendingCount => Pending.Count;

    private static void Tick()
    {
        if (!_enabled)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var pendingCount = Pending.Count;
        foreach (var pair in Pending.ToArray())
        {
            var item = pair.Value;
            if (now - item.FirstSeen > TimeSpan.FromMinutes(60) || item.Repeats >= MaxRepeats)
            {
                Pending.TryRemove(pair.Key, out _);
                continue;
            }

            if (now - item.LastNotified < RepeatInterval)
            {
                continue;
            }

            var message = pendingCount > 1
                ? $"{item.Message}（另有 {pendingCount - 1} 项未处理）"
                : item.Message;
            NotificationService.ShowThreat("仍未处理：" + item.Title, message);
            Pending[pair.Key] = item with { LastNotified = now, Repeats = item.Repeats + 1 };
        }
    }

    private static void EnsureTimer()
    {
        lock (TimerLock)
        {
            if (!_enabled)
            {
                return;
            }

            _timer ??= new Timer(_ => Tick(), null, RepeatInterval, RepeatInterval);
        }
    }

    private sealed record PendingThreat(string Title, string Message, DateTimeOffset FirstSeen,
        DateTimeOffset LastNotified, int Repeats);
}
