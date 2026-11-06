using Aegis.Core.Infrastructure;

namespace Aegis.Service;

public sealed class RealtimeFileMonitor : IDisposable
{
    private const int MaxErrors = 20;
    private readonly Action<string> _onPath;
    private readonly Dictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _errors = new();
    private readonly object _lock = new();
    private readonly Timer _refreshTimer;
    private bool _disposed;

    public RealtimeFileMonitor(Action<string> onPath)
    {
        _onPath = onPath;
        _refreshTimer = new Timer(_ => Refresh(), null, TimeSpan.Zero, TimeSpan.FromSeconds(30));
        Refresh();
    }

    public IReadOnlyList<string> WatchedPaths
    {
        get
        {
            lock (_lock)
            {
                return _watchers.Keys.ToArray();
            }
        }
    }

    public IReadOnlyList<string> Errors
    {
        get
        {
            lock (_lock)
            {
                return _errors.ToArray();
            }
        }
    }

    public void RefreshNow() => Refresh();

    private void AddError(string message)
    {
        lock (_lock)
        {
            if (_errors.Count >= MaxErrors)
            {
                _errors.RemoveAt(0);
            }

            _errors.Add(message);
        }
    }

    private void Refresh()
    {
        if (_disposed)
        {
            return;
        }

        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in UserProfileResolver.Resolve())
        {
            if (!string.IsNullOrWhiteSpace(profile.Desktop))
            {
                targets.Add(profile.Desktop);
            }

            if (!string.IsNullOrWhiteSpace(profile.Downloads))
            {
                targets.Add(profile.Downloads);
            }

            if (!string.IsNullOrWhiteSpace(profile.ProfilePath))
            {
                AddIfExists(targets, Path.Combine(profile.ProfilePath, "Desktop"));
                AddIfExists(targets, Path.Combine(profile.ProfilePath, "Downloads"));
            }
        }

        var usersRoot = Path.Combine(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\", "Users");
        if (Directory.Exists(usersRoot))
        {
            try
            {
                foreach (var profileDirectory in Directory.EnumerateDirectories(usersRoot))
                {
                    AddIfExists(targets, Path.Combine(profileDirectory, "Desktop"));
                    AddIfExists(targets, Path.Combine(profileDirectory, "Downloads"));
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                AddError("枚举用户目录失败：" + exception.Message);
            }
        }

        lock (_lock)
        {
            foreach (var path in _watchers.Keys.Except(targets, StringComparer.OrdinalIgnoreCase).ToArray())
            {
                try
                {
                    _watchers[path].EnableRaisingEvents = false;
                    _watchers[path].Dispose();
                }
                catch
                {
                    // Best-effort teardown.
                }

                _watchers.Remove(path);
            }

            foreach (var path in targets.Except(_watchers.Keys, StringComparer.OrdinalIgnoreCase))
            {
                Add(path);
            }
        }
    }

    private static void AddIfExists(HashSet<string> targets, string path)
    {
        if (Directory.Exists(path))
        {
            targets.Add(path);
        }
    }

    private void Add(string path)
    {
        try
        {
            var watcher = new FileSystemWatcher(path)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024,
                EnableRaisingEvents = true
            };
            watcher.Created += (_, args) => OnPath(args.FullPath);
            watcher.Renamed += (_, args) => OnPath(args.FullPath);
            watcher.Changed += (_, args) => OnPath(args.FullPath);
            watcher.Error += (_, args) => AddError("监控 " + path + " 出错：" + args.GetException().Message);
            _watchers[path] = watcher;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            AddError("无法监控 " + path + "：" + exception.Message);
        }
    }

    private void OnPath(string path)
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            if (Directory.Exists(path))
            {
                return;
            }

            _onPath(path);
        }
        catch
        {
            // Watch callbacks must not throw.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _refreshTimer.Dispose();
        lock (_lock)
        {
            foreach (var watcher in _watchers.Values)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch
                {
                    // Best-effort teardown.
                }
            }

            _watchers.Clear();
        }
    }
}
