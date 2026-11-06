using Aegis.Core.Signatures;

namespace Aegis.Service;

public sealed class SpecialPathProbe : IDisposable
{
    private static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(15);

    private readonly Action<SpecialPathEntry, bool> _onHit;
    private readonly TimeSpan _interval;
    private readonly Timer _timer;
    private readonly object _lock = new();
    private readonly HashSet<string> _reported = new(StringComparer.OrdinalIgnoreCase);
    private SpecialPathMatcher _matcher = SpecialPathMatcher.Empty;
    private bool _disposed;

    public SpecialPathProbe(Action<SpecialPathEntry, bool> onHit, TimeSpan? interval = null)
    {
        _onHit = onHit;
        _interval = interval ?? DefaultInterval;
        _timer = new Timer(_ => Probe(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
    }

    public int PathCount
    {
        get
        {
            lock (_lock)
            {
                return _matcher.Count;
            }
        }
    }

    public void Start() => _timer.Change(TimeSpan.Zero, _interval);

    public void Update(SpecialPathMatcher matcher)
    {
        lock (_lock)
        {
            _matcher = matcher;
            _reported.RemoveWhere(path => !matcher.TryMatch(path, out _));
        }
    }

    public void Probe()
    {
        if (_disposed)
        {
            return;
        }

        SpecialPathMatcher matcher;
        lock (_lock)
        {
            matcher = _matcher;
        }

        try
        {
            foreach (var entry in matcher.Entries)
            {
                bool isDirectory;
                try
                {
                    isDirectory = Directory.Exists(entry.Path);
                    if (!isDirectory && !File.Exists(entry.Path))
                    {
                        lock (_lock)
                        {
                            _reported.Remove(entry.Path);
                        }

                        continue;
                    }
                }
                catch
                {
                    continue;
                }

                lock (_lock)
                {
                    if (!_reported.Add(entry.Path))
                    {
                        continue;
                    }
                }

                try
                {
                    _onHit(entry, isDirectory);
                }
                catch
                {
                    // Probe callbacks must not throw.
                }
            }
        }
        catch
        {
            // A single probe cycle must not take down the timer.
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        _timer.Dispose();
    }
}
