using System.Diagnostics;

namespace Aegis.Service;

public sealed class ContinuousScanService : IDisposable
{
    private static readonly HashSet<string> ScanExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url", ".reg", ".msi", ".msp",
        ".zip", ".7z", ".rar", ".cab", ".iso", ".docm", ".xlsm", ".pptm", ".dotm", ".xlam"
    };

    private static readonly HashSet<string> SkipDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "node_modules", ".git", ".vs", ".idea", "obj", "bin", "packages", "AppData",
        "System Volume Information", "$Recycle.Bin", "WindowsApps", "Windows Defender",
        "Package Cache", "DriverStore", "WinSxS", "servicing", "assembly", "CatRoot",
        "CatRoot2", "Installer$", "SoftwareDistribution"
    };

    private static readonly TimeSpan IdleDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan PerFileDelay = TimeSpan.FromMilliseconds(30);
    private static readonly TimeSpan CpuSampleWindow = TimeSpan.FromSeconds(1.5);
    private static readonly TimeSpan CpuCooldown = TimeSpan.FromMilliseconds(250);
    private const int MaxKnownFiles = 200_000;

    private readonly Func<IReadOnlyList<string>> _targetsProvider;
    private readonly Func<string, CancellationToken, Task<bool>> _scanFile;
    private readonly Func<bool> _enabledProvider;
    private readonly Func<int> _cpuPercentProvider;
    private readonly Func<IReadOnlyList<string>> _exclusionsProvider;
    private readonly CancellationTokenSource _cancellation = new();
    private readonly object _stateLock = new();
    private readonly Dictionary<string, FileState> _knownFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly CpuSampler _sampler = new();
    private Task? _loop;
    private long _totalFiles;
    private long _totalThreats;
    private string? _currentPath;
    private DateTimeOffset? _lastActivityAt;
    private DateTimeOffset? _startedAt;
    private volatile bool _disposed;

    public ContinuousScanService(
        Func<IReadOnlyList<string>> targetsProvider,
        Func<string, CancellationToken, Task<bool>> scanFile,
        Func<bool> enabledProvider,
        Func<int> cpuPercentProvider,
        Func<IReadOnlyList<string>> exclusionsProvider)
    {
        _targetsProvider = targetsProvider;
        _scanFile = scanFile;
        _enabledProvider = enabledProvider;
        _cpuPercentProvider = cpuPercentProvider;
        _exclusionsProvider = exclusionsProvider;
    }

    public bool IsActive => _loop is { IsCompleted: false };

    public long TotalFiles => Interlocked.Read(ref _totalFiles);

    public long TotalThreats => Interlocked.Read(ref _totalThreats);

    public string? CurrentPath
    {
        get { lock (_stateLock) return _currentPath; }
    }

    public DateTimeOffset? StartedAt
    {
        get { lock (_stateLock) return _startedAt; }
    }

    public DateTimeOffset? LastActivityAt
    {
        get { lock (_stateLock) return _lastActivityAt; }
    }

    public void Start()
    {
        if (_disposed || _loop is not null)
        {
            return;
        }

        lock (_stateLock)
        {
            _startedAt = DateTimeOffset.UtcNow;
        }

        _loop = Task.Run(() => LoopAsync(_cancellation.Token), CancellationToken.None);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cancellation.Cancel();
        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(10));
        }
        catch
        {
            // Shutdown is best-effort.
        }

        _cancellation.Dispose();
        _process.Dispose();
    }

    private async Task LoopAsync(CancellationToken cancellationToken)
    {
        _sampler.Reset(_process);
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!_enabledProvider())
                {
                    await Task.Delay(IdleDelay, cancellationToken).ConfigureAwait(false);
                    _sampler.Reset(_process);
                    continue;
                }

                var scannedAny = false;
                foreach (var target in _targetsProvider())
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    foreach (var file in EnumerateFiles(target, cancellationToken))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        if (!_enabledProvider())
                        {
                            break;
                        }

                        if (IsExcluded(file) || !HasScanExtension(file) || IsKnownUnchanged(file))
                        {
                            continue;
                        }

                        scannedAny = true;
                        lock (_stateLock)
                        {
                            _currentPath = file;
                            _lastActivityAt = DateTimeOffset.UtcNow;
                        }

                        try
                        {
                            if (await _scanFile(file, cancellationToken).ConfigureAwait(false))
                            {
                                Interlocked.Increment(ref _totalThreats);
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch
                        {
                            // A single unreadable file must not stop the engine.
                        }

                        Interlocked.Increment(ref _totalFiles);
                        MarkKnown(file);
                        await Task.Delay(PerFileDelay, cancellationToken).ConfigureAwait(false);
                        await ThrottleAsync(cancellationToken).ConfigureAwait(false);
                    }
                }

                if (!scannedAny)
                {
                    await Task.Delay(IdleDelay, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // The engine must never take down the service.
                try
                {
                    await Task.Delay(IdleDelay, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        lock (_stateLock)
        {
            _currentPath = null;
        }
    }

    private async Task ThrottleAsync(CancellationToken cancellationToken)
    {
        var budget = (double)Math.Clamp(_cpuPercentProvider(), 1, 90);
        if (!_sampler.TrySample(_process, out var cpuPercent))
        {
            return;
        }

        if (cpuPercent <= budget)
        {
            return;
        }

        while (cpuPercent > budget && !cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(CpuCooldown, cancellationToken).ConfigureAwait(false);
            if (!_sampler.TrySample(_process, out cpuPercent))
            {
                return;
            }
        }
    }

    private sealed class CpuSampler
    {
        private TimeSpan _lastProcessTime;
        private long _lastSample;

        public void Reset(Process process)
        {
            lock (this)
            {
                _lastProcessTime = process.TotalProcessorTime;
                _lastSample = Stopwatch.GetTimestamp();
            }
        }

        public bool TrySample(Process process, out double cpuPercent)
        {
            lock (this)
            {
                cpuPercent = 0;
                var now = Stopwatch.GetTimestamp();
                var wall = Stopwatch.GetElapsedTime(_lastSample, now);
                if (wall < CpuSampleWindow)
                {
                    return false;
                }

                var processTime = process.TotalProcessorTime;
                var used = processTime - _lastProcessTime;
                _lastProcessTime = processTime;
                _lastSample = now;
                var wallMs = wall.TotalMilliseconds;
                if (wallMs <= 0)
                {
                    return false;
                }

                cpuPercent = used.TotalMilliseconds / (wallMs * Environment.ProcessorCount) * 100.0;
                return true;
            }
        }
    }

    private bool IsExcluded(string path)
    {
        IReadOnlyList<string> exclusions;
        try
        {
            exclusions = _exclusionsProvider();
        }
        catch
        {
            exclusions = Array.Empty<string>();
        }

        foreach (var exclusion in exclusions)
        {
            if (!string.IsNullOrWhiteSpace(exclusion) &&
                path.StartsWith(exclusion, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasScanExtension(string path)
    {
        try
        {
            return ScanExtensions.Contains(Path.GetExtension(path));
        }
        catch
        {
            return false;
        }
    }

    private bool IsKnownUnchanged(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return true;
            }

            lock (_stateLock)
            {
                return _knownFiles.TryGetValue(path, out var known) &&
                       known.Size == info.Length &&
                       known.LastWriteTicks == info.LastWriteTimeUtc.Ticks;
            }
        }
        catch
        {
            return true;
        }
    }

    private void MarkKnown(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return;
            }

            lock (_stateLock)
            {
                if (_knownFiles.Count >= MaxKnownFiles)
                {
                    _knownFiles.Clear();
                }

                _knownFiles[path] = new FileState(info.Length, info.LastWriteTimeUtc.Ticks);
            }
        }
        catch
        {
            // Cache updates are best-effort.
        }
    }

    private static IEnumerable<string> EnumerateFiles(string root, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            yield break;
        }

        var stack = new Stack<(string Path, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (directory, depth) = stack.Pop();

            foreach (var file in TryGetFiles(directory))
            {
                yield return file;
            }

            if (depth >= 10)
            {
                continue;
            }

            foreach (var subdirectory in TryGetDirectories(directory))
            {
                var name = Path.GetFileName(subdirectory);
                if (SkipDirectories.Contains(name) || IsReparsePoint(subdirectory))
                {
                    continue;
                }

                stack.Push((subdirectory, depth + 1));
            }
        }
    }

    private static string[] TryGetFiles(string directory)
    {
        try
        {
            return Directory.GetFiles(directory);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static string[] TryGetDirectories(string directory)
    {
        try
        {
            return Directory.GetDirectories(directory);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static bool IsReparsePoint(string directory)
    {
        try
        {
            return (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0;
        }
        catch
        {
            return true;
        }
    }

    private readonly record struct FileState(long Size, long LastWriteTicks);
}
