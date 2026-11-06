using System.Runtime.InteropServices;
using Aegis.Core.Infrastructure;

namespace Aegis.Service;

public sealed class IdleScanService : IDisposable
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
        "Package Cache"
    };

    private const int MaxFilesPerPass = 5000;
    private static readonly TimeSpan MaxPassDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DefaultIdleThreshold = TimeSpan.FromMinutes(10);

    private readonly Func<IReadOnlyList<string>> _targetsProvider;
    private readonly Func<string, CancellationToken, Task<bool>> _scanFile;
    private readonly Func<bool> _enabledProvider;
    private readonly Func<int> _idleMinutesProvider;
    private readonly Func<IReadOnlyList<string>> _exclusionsProvider;
    private readonly Func<TimeSpan> _idleProvider;
    private readonly Timer _timer;
    private readonly object _lock = new();
    private readonly Dictionary<string, ScannedFileState> _knownFiles = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _passCancellation;
    private bool _disposed;
    private volatile bool _scanning;

    public IdleScanService(
        Func<IReadOnlyList<string>> targetsProvider,
        Func<string, CancellationToken, Task<bool>> scanFile,
        Func<bool> enabledProvider,
        Func<int> idleMinutesProvider,
        Func<IReadOnlyList<string>> exclusionsProvider,
        Func<TimeSpan>? idleProvider = null,
        TimeSpan? checkInterval = null)
    {
        _targetsProvider = targetsProvider;
        _scanFile = scanFile;
        _enabledProvider = enabledProvider;
        _idleMinutesProvider = idleMinutesProvider;
        _exclusionsProvider = exclusionsProvider;
        _idleProvider = idleProvider ?? GetSystemIdleTime;
        _timer = new Timer(_ => _ = TickAsync(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        _timer.Change(checkInterval ?? CheckInterval, checkInterval ?? CheckInterval);
    }

    public bool IsScanning => _scanning;

    public DateTimeOffset? LastScanAt { get; private set; }

    public long LastScanFiles { get; private set; }

    public long LastScanThreats { get; private set; }

    public static IReadOnlyList<string> DefaultTargets()
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var profile in UserProfileResolver.GetCached(TimeSpan.FromSeconds(60)))
        {
            AddIfExists(targets, profile.Desktop);
            AddIfExists(targets, profile.Downloads);
            if (!string.IsNullOrWhiteSpace(profile.ProfilePath))
            {
                AddIfExists(targets, Path.Combine(profile.ProfilePath, "Desktop"));
                AddIfExists(targets, Path.Combine(profile.ProfilePath, "Downloads"));
                AddIfExists(targets, Path.Combine(profile.ProfilePath, "AppData", "Roaming", "Microsoft",
                    "Windows", "Start Menu", "Programs", "Startup"));
            }
        }

        AddIfExists(targets, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
        AddIfExists(targets, Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
        AddIfExists(targets, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        AddIfExists(targets, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        AddIfExists(targets, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

        var usersRoot = Path.Combine(
            Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\", "Users");
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
                // Target refresh is best-effort.
            }
        }

        return targets.ToArray();
    }

    private async Task TickAsync()
    {
        if (_disposed || _scanning || !_enabledProvider())
        {
            return;
        }

        TimeSpan threshold;
        try
        {
            threshold = TimeSpan.FromMinutes(Math.Clamp(_idleMinutesProvider(), 1, 240));
        }
        catch
        {
            threshold = DefaultIdleThreshold;
        }

        TimeSpan idle;
        try
        {
            idle = _idleProvider();
        }
        catch
        {
            return;
        }

        if (idle < threshold)
        {
            return;
        }

        CancellationTokenSource cancellation;
        lock (_lock)
        {
            if (_disposed || _scanning)
            {
                return;
            }

            _scanning = true;
            cancellation = new CancellationTokenSource();
            _passCancellation = cancellation;
        }

        try
        {
            await Task.Run(() => RunPassAsync(cancellation.Token), CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // An idle pass must never take down the service.
        }
        finally
        {
            lock (_lock)
            {
                _scanning = false;
                _passCancellation = null;
            }

            cancellation.Dispose();
        }
    }

    private async Task RunPassAsync(CancellationToken cancellationToken)
    {
        var files = 0L;
        var threats = 0L;
        var startedAt = DateTimeOffset.UtcNow;
        var abortThreshold = TimeSpan.FromMinutes(1);

        foreach (var target in _targetsProvider().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (cancellationToken.IsCancellationRequested || files >= MaxFilesPerPass ||
                DateTimeOffset.UtcNow - startedAt > MaxPassDuration)
            {
                break;
            }

            foreach (var file in EnumerateFiles(target, cancellationToken))
            {
                if (cancellationToken.IsCancellationRequested || files >= MaxFilesPerPass ||
                    DateTimeOffset.UtcNow - startedAt > MaxPassDuration)
                {
                    break;
                }

                if (_idleProvider() < abortThreshold)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }

                if (IsExcluded(file) || !HasScanExtension(file) || !TryReadState(file, out var state))
                {
                    continue;
                }

                if (_knownFiles.TryGetValue(file, out var known) && known == state)
                {
                    continue;
                }

                _knownFiles[file] = state;
                files++;
                try
                {
                    if (await _scanFile(file, cancellationToken).ConfigureAwait(false))
                    {
                        threats++;
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    // A single unreadable file must not abort the pass.
                }

                try
                {
                    await Task.Delay(10, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
            }
        }

        LastScanAt = DateTimeOffset.UtcNow;
        LastScanFiles = files;
        LastScanThreats = threats;
        PruneKnownFiles();
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

            if (depth >= 12)
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

    private bool IsExcluded(string path)
    {
        foreach (var exclusion in _exclusionsProvider())
        {
            if (IsUnder(path, exclusion))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasScanExtension(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Length > 0 && ScanExtensions.Contains(extension);
    }

    private static bool TryReadState(string path, out ScannedFileState state)
    {
        state = default;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0 || info.Length > 512L * 1024 * 1024)
            {
                return false;
            }

            state = new ScannedFileState(info.Length, info.LastWriteTimeUtc.Ticks);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void PruneKnownFiles()
    {
        if (_knownFiles.Count <= 100_000)
        {
            return;
        }

        var keep = _knownFiles
            .OrderByDescending(pair => pair.Value.LastWriteTicks)
            .Take(50_000)
            .ToArray();
        _knownFiles.Clear();
        foreach (var pair in keep)
        {
            _knownFiles[pair.Key] = pair.Value;
        }
    }

    private static bool IsUnder(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            return false;
        }

        var root = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
                   Path.DirectorySeparatorChar;
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
               path.Equals(directory, StringComparison.OrdinalIgnoreCase);
    }

    private static void AddIfExists(HashSet<string> targets, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
        {
            targets.Add(path);
        }
    }

    private static TimeSpan GetSystemIdleTime()
    {
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info))
        {
            return TimeSpan.Zero;
        }

        var idleMilliseconds = unchecked((uint)Environment.TickCount - info.Time);
        return idleMilliseconds > int.MaxValue
            ? TimeSpan.Zero
            : TimeSpan.FromMilliseconds(idleMilliseconds);
    }

    public void Dispose()
    {
        CancellationTokenSource? cancellation;
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            cancellation = _passCancellation;
        }

        _timer.Dispose();
        try
        {
            cancellation?.Cancel();
        }
        catch
        {
            // Best-effort teardown.
        }
    }

    private readonly record struct ScannedFileState(long Length, long LastWriteTicks);

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);
}
