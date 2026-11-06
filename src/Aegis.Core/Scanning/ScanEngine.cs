using System.Collections.Concurrent;
using System.Threading.Channels;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;

namespace Aegis.Core.Scanning;

public sealed class ScanEngine
{
    private const int MaxRecordedErrors = 100;
    private readonly AegisScanner _scanner;

    public ScanEngine(AegisScanner scanner)
    {
        _scanner = scanner;
    }

    public async Task<ScanSummary> ScanAsync(
        ScanRequest request,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var roots = ResolveRoots(request);
        var startedAt = DateTimeOffset.UtcNow;
        var scanId = Guid.NewGuid().ToString("N");
        var options = request.Options;
        var exclusionMatcher = BuildExclusionMatcher(options);
        var filesScanned = 0;
        var filesSkipped = 0;
        var maliciousCount = 0;
        var puaCount = 0;
        var attentionCount = 0;
        var suspiciousCount = 0;
        var cloudQueries = 0;
        var errorCount = 0;
        var bytesScanned = 0L;
        var cancelled = false;
        var findings = new ConcurrentBag<FileScanResult>();
        var errors = new ConcurrentQueue<ScanError>();
        var seenFiles = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(2048)
        {
            SingleWriter = true,
            SingleReader = false,
            FullMode = BoundedChannelFullMode.Wait
        });

        var producer = Task.Run(async () =>
        {
            try
            {
                var enumerationOptions = CreateEnumerationOptions(options);
                foreach (var root in roots)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (File.Exists(root))
                    {
                        if (!exclusionMatcher.IsExcluded(root) && seenFiles.TryAdd(root, 0))
                        {
                            await channel.Writer.WriteAsync(root, cancellationToken).ConfigureAwait(false);
                        }

                        continue;
                    }

                    if (!Directory.Exists(root))
                    {
                        AddError(errors, ref errorCount, new ScanError(root, "路径不存在。"));
                        continue;
                    }

                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(root, "*", enumerationOptions))
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            if (exclusionMatcher.IsExcluded(file) || !seenFiles.TryAdd(file, 0))
                            {
                                continue;
                            }

                            await channel.Writer.WriteAsync(file, cancellationToken).ConfigureAwait(false);
                        }
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                        AddError(errors, ref errorCount, new ScanError(root, "目录枚举失败：" + SafeError(exception)));
                    }
                }

                channel.Writer.TryComplete();
            }
            catch (OperationCanceledException)
            {
                channel.Writer.TryComplete();
            }
            catch (Exception exception)
            {
                AddError(errors, ref errorCount, new ScanError("(扫描枚举)", SafeError(exception)));
                channel.Writer.TryComplete(exception);
            }
        }, CancellationToken.None);

        var consumer = Task.Run(async () =>
        {
            try
            {
                await Parallel.ForEachAsync(
                    channel.Reader.ReadAllAsync(cancellationToken),
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = Math.Clamp(options.MaxDegreeOfParallelism, 1, 16),
                        CancellationToken = cancellationToken
                    },
                    async (file, token) =>
                    {
                        try
                        {
                            var result = await _scanner.ScanFileAsync(file, options, token).ConfigureAwait(false);
                            if (result.Verdict == ThreatVerdict.Skipped)
                            {
                                Interlocked.Increment(ref filesSkipped);
                                progress?.Report(new ScanProgress
                                {
                                    FilesScanned = Volatile.Read(ref filesScanned),
                                    Detections = Volatile.Read(ref maliciousCount) + Volatile.Read(ref suspiciousCount),
                                    Skipped = Volatile.Read(ref filesSkipped),
                                    CurrentPath = file
                                });
                                return;
                            }

                            Interlocked.Increment(ref filesScanned);
                            Interlocked.Add(ref bytesScanned, result.Size);
                            if (result.CloudQueried)
                            {
                                Interlocked.Increment(ref cloudQueries);
                            }

                            switch (result.Verdict)
                            {
                                case ThreatVerdict.Malicious:
                                    Interlocked.Increment(ref maliciousCount);
                                    findings.Add(result);
                                    break;
                                case ThreatVerdict.Pua:
                                    Interlocked.Increment(ref puaCount);
                                    findings.Add(result);
                                    break;
                                case ThreatVerdict.Attention:
                                    Interlocked.Increment(ref attentionCount);
                                    findings.Add(result);
                                    break;
                                case ThreatVerdict.Suspicious:
                                    Interlocked.Increment(ref suspiciousCount);
                                    findings.Add(result);
                                    break;
                            }

                            progress?.Report(new ScanProgress
                            {
                                FilesScanned = Volatile.Read(ref filesScanned),
                                Detections = Volatile.Read(ref maliciousCount) + Volatile.Read(ref puaCount) +
                                             Volatile.Read(ref attentionCount) + Volatile.Read(ref suspiciousCount),
                                Skipped = Volatile.Read(ref filesSkipped),
                                CurrentPath = file
                            });
                        }
                        catch (OperationCanceledException) when (token.IsCancellationRequested)
                        {
                            throw;
                        }
                        catch (Exception exception)
                        {
                            AddError(errors, ref errorCount, new ScanError(file, SafeError(exception)));
                        }
                    }).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The caller deliberately cancelled the scan.
            }
            catch (ChannelClosedException)
            {
                // Producer failed; the error is captured by the producer task.
            }
        }, CancellationToken.None);

        try
        {
            await Task.WhenAll(producer, consumer).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        catch
        {
            cancelled = cancellationToken.IsCancellationRequested;
        }

        if (cancellationToken.IsCancellationRequested)
        {
            cancelled = true;
        }

        var completedAt = DateTimeOffset.UtcNow;
        return new ScanSummary
        {
            ScanId = scanId,
            Profile = request.Profile,
            Roots = roots,
            StartedAt = startedAt,
            CompletedAt = completedAt,
            Duration = completedAt - startedAt,
            FilesScanned = Volatile.Read(ref filesScanned),
            FilesSkipped = Volatile.Read(ref filesSkipped),
            MaliciousCount = Volatile.Read(ref maliciousCount),
            PuaCount = Volatile.Read(ref puaCount),
            AttentionCount = Volatile.Read(ref attentionCount),
            SuspiciousCount = Volatile.Read(ref suspiciousCount),
            BytesScanned = Interlocked.Read(ref bytesScanned),
            ErrorCount = Volatile.Read(ref errorCount),
            Cancelled = cancelled,
            Detections = findings
                .OrderByDescending(result => result.Score)
                .ThenByDescending(result => result.Verdict)
                .ToArray(),
            Errors = errors.ToArray(),
            SignatureVersion = _scanner.Signatures.Version,
            CloudEnabled = _scanner.Cloud.IsConfigured,
            CloudQueries = Volatile.Read(ref cloudQueries)
        };
    }

    public static IReadOnlyList<string> ResolveRoots(ScanRequest request)
    {
        var roots = new List<string>();
        if (request.Profile == ScanProfileKind.Custom)
        {
            if (string.IsNullOrWhiteSpace(request.TargetPath))
            {
                throw new ArgumentException("自定义扫描必须提供文件或文件夹路径。", nameof(request));
            }

            var target = Path.GetFullPath(Environment.ExpandEnvironmentVariables(request.TargetPath.Trim()));
            if (!File.Exists(target) && !Directory.Exists(target))
            {
                throw new DirectoryNotFoundException("扫描目标不存在：" + target);
            }

            roots.Add(target);
            return roots;
        }

        if (request.Profile == ScanProfileKind.Quick)
        {
            var candidates = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) is { Length: > 0 } local ? Path.Combine(local, "Temp") : string.Empty,
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
            };

            foreach (var candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate))
                {
                    continue;
                }

                var fullPath = Path.GetFullPath(candidate);
                if ((Directory.Exists(fullPath) || File.Exists(fullPath)) &&
                    !roots.Contains(fullPath, StringComparer.OrdinalIgnoreCase))
                {
                    roots.Add(fullPath);
                }
            }

            if (roots.Count == 0)
            {
                roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            }

            return roots;
        }

        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.IsReady && drive.DriveType is DriveType.Fixed or DriveType.Removable)
                {
                    roots.Add(drive.RootDirectory.FullName);
                }
            }
            catch (IOException)
            {
                // Removed drives are ignored.
            }
            catch (UnauthorizedAccessException)
            {
                // Inaccessible drives are ignored.
            }
        }

        if (roots.Count == 0)
        {
            throw new InvalidOperationException("找不到可扫描的本地磁盘。");
        }

        return roots;
    }

    private static EnumerationOptions CreateEnumerationOptions(ScanOptions options)
    {
        var attributesToSkip = FileAttributes.ReparsePoint;
        if (!options.IncludeHiddenFiles)
        {
            attributesToSkip |= FileAttributes.Hidden | FileAttributes.System;
        }

        return new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = attributesToSkip,
            ReturnSpecialDirectories = false,
            MatchType = MatchType.Simple
        };
    }

    private static ExclusionMatcher BuildExclusionMatcher(ScanOptions options)
    {
        var paths = new List<string>();
        if (options.UseDefaultExclusions)
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrWhiteSpace(windows))
            {
                paths.Add(Path.Combine(windows, "WinSxS"));
                paths.Add(Path.Combine(windows, "System32", "DriverStore"));
            }

            paths.Add(Path.Combine(AppPaths.DataRoot, "signatures"));
            var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? "C:\\";
            paths.Add(Path.Combine(systemDrive, "$Recycle.Bin"));
            paths.Add(Path.Combine(systemDrive, "System Volume Information"));
        }

        foreach (var exclusion in options.UserExclusions)
        {
            if (string.IsNullOrWhiteSpace(exclusion))
            {
                continue;
            }

            try
            {
                var expanded = Environment.ExpandEnvironmentVariables(exclusion.Trim());
                paths.Add(Path.GetFullPath(expanded));
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                // Ignore malformed user exclusions instead of aborting the scan.
            }
        }

        return new ExclusionMatcher(paths);
    }

    private static void AddError(ConcurrentQueue<ScanError> errors, ref int count, ScanError error)
    {
        var next = Interlocked.Increment(ref count);
        if (next <= MaxRecordedErrors)
        {
            errors.Enqueue(error);
        }
    }

    private static string SafeError(Exception exception) => exception switch
    {
        UnauthorizedAccessException => "拒绝访问",
        DirectoryNotFoundException => "目录不存在",
        PathTooLongException => "路径过长",
        IOException => "I/O 错误",
        _ => exception.GetType().Name
    };

    private sealed class ExclusionMatcher
    {
        private readonly string[] _prefixes;
        private readonly HashSet<string> _exactPaths;

        public ExclusionMatcher(IEnumerable<string> paths)
        {
            var normalized = paths
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(Path.GetFullPath)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            _exactPaths = new HashSet<string>(normalized.Select(path => path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)), StringComparer.OrdinalIgnoreCase);
            _prefixes = normalized
                .Select(path => path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        public bool IsExcluded(string path)
        {
            var fullPath = Path.GetFullPath(path);
            if (_exactPaths.Contains(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)))
            {
                return true;
            }

            return _prefixes.Any(prefix => fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }
    }
}
