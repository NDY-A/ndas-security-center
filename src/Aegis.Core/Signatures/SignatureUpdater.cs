using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Aegis.Core.Yara;

namespace Aegis.Core.Signatures;

public sealed record SignatureUpdateSource(string Name, Uri BaseUri);

public sealed record SignatureUpdateProgress(string Stage, int Percent, string Message);

public sealed class SignatureUpdateResult
{
    public required bool Success { get; init; }
    public bool IsUpToDate { get; init; }
    public string? Error { get; init; }
    public string? Version { get; init; }
    public string? Source { get; init; }
    public int HashCount { get; init; }
    public int DomainCount { get; init; }
    public int IpCount { get; init; }
    public int YaraRuleCount { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
}

public sealed class SignatureUpdater
{
    public const string VersionFileName = "version.txt";
    public const string YaraRuleFileName = "yara/rules.yar";
    public const string DefenderPackManifestFileName = "manifest.json";
    public const string DefenderPackManifestPath = "yara/defender/manifest.json";
    public const string ExtendedPackRepository = "NDY-A/ndas-extended-yara";
    private static readonly Regex PackFileNamePattern = new(
        "^[A-Za-z0-9._-]+\\.(?:yar|yara)$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private const long MaxSignatureFileBytes = SignatureFileLimits.MaxBytes;
    private const long MaxYaraFileBytes = SignatureFileLimits.MaxBytes;
    private const long MaxSpecialPathFileBytes = SignatureFileLimits.MaxBytes;
    private const int CopyBufferSize = 128 * 1024;
    private const double MinimumYaraRetentionRatio = 0.5;
    private const string AllowYaraRegressionEnvironmentVariable = "NDAS_ALLOW_YARA_REGRESSION";
    private readonly string _dataRoot;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly IReadOnlyList<SignatureUpdateSource> _sources;
    private readonly IReadOnlyList<SignatureUpdateSource> _defenderPackSources;

    public SignatureUpdater(string dataRoot, HttpClient? httpClient = null, IEnumerable<SignatureUpdateSource>? sources = null,
        IEnumerable<SignatureUpdateSource>? defenderPackSources = null)
    {
        _dataRoot = dataRoot;
        _sources = (sources ?? DefaultSources()).ToArray();
        _defenderPackSources = defenderPackSources?.ToArray() ??
            DefaultDefenderPackSources()
                .Concat(_sources.Select(source => new SignatureUpdateSource(
                    source.Name + " · 旧位置", new Uri(source.BaseUri, "yara/defender/"))))
                .ToArray();
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient(new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            ConnectTimeout = TimeSpan.FromSeconds(8),
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        })
        {
            Timeout = TimeSpan.FromSeconds(30)
        };

        if (_httpClient.DefaultRequestHeaders.UserAgent.Count == 0)
        {
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("NDAS/0.1 (+local-endpoint-security)");
        }
    }

    public static IReadOnlyList<SignatureUpdateSource> DefaultSources()
    {
        return new[]
        {
            new SignatureUpdateSource("GitHub Raw", new Uri("https://raw.githubusercontent.com/NDY-A/malware-egress-blocklist/main/data/")),
            new SignatureUpdateSource("GitHub Web Raw", new Uri("https://github.com/NDY-A/malware-egress-blocklist/raw/main/data/")),
            new SignatureUpdateSource("jsDelivr", new Uri("https://fastly.jsdelivr.net/gh/NDY-A/malware-egress-blocklist@main/data/")),
            new SignatureUpdateSource("jsDelivr CDN", new Uri("https://cdn.jsdelivr.net/gh/NDY-A/malware-egress-blocklist@main/data/"))
        };
    }

    public static IReadOnlyList<SignatureUpdateSource> DefaultDefenderPackSources()
    {
        var repository = ExtendedPackRepository;
        return new[]
        {
            new SignatureUpdateSource("扩展规则包 · GitHub Raw",
                new Uri($"https://raw.githubusercontent.com/{repository}/main/")),
            new SignatureUpdateSource("扩展规则包 · GitHub Web Raw",
                new Uri($"https://github.com/{repository}/raw/main/")),
            new SignatureUpdateSource("扩展规则包 · jsDelivr",
                new Uri($"https://fastly.jsdelivr.net/gh/{repository}@main/")),
            new SignatureUpdateSource("扩展规则包 · jsDelivr CDN",
                new Uri($"https://cdn.jsdelivr.net/gh/{repository}@main/"))
        };
    }

    public async Task<SignatureUpdateResult> UpdateAsync(
        IProgress<SignatureUpdateProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var warnings = new List<string>();
        var workRoot = Path.Combine(_dataRoot, ".download-" + Guid.NewGuid().ToString("N"));
        var staging = Path.Combine(_dataRoot, ".staging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dataRoot);

        try
        {
            DownloadedSet? downloaded = null;
            Exception? lastError = null;
            var currentManifest = await TryReadCurrentManifestAsync(cancellationToken).ConfigureAwait(false);
            var sawDownload = false;
            var sourceIndex = 0;

            progress?.Report(new SignatureUpdateProgress("检查", 10, "正在比较当前病毒库…"));

            foreach (var source in _sources)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var attemptDirectory = Path.Combine(workRoot, "attempt" + sourceIndex++);
                try
                {
                    progress?.Report(new SignatureUpdateProgress("下载", 10, $"正在连接 {source.Name}…"));
                    var candidate = await DownloadSetAsync(source, progress, attemptDirectory, cancellationToken)
                        .ConfigureAwait(false);
                    sawDownload = true;
                    var candidateVersion = await ResolveVersionAsync(candidate.Files, cancellationToken).ConfigureAwait(false);
                    if (!IsCandidateNewer(candidateVersion, currentManifest?.Version))
                    {
                        warnings.Add($"{source.Name} 返回旧版本 {candidateVersion ?? "无版本号"}（当前 {currentManifest?.Version ?? "无"}），已跳过。");
                        continue;
                    }

                    downloaded = candidate;
                    Directory.Move(attemptDirectory, staging);
                    break;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    lastError = exception;
                    warnings.Add($"{source.Name} 不可用：{SafeMessage(exception)}");
                }
            }

            if (downloaded is null)
            {
                if (currentManifest is not null && sawDownload)
                {
                    progress?.Report(new SignatureUpdateProgress("完成", 100, "当前已是最新版本。"));
                    return new SignatureUpdateResult
                    {
                        Success = true,
                        IsUpToDate = true,
                        Version = currentManifest.Version,
                        Source = "current",
                        HashCount = currentManifest.Counts.Hashes,
                        DomainCount = currentManifest.Counts.Domains,
                        IpCount = currentManifest.Counts.Ips,
                        YaraRuleCount = currentManifest.Counts.YaraRules,
                        CompletedAt = DateTimeOffset.UtcNow,
                        CheckedAt = DateTimeOffset.UtcNow,
                        Warnings = warnings
                    };
                }

                return new SignatureUpdateResult
                {
                    Success = false,
                    Error = lastError is null ? "没有配置病毒库下载源。" : "所有下载源均失败：" + SafeMessage(lastError),
                    CompletedAt = DateTimeOffset.UtcNow,
                    Warnings = warnings
                };
            }

            progress?.Report(new SignatureUpdateProgress("校验", 55, "正在校验哈希、域名和 IP 列表…"));
            var stagedFiles = RebaseToDirectory(downloaded.Files, staging);
            var parsed = await ValidateAsync(stagedFiles, cancellationToken).ConfigureAwait(false);
            if (parsed.HashCount == 0)
            {
                throw new InvalidDataException("下载的 hashes.csv 没有有效条目。");
            }

            if (parsed.DomainCount == 0)
            {
                throw new InvalidDataException("下载的 domains.txt 没有有效条目。");
            }

            warnings.AddRange(downloaded.Warnings);
            warnings.AddRange(parsed.Warnings);

            var fetchedAt = DateTimeOffset.UtcNow;
            var manifestFiles = new Dictionary<string, ManifestFileInfo>(StringComparer.OrdinalIgnoreCase);
            var digestText = new StringBuilder();
            foreach (var pair in stagedFiles.OrderBy(x => x.Key, StringComparer.Ordinal))
            {
                var (sha256, bytes) = await HashFileAsync(pair.Value, cancellationToken).ConfigureAwait(false);
                manifestFiles[pair.Key] = new ManifestFileInfo { Sha256 = sha256, Bytes = bytes };
                digestText.Append(bytes).Append(':').Append(sha256).Append(';');
            }

            var combinedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(
                digestText.ToString() + downloaded.Source.BaseUri.AbsoluteUri));
            var fallbackVersion = $"github-{fetchedAt:yyyy.MM.dd-HHmm}-{Convert.ToHexString(combinedDigest)[..8].ToLowerInvariant()}";
            var version = await ResolveVersionAsync(stagedFiles, cancellationToken).ConfigureAwait(false) ?? fallbackVersion;

            // 规则数骤减保护：候选库的 YARA 规则总数低于当前库的一半时拒绝提交，
            // 避免扩展包下载失败等情况下把检测能力悄悄换成一个缩水版病毒库。
            var currentYaraRules = currentManifest?.Counts?.YaraRules ?? 0;
            if (currentYaraRules > 0 &&
                parsed.YaraRules < currentYaraRules * MinimumYaraRetentionRatio &&
                !AllowYaraRegression())
            {
                return new SignatureUpdateResult
                {
                    Success = false,
                    Version = version,
                    Error = $"候选病毒库的 YARA 规则数显著减少（{currentYaraRules:N0} → {parsed.YaraRules:N0}），" +
                            $"已拒绝更新以保护检测能力。如确认要接受降级，请设置环境变量 {AllowYaraRegressionEnvironmentVariable}=1 后重启 NDAS 再更新。",
                    CompletedAt = DateTimeOffset.UtcNow,
                    Warnings = warnings
                };
            }

            var manifest = new SignatureManifest
            {
                SchemaVersion = 1,
                Version = version,
                Source = downloaded.Source.BaseUri.AbsoluteUri,
                FetchedAt = fetchedAt,
                IsSeed = false,
                Files = manifestFiles,
                Counts = new SignatureCounts
                {
                    Hashes = parsed.HashCount,
                    Domains = parsed.DomainCount,
                    Ips = parsed.IpCount,
                    YaraRules = parsed.YaraRules,
                    SpecialPaths = parsed.SpecialPaths
                }
            };

            progress?.Report(new SignatureUpdateProgress("安装", 80, "正在原子替换本地病毒库…"));
            await manifest.WriteAsync(Path.Combine(staging, "manifest.json"), cancellationToken).ConfigureAwait(false);

            // Validate the staged directory through the exact same path used at startup.
            _ = await SignatureRepository.LoadDirectoryAsync(staging, cancellationToken).ConfigureAwait(false);
            Commit(staging);

            progress?.Report(new SignatureUpdateProgress("完成", 100, $"病毒库已更新到 {version}。"));
            return new SignatureUpdateResult
            {
                Success = true,
                Version = version,
                Source = downloaded.Source.Name,
                HashCount = parsed.HashCount,
                DomainCount = parsed.DomainCount,
                IpCount = parsed.IpCount,
                YaraRuleCount = parsed.YaraRules,
                CompletedAt = fetchedAt,
                Warnings = warnings
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new SignatureUpdateResult
            {
                Success = false,
                Error = SafeMessage(exception),
                CompletedAt = DateTimeOffset.UtcNow,
                Warnings = warnings
            };
        }
        finally
        {
            DeleteDirectoryQuietly(staging);
            DeleteDirectoryQuietly(workRoot);
        }
    }

    private static Dictionary<string, string> RebaseToDirectory(Dictionary<string, string> files, string directory)
    {
        return files.ToDictionary(
            pair => pair.Key,
            pair => Path.Combine(directory, pair.Key.Replace('/', Path.DirectorySeparatorChar)),
            StringComparer.OrdinalIgnoreCase);
    }

    private async Task<DownloadedSet> DownloadSetAsync(
        SignatureUpdateSource source,
        IProgress<SignatureUpdateProgress>? progress,
        string directory,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(directory);
        var warnings = new List<string>();
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        async Task<string> FetchAsync(string relativePath, long maxBytes)
        {
            var target = Path.Combine(directory, relativePath.Replace('/', Path.DirectorySeparatorChar));
            var folder = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(folder))
            {
                Directory.CreateDirectory(folder);
            }

            await DownloadToFileAsync(new Uri(source.BaseUri, relativePath), target, maxBytes, cancellationToken)
                .ConfigureAwait(false);
            return target;
        }

        files[BlocklistParser.HashFileName] = await FetchAsync(BlocklistParser.HashFileName, MaxSignatureFileBytes).ConfigureAwait(false);
        files[BlocklistParser.DomainFileName] = await FetchAsync(BlocklistParser.DomainFileName, MaxSignatureFileBytes).ConfigureAwait(false);
        files[BlocklistParser.IpFileName] = await FetchAsync(BlocklistParser.IpFileName, MaxSignatureFileBytes).ConfigureAwait(false);

        try
        {
            files[YaraRuleFileName] = await FetchAsync(YaraRuleFileName, MaxYaraFileBytes).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            if (!exception.Message.Contains("404", StringComparison.Ordinal))
            {
                warnings.Add($"{source.Name} 未提供可用的 YARA 规则包：{SafeMessage(exception)}");
            }
        }

        try
        {
            await DownloadDefenderPackWithFallbackAsync(directory, files, warnings, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // 404 表示该源不提供扩展包；其它错误（网络中断、校验失败等）必须让整个源失败，
            // 否则会提交一个缺少扩展规则的降级病毒库（2026-11-24 的降级事故即由此而来）。
            if (!exception.Message.Contains("404", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"扩展 YARA 规则包下载失败：{SafeMessage(exception)}", exception);
            }
        }

        try
        {
            files[SpecialPathMatcher.FileName] = await FetchAsync(SpecialPathMatcher.FileName, MaxSpecialPathFileBytes).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            if (!exception.Message.Contains("404", StringComparison.Ordinal))
            {
                warnings.Add($"{source.Name} 未提供特殊路径清单：{SafeMessage(exception)}");
            }
        }

        try
        {
            var versionPath = await FetchAsync(VersionFileName, MaxSignatureFileBytes).ConfigureAwait(false);
            var versionText = (await File.ReadAllTextAsync(versionPath, cancellationToken).ConfigureAwait(false)).Trim();
            if (IsValidVersion(versionText))
            {
                files[VersionFileName] = versionPath;
            }
            else
            {
                warnings.Add($"{source.Name} 的 version.txt 内容无效，将使用自动版本号。");
                File.Delete(versionPath);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"{source.Name} 未提供版本文件，将使用自动版本号。");
        }

        progress?.Report(new SignatureUpdateProgress("下载", 45, $"已从 {source.Name} 下载 {files.Count} 个数据文件。"));
        return new DownloadedSet(source, files, warnings);
    }

    private async Task DownloadDefenderPackWithFallbackAsync(string directory,
        Dictionary<string, string> files, List<string> warnings, CancellationToken cancellationToken)
    {
        var failures = new List<string>();
        foreach (var packSource in _defenderPackSources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CleanupDefenderPackOutputs(directory, files);
            try
            {
                await DownloadDefenderPackAsync(packSource, directory, files, cancellationToken).ConfigureAwait(false);
                warnings.Add($"已从 {packSource.Name} 获取扩展 YARA 规则包。");
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                if (exception.Message.Contains("404", StringComparison.Ordinal))
                {
                    // 该来源不提供扩展包，尝试下一个。
                    continue;
                }

                failures.Add($"{packSource.Name}：{SafeMessage(exception)}");
            }
        }

        CleanupDefenderPackOutputs(directory, files);
        if (failures.Count > 0)
        {
            throw new InvalidOperationException(
                "扩展 YARA 规则包的所有来源均失败（" + string.Join("；", failures.Take(3)) + "）。");
        }

        warnings.Add("所有更新源均未提供扩展 YARA 规则包。");
    }

    private async Task DownloadDefenderPackAsync(SignatureUpdateSource packSource, string directory,
        Dictionary<string, string> files, CancellationToken cancellationToken)
    {
        var manifestPath = Path.Combine(directory, DefenderPackManifestPath.Replace('/', Path.DirectorySeparatorChar));
        var manifestFolder = Path.GetDirectoryName(manifestPath);
        if (!string.IsNullOrEmpty(manifestFolder))
        {
            Directory.CreateDirectory(manifestFolder);
        }

        await DownloadToFileAsync(new Uri(packSource.BaseUri, DefenderPackManifestFileName), manifestPath,
            SignatureFileLimits.MaxBytes, cancellationToken).ConfigureAwait(false);

        var entries = ParseDefenderPackEntries(
            await File.ReadAllTextAsync(manifestPath, cancellationToken).ConfigureAwait(false));

        // 包清单未变化时直接复用本地已校验的分片，避免每次自动检查重复下载上百 MB。
        var localManifestPath = Path.Combine(_dataRoot, "current",
            DefenderPackManifestPath.Replace('/', Path.DirectorySeparatorChar));
        var localYaraDirectory = Path.Combine(_dataRoot, "current", "yara");
        if (PackEntriesMatchLocal(entries, localManifestPath) &&
            await TryReuseLocalPackAsync(localYaraDirectory, directory, entries, files, cancellationToken)
                .ConfigureAwait(false))
        {
            return;
        }

        foreach (var entry in entries)
        {
            var target = Path.Combine(directory, "yara", entry.Name);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await DownloadToFileAsync(new Uri(packSource.BaseUri, entry.Name), target,
                SignatureFileLimits.MaxBytes, cancellationToken).ConfigureAwait(false);

            var (sha256, length) = await HashFileAsync(target, cancellationToken).ConfigureAwait(false);
            if (!sha256.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase) ||
                (entry.Bytes > 0 && entry.Bytes != length))
            {
                throw new InvalidDataException($"扩展 YARA 文件校验失败：{entry.Name}");
            }

            files["yara/" + entry.Name] = target;
        }
    }

    private static List<(string Name, long Bytes, string Sha256)> ParseDefenderPackEntries(string manifestText)
    {
        using var document = JsonDocument.Parse(manifestText);
        if (!document.RootElement.TryGetProperty("files", out var filesElement) ||
            filesElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("扩展 YARA 规则包清单无效。");
        }

        var entries = new List<(string Name, long Bytes, string Sha256)>();
        foreach (var entry in filesElement.EnumerateArray())
        {
            var name = entry.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            var sha256 = entry.TryGetProperty("sha256", out var shaElement) ? shaElement.GetString() : null;
            var bytes = entry.TryGetProperty("bytes", out var bytesElement) &&
                        bytesElement.TryGetInt64(out var parsedBytes)
                ? parsedBytes
                : 0;
            if (string.IsNullOrWhiteSpace(name) ||
                !PackFileNamePattern.IsMatch(name) ||
                string.Equals(name, "rules.yar", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(sha256) ||
                sha256.Length != 64)
            {
                throw new InvalidDataException("扩展 YARA 规则包清单包含无效文件项。");
            }

            entries.Add((name, bytes, sha256));
        }

        if (entries.Count == 0)
        {
            throw new InvalidDataException("扩展 YARA 规则包为空。");
        }

        return entries;
    }

    private static bool PackEntriesMatchLocal(IReadOnlyList<(string Name, long Bytes, string Sha256)> entries,
        string localManifestPath)
    {
        if (!File.Exists(localManifestPath))
        {
            return false;
        }

        try
        {
            var localEntries = ParseDefenderPackEntries(File.ReadAllText(localManifestPath));
            if (localEntries.Count != entries.Count)
            {
                return false;
            }

            for (var index = 0; index < entries.Count; index++)
            {
                if (!string.Equals(entries[index].Name, localEntries[index].Name, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(entries[index].Sha256, localEntries[index].Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                                              or JsonException or InvalidDataException)
        {
            return false;
        }
    }

    private async Task<bool> TryReuseLocalPackAsync(string localYaraDirectory, string directory,
        IReadOnlyList<(string Name, long Bytes, string Sha256)> entries,
        Dictionary<string, string> files, CancellationToken cancellationToken)
    {
        foreach (var entry in entries)
        {
            var info = new FileInfo(Path.Combine(localYaraDirectory, entry.Name));
            if (!info.Exists || (entry.Bytes > 0 && info.Length != entry.Bytes))
            {
                return false;
            }
        }

        foreach (var entry in entries)
        {
            var target = Path.Combine(directory, "yara", entry.Name);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(Path.Combine(localYaraDirectory, entry.Name), target, overwrite: true);

            var (sha256, length) = await HashFileAsync(target, cancellationToken).ConfigureAwait(false);
            if (!sha256.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase) ||
                (entry.Bytes > 0 && entry.Bytes != length))
            {
                return false;
            }

            files["yara/" + entry.Name] = target;
        }

        return true;
    }

    private static void CleanupDefenderPackOutputs(string directory, Dictionary<string, string> files)
    {
        var yaraDirectory = Path.Combine(directory, "yara");
        if (Directory.Exists(yaraDirectory))
        {
            foreach (var path in Directory.EnumerateFiles(yaraDirectory, "defender-patterns-*", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    File.Delete(path);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                }
            }
        }

        foreach (var key in files.Keys
                     .Where(key => key.StartsWith("yara/defender-", StringComparison.OrdinalIgnoreCase))
                     .ToList())
        {
            files.Remove(key);
        }
    }

    private static async Task<string?> ResolveVersionAsync(Dictionary<string, string> files, CancellationToken cancellationToken)
    {
        if (!files.TryGetValue(VersionFileName, out var path))
        {
            return null;
        }

        try
        {
            var text = (await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false)).Trim();
            return IsValidVersion(text) ? text : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static bool IsValidVersion(string value) =>
        value.Length is > 0 and <= 48 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_');

    private static bool IsCandidateNewer(string? candidateVersion, string? currentVersion)
    {
        if (string.IsNullOrWhiteSpace(currentVersion))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(candidateVersion))
        {
            return false;
        }

        var candidateHasParts = TryParseVersion(candidateVersion, out var candidateParts);
        var currentHasParts = TryParseVersion(currentVersion, out var currentParts);
        if (candidateHasParts && currentHasParts)
        {
            return CompareVersionParts(candidateParts, currentParts) > 0;
        }

        if (candidateHasParts)
        {
            return true;
        }

        if (currentHasParts)
        {
            return false;
        }

        return !string.Equals(candidateVersion, currentVersion, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseVersion(string value, out int[] parts)
    {
        parts = Array.Empty<int>();
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64)
        {
            return false;
        }

        var segments = value.Split('.');
        if (segments.Length is < 2 or > 8)
        {
            return false;
        }

        var result = new int[segments.Length];
        for (var index = 0; index < segments.Length; index++)
        {
            if (!int.TryParse(segments[index], NumberStyles.None, CultureInfo.InvariantCulture, out var part) || part < 0)
            {
                return false;
            }

            result[index] = part;
        }

        parts = result;
        return true;
    }

    private static bool AllowYaraRegression() =>
        string.Equals(Environment.GetEnvironmentVariable(AllowYaraRegressionEnvironmentVariable), "1",
            StringComparison.OrdinalIgnoreCase);

    private static int CompareVersionParts(int[] left, int[] right)
    {
        var length = Math.Max(left.Length, right.Length);
        for (var index = 0; index < length; index++)
        {
            var leftPart = index < left.Length ? left[index] : 0;
            var rightPart = index < right.Length ? right[index] : 0;
            if (leftPart != rightPart)
            {
                return leftPart.CompareTo(rightPart);
            }
        }

        return 0;
    }

    private async Task DownloadToFileAsync(Uri uri, string targetPath, long maxBytes, CancellationToken cancellationToken)
    {
        var builder = new UriBuilder(uri);
        var query = builder.Query.TrimStart('?');
        var cacheBuster = "aegis=" + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        builder.Query = string.IsNullOrEmpty(query) ? cacheBuster : query + "&" + cacheBuster;
        uri = builder.Uri;

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true };
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new HttpRequestException($"HTTP {(int)response.StatusCode}");
        }

        if (response.Content.Headers.ContentLength is { } contentLength && contentLength > maxBytes)
        {
            throw new InvalidDataException("服务器返回的文件过大。");
        }

        await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None,
            CopyBufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var buffer = new byte[CopyBufferSize];
        long total = 0;
        while (true)
        {
            var read = await responseStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > maxBytes)
            {
                throw new InvalidDataException("下载内容超过大小限制。");
            }

            await fileStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        if (total == 0)
        {
            throw new InvalidDataException("服务器返回空文件。");
        }
    }

    private static async Task<(string Sha256, long Bytes)> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            CopyBufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[CopyBufferSize];
        long total = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            hasher.AppendData(buffer, 0, read);
            total += read;
        }

        return (Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant(), total);
    }

    private async Task<SignatureManifest?> TryReadCurrentManifestAsync(CancellationToken cancellationToken)
    {
        var path = Path.Combine(_dataRoot, "current", "manifest.json");
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            return await SignatureManifest.ReadAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return null;
        }
    }

    private static async Task<ParsedCounts> ValidateAsync(Dictionary<string, string> files, CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        HashParseResult hashResult;
        IndicatorParseResult domainResult;
        IndicatorParseResult ipResult;

        await using (var stream = OpenRead(files[BlocklistParser.HashFileName]))
        {
            hashResult = await BlocklistParser.ParseHashesAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = OpenRead(files[BlocklistParser.DomainFileName]))
        {
            domainResult = await BlocklistParser.ParseDomainsAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = OpenRead(files[BlocklistParser.IpFileName]))
        {
            ipResult = await BlocklistParser.ParseIpsAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        warnings.AddRange(hashResult.Warnings);
        warnings.AddRange(domainResult.Warnings);
        warnings.AddRange(ipResult.Warnings);

        var yaraRules = 0;
        if (files.TryGetValue(YaraRuleFileName, out var yaraPath))
        {
            var yaraSet = YaraRuleSet.Parse(await File.ReadAllTextAsync(yaraPath, cancellationToken).ConfigureAwait(false), YaraRuleFileName);
            if (yaraSet.RuleCount == 0)
            {
                files.Remove(YaraRuleFileName);
                File.Delete(yaraPath);
                warnings.Add("下载的 YARA 规则包没有可加载的规则，已忽略。");
            }
            else
            {
                yaraRules = yaraSet.RuleCount;
                if (yaraSet.SkippedCount > 0)
                {
                    warnings.Add($"YARA 规则包已加载 {yaraSet.RuleCount} 条规则，跳过 {yaraSet.SkippedCount} 条不支持的规则。");
                }

                foreach (var warning in yaraSet.Warnings)
                {
                    if (warnings.Count >= 40)
                    {
                        break;
                    }

                    warnings.Add(warning);
                }
            }
        }

        var extraKeys = files.Keys
            .Where(key => key.StartsWith("yara/", StringComparison.OrdinalIgnoreCase) &&
                          !string.Equals(key, YaraRuleFileName, StringComparison.OrdinalIgnoreCase) &&
                          (key.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                           key.EndsWith(".yara", StringComparison.OrdinalIgnoreCase)))
            .ToList();
        foreach (var key in extraKeys)
        {
            var path = files[key];
            var name = Path.GetFileName(path);
            var extraSet = YaraRuleSet.Parse(
                await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false), name);
            if (extraSet.RuleCount == 0)
            {
                files.Remove(key);
                File.Delete(path);
                warnings.Add($"扩展 YARA 规则文件 {name} 没有可加载的规则，已忽略。");
                continue;
            }

            yaraRules += extraSet.RuleCount;
            if (extraSet.SkippedCount > 0)
            {
                warnings.Add($"{name} 已加载 {extraSet.RuleCount} 条规则，跳过 {extraSet.SkippedCount} 条不支持的规则。");
            }
        }

        var specialPaths = 0;
        if (files.TryGetValue(SpecialPathMatcher.FileName, out var specialPath))
        {
            await using var stream = OpenRead(specialPath);
            var specialPathResult = await SpecialPathParser.ParseAsync(stream, cancellationToken).ConfigureAwait(false);
            specialPaths = specialPathResult.Matcher.Count;
            if (specialPaths == 0)
            {
                files.Remove(SpecialPathMatcher.FileName);
                File.Delete(specialPath);
                warnings.Add("下载的特殊路径清单没有有效条目，已忽略。");
            }
            else
            {
                foreach (var warning in specialPathResult.Warnings)
                {
                    if (warnings.Count >= 40)
                    {
                        break;
                    }

                    warnings.Add(warning);
                }
            }
        }

        return new ParsedCounts(hashResult.Hashes.Count, domainResult.Values.Count, ipResult.Values.Count,
            yaraRules, specialPaths, warnings);
    }

    private static FileStream OpenRead(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.Read,
        CopyBufferSize, FileOptions.Asynchronous | FileOptions.SequentialScan);

    private void Commit(string staging)
    {
        var current = Path.Combine(_dataRoot, "current");
        var previous = Path.Combine(_dataRoot, "previous");

        if (Directory.Exists(previous))
        {
            Directory.Delete(previous, recursive: true);
        }

        var hadCurrent = Directory.Exists(current);
        if (hadCurrent)
        {
            Directory.Move(current, previous);
        }

        try
        {
            Directory.Move(staging, current);
        }
        catch
        {
            if (hadCurrent && Directory.Exists(previous) && !Directory.Exists(current))
            {
                Directory.Move(previous, current);
            }

            throw;
        }
    }

    private static void DeleteDirectoryQuietly(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (IOException)
        {
            // A stale directory is harmless; the next run uses a new name.
        }
    }

    private static string SafeMessage(Exception exception) => exception switch
    {
        HttpRequestException => "网络请求失败。",
        TaskCanceledException => "请求超时。",
        InvalidDataException => exception.Message,
        InvalidOperationException => exception.Message,
        IOException => "文件写入失败。",
        UnauthorizedAccessException => "没有写入病毒库目录的权限。",
        JsonException => "服务器返回了无效数据。",
        _ => exception.GetType().Name
    };

    private sealed record DownloadedSet(SignatureUpdateSource Source, Dictionary<string, string> Files, List<string> Warnings);

    private sealed record ParsedCounts(int HashCount, int DomainCount, int IpCount, int YaraRules,
        int SpecialPaths, List<string> Warnings);
}
