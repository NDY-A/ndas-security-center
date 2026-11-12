using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
    private const long MaxFileBytes = 16L * 1024 * 1024;
    private const long MaxYaraFileBytes = 32L * 1024 * 1024;
    private const long MaxSpecialPathFileBytes = 1024L * 1024;
    private readonly string _dataRoot;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly IReadOnlyList<SignatureUpdateSource> _sources;

    public SignatureUpdater(string dataRoot, HttpClient? httpClient = null, IEnumerable<SignatureUpdateSource>? sources = null)
    {
        _dataRoot = dataRoot;
        _sources = (sources ?? DefaultSources()).ToArray();
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

    public async Task<SignatureUpdateResult> UpdateAsync(
        IProgress<SignatureUpdateProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var warnings = new List<string>();
        var staging = Path.Combine(_dataRoot, ".staging-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dataRoot);

        try
        {
            DownloadedSet? downloaded = null;
            Exception? lastError = null;
            var currentManifest = await TryReadCurrentManifestAsync(cancellationToken).ConfigureAwait(false);
            var sawDownload = false;

            progress?.Report(new SignatureUpdateProgress("检查", 10, "正在比较当前病毒库…"));

            foreach (var source in _sources)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    progress?.Report(new SignatureUpdateProgress("下载", 10, $"正在连接 {source.Name}…"));
                    var candidate = await DownloadSetAsync(source, progress, cancellationToken).ConfigureAwait(false);
                    sawDownload = true;
                    var candidateVersion = ResolveVersion(candidate.Files);
                    if (!IsCandidateNewer(candidateVersion, currentManifest?.Version))
                    {
                        warnings.Add($"{source.Name} 返回旧版本 {candidateVersion ?? "无版本号"}（当前 {currentManifest?.Version ?? "无"}），已跳过。");
                        continue;
                    }

                    downloaded = candidate;
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
            var parsed = await ValidateAsync(downloaded, cancellationToken).ConfigureAwait(false);
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

            Directory.CreateDirectory(staging);
            foreach (var pair in downloaded.Files)
            {
                var target = Path.Combine(staging, pair.Key);
                var folder = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(folder))
                {
                    Directory.CreateDirectory(folder);
                }

                await File.WriteAllBytesAsync(target, pair.Value, cancellationToken).ConfigureAwait(false);
            }

            var fetchedAt = DateTimeOffset.UtcNow;
            var combinedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(
                string.Concat(downloaded.Files.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => x.Value.Length + ":" + Convert.ToHexString(SHA256.HashData(x.Value)))) +
                downloaded.Source.BaseUri.AbsoluteUri));
            var fallbackVersion = $"github-{fetchedAt:yyyy.MM.dd-HHmm}-{Convert.ToHexString(combinedDigest)[..8].ToLowerInvariant()}";
            var version = ResolveVersion(downloaded.Files) ?? fallbackVersion;

            var manifest = new SignatureManifest
            {
                SchemaVersion = 1,
                Version = version,
                Source = downloaded.Source.BaseUri.AbsoluteUri,
                FetchedAt = fetchedAt,
                IsSeed = false,
                Files = downloaded.Files.ToDictionary(
                    pair => pair.Key,
                    pair => new ManifestFileInfo
                    {
                        Sha256 = Convert.ToHexString(SHA256.HashData(pair.Value)).ToLowerInvariant(),
                        Bytes = pair.Value.LongLength
                    },
                    StringComparer.OrdinalIgnoreCase),
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
            if (Directory.Exists(staging))
            {
                try
                {
                    Directory.Delete(staging, recursive: true);
                }
                catch (IOException)
                {
                    // A stale staging directory is harmless; the next update uses a new name.
                }
            }
        }
    }

    private async Task<DownloadedSet> DownloadSetAsync(
        SignatureUpdateSource source,
        IProgress<SignatureUpdateProgress>? progress,
        CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
        {
            [BlocklistParser.HashFileName] = await DownloadAsync(new Uri(source.BaseUri, BlocklistParser.HashFileName), cancellationToken).ConfigureAwait(false),
            [BlocklistParser.DomainFileName] = await DownloadAsync(new Uri(source.BaseUri, BlocklistParser.DomainFileName), cancellationToken).ConfigureAwait(false),
            [BlocklistParser.IpFileName] = await DownloadAsync(new Uri(source.BaseUri, BlocklistParser.IpFileName), cancellationToken).ConfigureAwait(false)
        };

        try
        {
            files[YaraRuleFileName] = await DownloadAsync(
                new Uri(source.BaseUri, YaraRuleFileName), cancellationToken, MaxYaraFileBytes).ConfigureAwait(false);
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
            files[SpecialPathMatcher.FileName] = await DownloadAsync(
                new Uri(source.BaseUri, SpecialPathMatcher.FileName), cancellationToken,
                MaxSpecialPathFileBytes).ConfigureAwait(false);
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
            var versionBytes = await DownloadAsync(new Uri(source.BaseUri, VersionFileName), cancellationToken).ConfigureAwait(false);
            var versionText = Encoding.UTF8.GetString(versionBytes).Trim();
            if (IsValidVersion(versionText))
            {
                files[VersionFileName] = versionBytes;
            }
            else
            {
                warnings.Add($"{source.Name} 的 version.txt 内容无效，将使用自动版本号。");
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            warnings.Add($"{source.Name} 未提供版本文件，将使用自动版本号。");
        }

        progress?.Report(new SignatureUpdateProgress("下载", 45, $"已从 {source.Name} 下载 {files.Count} 个数据文件。"));
        return new DownloadedSet(source, files, warnings);
    }

    private static string? ResolveVersion(Dictionary<string, byte[]> files)
    {
        if (!files.TryGetValue(VersionFileName, out var bytes))
        {
            return null;
        }

        var text = Encoding.UTF8.GetString(bytes).Trim();
        return IsValidVersion(text) ? text : null;
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

    private async Task<byte[]> DownloadAsync(Uri uri, CancellationToken cancellationToken, long maxBytes = MaxFileBytes)
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
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        long total = 0;
        while (true)
        {
            var read = await responseStream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > maxBytes)
            {
                throw new InvalidDataException("下载内容超过大小限制。");
            }

            buffer.Write(chunk, 0, read);
        }

        if (buffer.Length == 0)
        {
            throw new InvalidDataException("服务器返回空文件。");
        }

        return buffer.ToArray();
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

    private static async Task<ParsedCounts> ValidateAsync(DownloadedSet downloaded, CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        HashParseResult hashResult;
        IndicatorParseResult domainResult;
        IndicatorParseResult ipResult;

        await using (var stream = new MemoryStream(downloaded.Files[BlocklistParser.HashFileName], writable: false))
        {
            hashResult = await BlocklistParser.ParseHashesAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = new MemoryStream(downloaded.Files[BlocklistParser.DomainFileName], writable: false))
        {
            domainResult = await BlocklistParser.ParseDomainsAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = new MemoryStream(downloaded.Files[BlocklistParser.IpFileName], writable: false))
        {
            ipResult = await BlocklistParser.ParseIpsAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        warnings.AddRange(hashResult.Warnings);
        warnings.AddRange(domainResult.Warnings);
        warnings.AddRange(ipResult.Warnings);

        var yaraRules = 0;
        if (downloaded.Files.TryGetValue(YaraRuleFileName, out var yaraBytes))
        {
            var yaraSet = YaraRuleSet.Parse(Encoding.UTF8.GetString(yaraBytes), YaraRuleFileName);
            if (yaraSet.RuleCount == 0)
            {
                downloaded.Files.Remove(YaraRuleFileName);
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

        var specialPaths = 0;
        if (downloaded.Files.TryGetValue(SpecialPathMatcher.FileName, out var specialPathBytes))
        {
            await using var stream = new MemoryStream(specialPathBytes, writable: false);
            var specialPathResult = await SpecialPathParser.ParseAsync(stream, cancellationToken).ConfigureAwait(false);
            specialPaths = specialPathResult.Matcher.Count;
            if (specialPaths == 0)
            {
                downloaded.Files.Remove(SpecialPathMatcher.FileName);
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

    private static string SafeMessage(Exception exception) => exception switch
    {
        HttpRequestException => "网络请求失败。",
        TaskCanceledException => "请求超时。",
        InvalidDataException => exception.Message,
        IOException => "文件写入失败。",
        UnauthorizedAccessException => "没有写入病毒库目录的权限。",
        JsonException => "服务器返回了无效数据。",
        _ => exception.GetType().Name
    };

    private sealed record DownloadedSet(SignatureUpdateSource Source, Dictionary<string, byte[]> Files, List<string> Warnings);

    private sealed record ParsedCounts(int HashCount, int DomainCount, int IpCount, int YaraRules,
        int SpecialPaths, List<string> Warnings);
}
