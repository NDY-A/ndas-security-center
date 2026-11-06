using System.Security.Cryptography;
using Aegis.Core.Infrastructure;
using Aegis.Core.Yara;

namespace Aegis.Core.Signatures;

public sealed class SignatureRepository
{
    private static readonly string[] RequiredFiles =
    {
        BlocklistParser.HashFileName,
        BlocklistParser.DomainFileName,
        BlocklistParser.IpFileName
    };

    private readonly string _dataRoot;
    private readonly string _seedDirectory;

    public SignatureRepository(string dataRoot, string seedDirectory)
    {
        _dataRoot = dataRoot;
        _seedDirectory = seedDirectory;
    }

    public string CurrentDirectory => Path.Combine(_dataRoot, "current");

    public string PreviousDirectory => Path.Combine(_dataRoot, "previous");

    public string SeedDirectory => _seedDirectory;

    public async Task<SignatureSnapshot> LoadAsync(CancellationToken cancellationToken = default)
    {
        var warnings = new List<string>();

        if (Directory.Exists(CurrentDirectory))
        {
            try
            {
                return await LoadDirectoryAsync(CurrentDirectory, cancellationToken,
                    Path.Combine(_seedDirectory, "yara"),
                    Path.Combine(_seedDirectory, SpecialPathMatcher.FileName)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception)
            {
                warnings.Add("本地病毒库未通过完整性校验，已回退到内置种子库：" + SafeMessage(exception));
            }
        }
        else
        {
            warnings.Add("尚未下载独立病毒库，当前使用内置种子库。");
        }

        if (!Directory.Exists(_seedDirectory))
        {
            throw new InvalidOperationException("找不到内置病毒库，且没有可用的本地病毒库。");
        }

        try
        {
            var snapshot = await LoadDirectoryAsync(_seedDirectory, cancellationToken).ConfigureAwait(false);
            return new SignatureSnapshot
            {
                Version = snapshot.Version,
                Source = snapshot.Source,
                FetchedAt = snapshot.FetchedAt,
                IsSeed = true,
                SourceDirectory = snapshot.SourceDirectory,
                Hashes = snapshot.Hashes,
                Domains = snapshot.Domains,
                IpAddresses = snapshot.IpAddresses,
                Yara = snapshot.Yara,
                SpecialPaths = snapshot.SpecialPaths,
                Warnings = warnings.Concat(snapshot.Warnings).ToArray()
            };
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new InvalidOperationException("内置病毒库不可用：" + SafeMessage(exception), exception);
        }
    }

    public static async Task<SignatureSnapshot> LoadDirectoryAsync(string directory, CancellationToken cancellationToken,
        string? yaraFallbackDirectory = null, string? specialPathFallbackFile = null)
    {
        var manifestPath = Path.Combine(directory, "manifest.json");
        var manifest = await SignatureManifest.ReadAsync(manifestPath, cancellationToken).ConfigureAwait(false);
        var warnings = new List<string>();

        foreach (var fileName in RequiredFiles)
        {
            if (!manifest.Files.ContainsKey(fileName))
            {
                throw new InvalidDataException($"病毒库清单缺少 {fileName} 的完整性信息。");
            }
        }

        var fileBytes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var fileName in RequiredFiles)
        {
            var path = Path.Combine(directory, fileName);
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                throw new FileNotFoundException($"病毒库文件缺失：{fileName}", path);
            }

            if (info.Length > 16 * 1024 * 1024)
            {
                throw new InvalidDataException($"病毒库文件 {fileName} 大小异常。");
            }

            var bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            var actualHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var expected = manifest.Files[fileName].Sha256;
            if (!expected.Equals(actualHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"病毒库文件 {fileName} 的 SHA-256 与清单不一致。");
            }

            if (manifest.Files[fileName].Bytes > 0 && manifest.Files[fileName].Bytes != bytes.LongLength)
            {
                warnings.Add($"{fileName} 的字节数与清单记录不一致。");
            }

            fileBytes[fileName] = bytes;
        }

        byte[]? specialPathBytes = null;
        if (manifest.Files.TryGetValue(SpecialPathMatcher.FileName, out var specialPathManifest))
        {
            var path = Path.Combine(directory, SpecialPathMatcher.FileName);
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                throw new FileNotFoundException($"病毒库文件缺失：{SpecialPathMatcher.FileName}", path);
            }

            if (info.Length > 4 * 1024 * 1024)
            {
                throw new InvalidDataException($"病毒库文件 {SpecialPathMatcher.FileName} 大小异常。");
            }

            specialPathBytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            var actualHash = Convert.ToHexString(SHA256.HashData(specialPathBytes)).ToLowerInvariant();
            if (!specialPathManifest.Sha256.Equals(actualHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"病毒库文件 {SpecialPathMatcher.FileName} 的 SHA-256 与清单不一致。");
            }

            if (specialPathManifest.Bytes > 0 && specialPathManifest.Bytes != specialPathBytes.LongLength)
            {
                warnings.Add($"{SpecialPathMatcher.FileName} 的字节数与清单记录不一致。");
            }
        }
        else if (!string.IsNullOrWhiteSpace(specialPathFallbackFile) && File.Exists(specialPathFallbackFile))
        {
            specialPathBytes = await File.ReadAllBytesAsync(specialPathFallbackFile, cancellationToken).ConfigureAwait(false);
            warnings.Add("当前病毒库未包含特殊路径列表，已使用内置列表。");
        }

        HashParseResult hashResult;
        IndicatorParseResult domainResult;
        IndicatorParseResult ipResult;
        await using (var stream = new MemoryStream(fileBytes[BlocklistParser.HashFileName], writable: false))
        {
            hashResult = await BlocklistParser.ParseHashesAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = new MemoryStream(fileBytes[BlocklistParser.DomainFileName], writable: false))
        {
            domainResult = await BlocklistParser.ParseDomainsAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = new MemoryStream(fileBytes[BlocklistParser.IpFileName], writable: false))
        {
            ipResult = await BlocklistParser.ParseIpsAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        if (hashResult.Hashes.Count == 0)
        {
            throw new InvalidDataException("病毒库不包含有效文件哈希。");
        }

        warnings.AddRange(hashResult.Warnings);
        warnings.AddRange(domainResult.Warnings);
        warnings.AddRange(ipResult.Warnings);

        SpecialPathMatcher specialPaths = SpecialPathMatcher.Empty;
        if (specialPathBytes is not null)
        {
            await using var stream = new MemoryStream(specialPathBytes, writable: false);
            var specialResult = await SpecialPathParser.ParseAsync(stream, cancellationToken).ConfigureAwait(false);
            specialPaths = specialResult.Matcher;
            warnings.AddRange(specialResult.Warnings);
        }

        YaraRuleSet yaraRules;
        try
        {
            yaraRules = YaraRuleSet.LoadDirectory(Path.Combine(directory, "yara"));
            warnings.AddRange(yaraRules.Warnings);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            warnings.Add("YARA 规则加载失败：" + SafeMessage(exception));
            yaraRules = YaraRuleSet.Empty;
        }

        if (yaraRules.RuleCount == 0 && !string.IsNullOrWhiteSpace(yaraFallbackDirectory))
        {
            try
            {
                var fallback = YaraRuleSet.LoadDirectory(yaraFallbackDirectory);
                if (fallback.RuleCount > 0)
                {
                    yaraRules = fallback;
                    warnings.Add("当前病毒库未包含 YARA 规则，已使用内置规则库。");
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // The current snapshot simply keeps the built-in-empty rule set.
            }
        }

        if (manifest.Counts is not null)
        {
            if (manifest.Counts.Hashes != 0 && manifest.Counts.Hashes != hashResult.Hashes.Count)
            {
                warnings.Add($"哈希数量与清单不一致（清单 {manifest.Counts.Hashes}，实际 {hashResult.Hashes.Count}）。");
            }

            if (manifest.Counts.Domains != 0 && manifest.Counts.Domains != domainResult.Values.Count)
            {
                warnings.Add($"域名数量与清单不一致（清单 {manifest.Counts.Domains}，实际 {domainResult.Values.Count}）。");
            }

            if (manifest.Counts.Ips != 0 && manifest.Counts.Ips != ipResult.Values.Count)
            {
                warnings.Add($"IP 数量与清单不一致（清单 {manifest.Counts.Ips}，实际 {ipResult.Values.Count}）。");
            }

            if (manifest.Counts.YaraRules != 0 && manifest.Counts.YaraRules != yaraRules.RuleCount)
            {
                warnings.Add($"YARA 规则数量与清单不一致（清单 {manifest.Counts.YaraRules}，实际 {yaraRules.RuleCount}）。");
            }

            if (manifest.Counts.SpecialPaths != 0 && manifest.Counts.SpecialPaths != specialPaths.Count)
            {
                warnings.Add($"特殊路径数量与清单不一致（清单 {manifest.Counts.SpecialPaths}，实际 {specialPaths.Count}）。");
            }
        }

        return new SignatureSnapshot
        {
            Version = string.IsNullOrWhiteSpace(manifest.Version) ? "unknown" : manifest.Version,
            Source = manifest.Source,
            FetchedAt = manifest.FetchedAt,
            IsSeed = manifest.IsSeed,
            SourceDirectory = directory,
            Hashes = hashResult.Hashes,
            Domains = new DomainMatcher(domainResult.Values.Keys),
            IpAddresses = new IpMatcher(ipResult.Values.Keys),
            Yara = yaraRules,
            SpecialPaths = specialPaths,
            Warnings = warnings
        };
    }

    private static string SafeMessage(Exception exception) => exception switch
    {
        FileNotFoundException => "找不到必要文件。",
        InvalidDataException => exception.Message,
        IOException => "读取病毒库时发生 I/O 错误。",
        UnauthorizedAccessException => "没有读取病毒库的权限。",
        _ => exception.GetType().Name
    };
}
