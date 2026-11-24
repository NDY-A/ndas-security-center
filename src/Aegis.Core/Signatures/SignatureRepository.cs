using System.Security.Cryptography;
using System.Text.Json;
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

    public async Task<SignatureSnapshot> LoadAsync(CancellationToken cancellationToken = default,
        bool includeExtendedRulePack = true)
    {
        var warnings = new List<string>();

        if (Directory.Exists(CurrentDirectory))
        {
            try
            {
                return await LoadDirectoryAsync(CurrentDirectory, cancellationToken,
                    Path.Combine(_seedDirectory, "yara"),
                    Path.Combine(_seedDirectory, SpecialPathMatcher.FileName),
                    Path.Combine(_seedDirectory, TrustedHashIndex.RelativePath),
                    includeExtendedRulePack).ConfigureAwait(false);
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
            var snapshot = await LoadDirectoryAsync(_seedDirectory, cancellationToken,
                includeExtendedRulePack: includeExtendedRulePack).ConfigureAwait(false);
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
                TrustedHashes = snapshot.TrustedHashes,
                ExtendedRuleEngineIIEnabled = snapshot.ExtendedRuleEngineIIEnabled,
                ExtendedRulePackSkippedFiles = snapshot.ExtendedRulePackSkippedFiles,
                Warnings = warnings.Concat(snapshot.Warnings).ToArray()
            };
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new InvalidOperationException("内置病毒库不可用：" + SafeMessage(exception), exception);
        }
    }

    public static async Task<SignatureSnapshot> LoadDirectoryAsync(string directory, CancellationToken cancellationToken,
        string? yaraFallbackDirectory = null, string? specialPathFallbackFile = null,
        string? trustedHashFallbackFile = null, bool includeExtendedRulePack = true)
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

        var filePaths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fileName in RequiredFiles)
        {
            var path = Path.Combine(directory, fileName);
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                throw new FileNotFoundException($"病毒库文件缺失：{fileName}", path);
            }

            if (info.Length > SignatureFileLimits.MaxBytes)
            {
                throw new InvalidDataException($"病毒库文件 {fileName} 大小异常。");
            }

            await VerifyDigestAsync(path, fileName, manifest.Files[fileName].Sha256, cancellationToken).ConfigureAwait(false);
            if (manifest.Files[fileName].Bytes > 0 && manifest.Files[fileName].Bytes != info.Length)
            {
                warnings.Add($"{fileName} 的字节数与清单记录不一致。");
            }

            filePaths[fileName] = path;
        }

        string? specialPathFile = null;
        if (manifest.Files.TryGetValue(SpecialPathMatcher.FileName, out var specialPathManifest))
        {
            var path = Path.Combine(directory, SpecialPathMatcher.FileName);
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                throw new FileNotFoundException($"病毒库文件缺失：{SpecialPathMatcher.FileName}", path);
            }

            if (info.Length > SignatureFileLimits.MaxBytes)
            {
                throw new InvalidDataException($"病毒库文件 {SpecialPathMatcher.FileName} 大小异常。");
            }

            await VerifyDigestAsync(path, SpecialPathMatcher.FileName, specialPathManifest.Sha256, cancellationToken).ConfigureAwait(false);
            if (specialPathManifest.Bytes > 0 && specialPathManifest.Bytes != info.Length)
            {
                warnings.Add($"{SpecialPathMatcher.FileName} 的字节数与清单记录不一致。");
            }

            specialPathFile = path;
        }
        else if (!string.IsNullOrWhiteSpace(specialPathFallbackFile) && File.Exists(specialPathFallbackFile))
        {
            specialPathFile = specialPathFallbackFile;
            warnings.Add("当前病毒库未包含特殊路径列表，已使用内置列表。");
        }

        HashParseResult hashResult;
        IndicatorParseResult domainResult;
        IndicatorParseResult ipResult;
        await using (var stream = OpenRead(filePaths[BlocklistParser.HashFileName]))
        {
            hashResult = await BlocklistParser.ParseHashesAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = OpenRead(filePaths[BlocklistParser.DomainFileName]))
        {
            domainResult = await BlocklistParser.ParseDomainsAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        await using (var stream = OpenRead(filePaths[BlocklistParser.IpFileName]))
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
        if (specialPathFile is not null)
        {
            await using var stream = OpenRead(specialPathFile);
            var specialResult = await SpecialPathParser.ParseAsync(stream, cancellationToken).ConfigureAwait(false);
            specialPaths = specialResult.Matcher;
            warnings.AddRange(specialResult.Warnings);
        }

        TrustedHashIndex trustedHashes = TrustedHashIndex.Empty;
        var trustedHashPath = Path.Combine(directory, TrustedHashIndex.RelativePath);
        if (File.Exists(trustedHashPath))
        {
            try
            {
                trustedHashes = await TrustedHashIndex.LoadAsync(trustedHashPath, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                warnings.Add("可信哈希库加载失败：" + SafeMessage(exception));
            }
        }
        else if (!string.IsNullOrWhiteSpace(trustedHashFallbackFile) && File.Exists(trustedHashFallbackFile))
        {
            try
            {
                trustedHashes = await TrustedHashIndex.LoadAsync(trustedHashFallbackFile, cancellationToken).ConfigureAwait(false);
                warnings.Add("当前病毒库未包含可信哈希库，已使用内置列表。");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                warnings.Add("内置可信哈希库加载失败：" + SafeMessage(exception));
            }
        }

        var excludedYaraFiles = includeExtendedRulePack
            ? null
            : ResolveExtendedPackFileNames(Path.Combine(directory, "yara"));
        YaraRuleSet yaraRules;
        try
        {
            yaraRules = YaraRuleSet.LoadDirectory(Path.Combine(directory, "yara"), excludedYaraFiles);
            warnings.AddRange(yaraRules.Warnings);
            if (excludedYaraFiles is { Count: > 0 })
            {
                warnings.Add($"增强型规则引擎 II 未启用，跳过 {excludedYaraFiles.Count} 个扩展规则分片" +
                             $"（已加载 {yaraRules.RuleCount:N0} 条 YARA 规则）。");
            }
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

            if (manifest.Counts.YaraRules != 0 && manifest.Counts.YaraRules != yaraRules.RuleCount &&
                excludedYaraFiles is not { Count: > 0 })
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
            TrustedHashes = trustedHashes,
            ExtendedRuleEngineIIEnabled = includeExtendedRulePack,
            ExtendedRulePackSkippedFiles = excludedYaraFiles?.Count ?? 0,
            Warnings = warnings
        };
    }

    public static IReadOnlyCollection<string> ResolveExtendedPackFileNames(string yaraDirectory)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var packManifestPath = Path.Combine(yaraDirectory, "defender", "manifest.json");
        if (File.Exists(packManifestPath))
        {
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(packManifestPath));
                if (document.RootElement.TryGetProperty("files", out var filesElement) &&
                    filesElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var entry in filesElement.EnumerateArray())
                    {
                        var name = entry.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            names.Add(Path.GetFileName(name));
                        }
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
            {
                // 包清单损坏时退回按文件名模式识别扩展分片。
            }
        }

        try
        {
            foreach (var path in Directory.EnumerateFiles(yaraDirectory, "defender-patterns-*", SearchOption.TopDirectoryOnly))
            {
                var extension = Path.GetExtension(path);
                if (extension.Equals(".yar", StringComparison.OrdinalIgnoreCase) ||
                    extension.Equals(".yara", StringComparison.OrdinalIgnoreCase))
                {
                    names.Add(Path.GetFileName(path));
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return names;
    }

    private static FileStream OpenRead(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.Read,
        1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static async Task VerifyDigestAsync(string path, string fileName, string expectedSha256,
        CancellationToken cancellationToken)
    {
        await using var stream = OpenRead(path);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            hasher.AppendData(buffer, 0, read);
        }

        var actualHash = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        if (!expectedSha256.Equals(actualHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"病毒库文件 {fileName} 的 SHA-256 与清单不一致。");
        }
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
