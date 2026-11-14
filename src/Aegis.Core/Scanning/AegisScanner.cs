using System.Diagnostics;
using System.Security.Cryptography;
using Aegis.Core.Cloud;
using Aegis.Core.Heuristics;
using Aegis.Core.Infrastructure;
using Aegis.Core.Models;
using Aegis.Core.Signatures;
using Aegis.ML;

namespace Aegis.Core.Scanning;

public sealed class AegisScanner
{
    public const string EngineVersion = "0.1.0";
    private const int HeaderBytes = 512;
    private const int MaliciousThreshold = 90;
    private const int PuaThreshold = 80;
    private const int AttentionThreshold = 70;
    private const int CloudSuspiciousThreshold = 20;

    private readonly ICloudReputationService _cloud;
    private readonly HeuristicEngine _heuristics;

    public AegisScanner(SignatureSnapshot signatures, ICloudReputationService? cloud = null)
    {
        Signatures = signatures;
        _cloud = cloud ?? DisabledCloudReputationService.Instance;
        _heuristics = new HeuristicEngine(signatures);
    }

    public SignatureSnapshot Signatures { get; }

    public ICloudReputationService Cloud => _cloud;

    public async Task<FileScanResult> ScanFileAsync(string path, ScanOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        options ??= ScanOptions.Default;
        var stopwatch = Stopwatch.StartNew();
        var fullPath = Path.GetFullPath(path);
        var fileInfo = new FileInfo(fullPath);
        if (!fileInfo.Exists)
        {
            throw new FileNotFoundException("扫描目标不存在。", fullPath);
        }

        if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return SkippedResult(fullPath, fileInfo.Length, "跳过重解析点/符号链接，避免目录循环。", stopwatch.Elapsed);
        }

        if (fileInfo.Length > options.MaxFileSizeBytes)
        {
            return SkippedResult(fullPath, fileInfo.Length, $"文件超过扫描大小上限（{FormatBytes(options.MaxFileSizeBytes)}）。", stopwatch.Elapsed);
        }

        var hashed = await HashFileAsync(fullPath, cancellationToken).ConfigureAwait(false);
        var kind = FileKindDetector.Detect(fullPath, hashed.Header);
        if (options.AllowedHashes.Any(hash => string.Equals(hash, hashed.Sha256, StringComparison.OrdinalIgnoreCase)))
        {
            stopwatch.Stop();
            return new FileScanResult
            {
                FilePath = fullPath,
                FileName = Path.GetFileName(fullPath),
                Size = hashed.Size,
                Sha256 = hashed.Sha256,
                Kind = kind,
                Verdict = ThreatVerdict.Clean,
                Score = 0,
                Detections = Array.Empty<Detection>(),
                Notes = new[] { "SHA-256 在白名单中，已跳过检测。" },
                ScanDuration = stopwatch.Elapsed,
                ScannedAt = DateTimeOffset.UtcNow
            };
        }

        var detections = new List<Detection>();
        var notes = new List<string>();
        IReadOnlyList<NetworkIndicator> indicators = Array.Empty<NetworkIndicator>();
        PeFileInfo? peInfo = null;
        var cloudQueried = false;
        string? cloudError = null;

        if (hashed.Sha256.Equals(KnownTestFiles.EicarSha256, StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(new Detection
            {
                RuleId = "Test.Eicar",
                Name = "Test/EICAR",
                Description = "这是 EICAR 标准反病毒测试文件，不是恶意软件；用于验证哈希、启发式和告警链路。",
                Score = 100,
                Severity = ThreatSeverity.Critical,
                Source = DetectionSource.BuiltInTest,
                Evidence = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            });
        }
        else if (Signatures.TryMatchHash(hashed.Sha256, hashed.Md5, out var knownSignature) && knownSignature is not null)
        {
            var matchedByMd5 = !Signatures.Hashes.ContainsKey(hashed.Sha256);
            var matchedAlgorithm = matchedByMd5 ? "MD5" : "SHA-256";
            var signatureName = knownSignature.ThreatName ?? "Signature/NDY-A.Blocklist";
            detections.Add(new Detection
            {
                RuleId = "Sig.NDY-A.Blocklist",
                Name = signatureName,
                Description = knownSignature.ThreatName is { Length: > 0 }
                    ? $"{matchedAlgorithm} 命中 NDY-A https://github.com/NDY-A/malware-egress-blocklist 定义：{knownSignature.ThreatName}。"
                    : $"{matchedAlgorithm} 命中 NDY-A malware-egress-blocklist 的已知恶意样本。",
                Score = 100,
                Severity = ThreatSeverity.Critical,
                Source = DetectionSource.Hash,
                Evidence = knownSignature.DisplayLabel
            });
            notes.Add(knownSignature.Notes ?? knownSignature.Label);
        }

        if (Signatures.SpecialPaths.TryMatch(fullPath, out var specialPath) && specialPath is not null)
        {
            detections.Add(new Detection
            {
                RuleId = "Ioc.SpecialPath",
                Name = specialPath.Label ?? "IOC/SpecialPath",
                Description = string.IsNullOrWhiteSpace(specialPath.Comment)
                    ? $"文件位于特殊检察清单中的已知恶意落点或篡改目标路径：{specialPath.Path}"
                    : $"文件位于特殊检察清单中的已知恶意落点或篡改目标路径：{specialPath.Path}。{specialPath.Comment}",
                Score = 100,
                Severity = ThreatSeverity.Critical,
                Source = DetectionSource.PathIoc,
                Evidence = specialPath.Path
            });
        }

        if (detections.Count == 0 && options.RunHeuristics)
        {
            var analysis = await _heuristics.AnalyzeAsync(fullPath, kind, cancellationToken).ConfigureAwait(false);
            detections.AddRange(analysis.Detections);
            notes.AddRange(analysis.Notes);
            indicators = analysis.NetworkIndicators;
            peInfo = analysis.PeInfo;
        }

        var localScore = Math.Min(100, detections.Sum(detection => detection.Score));
        var hasDecisiveLocalDetection = localScore >= MaliciousThreshold ||
                                        detections.Any(detection => detection.Source is DetectionSource.Hash or DetectionSource.BuiltInTest or DetectionSource.PathIoc);

        if (options.RunHeuristics &&
            kind == FileKind.PortableExecutable &&
            !hasDecisiveLocalDetection &&
            localScore < MaliciousThreshold)
        {
            ApplyMachineLearning(fullPath, detections, notes);
            localScore = Math.Min(100, detections.Sum(detection => detection.Score));
            hasDecisiveLocalDetection = localScore >= MaliciousThreshold;
        }

        if (!hasDecisiveLocalDetection &&
            options.QueryCloud &&
            _cloud.IsConfigured &&
            ShouldQueryCloud(kind, localScore, options.CloudPolicy))
        {
            cloudQueried = true;
            try
            {
                var cloudResult = await _cloud.QueryFileAsync(hashed.Sha256, hashed.Size, cancellationToken).ConfigureAwait(false);
                if (cloudResult is not null && (cloudResult.IsMalicious || cloudResult.IsSuspicious))
                {
                    var severity = cloudResult.IsMalicious ? ThreatSeverity.Critical : ThreatSeverity.High;
                    detections.Add(new Detection
                    {
                        RuleId = "Cloud.Reputation",
                        Name = cloudResult.ThreatName ?? (cloudResult.IsMalicious ? "Cloud:Malicious" : "Cloud:Suspicious"),
                        Description = "云安全服务基于文件 SHA-256 返回了风险判定；未上传文件内容或本地路径。",
                        Score = cloudResult.Score,
                        Severity = severity,
                        Source = DetectionSource.Cloud,
                        Evidence = cloudResult.IsMalicious ? "云端判定：恶意" : "云端判定：可疑"
                    });
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                cloudError = "云查询失败：" + SafeCloudError(exception);
            }

            if (cloudError is null && !string.IsNullOrWhiteSpace(_cloud.LastError) && detections.Count == 0)
            {
                cloudError = _cloud.LastError;
            }

            if (cloudError is not null)
            {
                notes.Add(cloudError);
            }
        }

        var score = Math.Min(100, detections.Sum(detection => detection.Score));
        var hasStrongDetection = detections.Any(detection =>
            detection.Source is DetectionSource.Hash or DetectionSource.BuiltInTest or DetectionSource.PathIoc ||
            (detection.Source == DetectionSource.Cloud && detection.Score >= MaliciousThreshold));
        var verdict = hasStrongDetection || score >= MaliciousThreshold
            ? ThreatVerdict.Malicious
            : score >= PuaThreshold
                ? ThreatVerdict.Pua
                : score >= AttentionThreshold
                    ? ThreatVerdict.Attention
                    : ThreatVerdict.Clean;

        var orderedDetections = detections
            .OrderByDescending(detection => detection.Severity)
            .ThenByDescending(detection => detection.Score)
            .ToArray();

        var reportThreshold = verdict switch
        {
            ThreatVerdict.Malicious => MaliciousThreshold,
            ThreatVerdict.Pua => PuaThreshold,
            ThreatVerdict.Attention => AttentionThreshold,
            _ => int.MaxValue
        };
        var threatName = orderedDetections.FirstOrDefault(detection => detection.Score >= reportThreshold)?.Name
                         ?? orderedDetections.FirstOrDefault()?.Name;

        stopwatch.Stop();
        return new FileScanResult
        {
            FilePath = fullPath,
            FileName = Path.GetFileName(fullPath),
            Size = hashed.Size,
            Sha256 = hashed.Sha256,
            Kind = kind,
            Verdict = verdict,
            Score = score,
            ThreatName = threatName,
            Detections = orderedDetections,
            Notes = notes.Distinct().Take(20).ToArray(),
            NetworkIndicators = indicators,
            PeInfo = peInfo,
            CloudQueried = cloudQueried,
            CloudError = cloudError,
            ScanDuration = stopwatch.Elapsed,
            ScannedAt = DateTimeOffset.UtcNow
        };
    }

    private static void ApplyMachineLearning(string path, List<Detection> detections, List<string> notes)
    {
        if (!MlEngine.TryScore(path, out var probability, out var error))
        {
            return;
        }

        var signatureMismatch = detections.Any(detection => detection.RuleId == "Heur.PE.SignatureMismatch");
        if (probability < 0.5f)
        {
            if (signatureMismatch && probability >= 0.2f)
            {
                detections.Add(new Detection
                {
                    RuleId = "Heur.PE.SignedHostTamper",
                    Name = "Heur:PE/SignedHostTamper",
                    Description = $"文件签名校验失败，且机器学习模型给出中等以上风险评分（{probability:P1}），符合白加黑宿主篡改/补丁加载器特征。",
                    Score = 50,
                    Severity = ThreatSeverity.High,
                    Source = DetectionSource.Heuristic,
                    Evidence = $"p={probability:F4} signature=invalid"
                });
                notes.Add($"联合信号：签名校验失败 + ML 恶意概率 {probability:P1}。");
            }

            return;
        }

        notes.Add($"PE 静态特征机器学习模型评分：恶意概率 {probability:P1}（{MlEngine.ModelVersion}）。");
        if (signatureMismatch && probability >= 0.2f)
        {
            detections.Add(new Detection
            {
                RuleId = "Heur.PE.SignedHostTamper",
                Name = "Heur:PE/SignedHostTamper",
                Description = $"文件签名校验失败，且机器学习模型给出较高风险评分（{probability:P1}），符合白加黑宿主篡改/补丁加载器特征。",
                Score = 80,
                Severity = ThreatSeverity.High,
                Source = DetectionSource.Heuristic,
                Evidence = $"p={probability:F4} signature=invalid"
            });
        }

        if (probability >= 0.88f)
        {
            detections.Add(new Detection
            {
                RuleId = "ML.PE.Model",
                Name = "Heur:PE/ML.HighRisk",
                Description = $"PE 静态特征机器学习模型判定为高度可疑（恶意概率 {probability:P1}）。该信号单独不构成最终判定，会与其他检测叠加。",
                Score = 88,
                Severity = ThreatSeverity.Medium,
                Source = DetectionSource.MachineLearning,
                Evidence = $"p={probability:F4} model={MlEngine.ModelVersion}"
            });
        }
        else if (probability >= 0.75f)
        {
            detections.Add(new Detection
            {
                RuleId = "ML.PE.Model",
                Name = "Heur:PE/ML.Suspicious",
                Description = $"PE 静态特征机器学习模型给出较高风险评分（恶意概率 {probability:P1}）。该信号单独不构成最终判定，会与其他检测叠加。",
                Score = 75,
                Severity = ThreatSeverity.Low,
                Source = DetectionSource.MachineLearning,
                Evidence = $"p={probability:F4} model={MlEngine.ModelVersion}"
            });
        }
    }

    private static bool ShouldQueryCloud(FileKind kind, int localScore, CloudQueryPolicy policy)
    {
        return policy switch
        {
            CloudQueryPolicy.Never => false,
            CloudQueryPolicy.All => true,
            CloudQueryPolicy.ExecutablesAndScripts => FileKindDetector.SupportsCloudLookup(kind, policy),
            CloudQueryPolicy.SuspiciousOnly => localScore >= CloudSuspiciousThreshold && FileKindDetector.SupportsCloudLookup(kind, CloudQueryPolicy.ExecutablesAndScripts),
            _ => false
        };
    }

    private static async Task<HashedFile> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            1024 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var size = stream.Length;
        var header = new byte[HeaderBytes];
        var headerRead = 0;
        var buffer = new byte[1024 * 1024];
        using var sha256Hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var md5Hasher = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            sha256Hasher.AppendData(buffer, 0, read);
            md5Hasher.AppendData(buffer, 0, read);
            if (headerRead < header.Length)
            {
                var copy = Math.Min(read, header.Length - headerRead);
                Buffer.BlockCopy(buffer, 0, header, headerRead, copy);
                headerRead += copy;
            }
        }

        var sha256 = Convert.ToHexString(sha256Hasher.GetHashAndReset()).ToLowerInvariant();
        var md5 = Convert.ToHexString(md5Hasher.GetHashAndReset()).ToLowerInvariant();
        return new HashedFile(sha256, md5, size, header.AsSpan(0, headerRead).ToArray());
    }

    private static FileScanResult SkippedResult(string path, long size, string reason, TimeSpan duration)
    {
        return new FileScanResult
        {
            FilePath = path,
            FileName = Path.GetFileName(path),
            Size = size,
            Sha256 = string.Empty,
            Kind = FileKindDetector.Detect(path, ReadOnlySpan<byte>.Empty),
            Verdict = ThreatVerdict.Skipped,
            Score = 0,
            Detections = Array.Empty<Detection>(),
            Notes = new[] { reason },
            ScanDuration = duration,
            ScannedAt = DateTimeOffset.UtcNow
        };
    }

    private static string SafeCloudError(Exception exception) => exception switch
    {
        HttpRequestException => "无法连接云端",
        TaskCanceledException => "云端超时",
        IOException => "网络 I/O 错误",
        _ => exception.GetType().Name
    };

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => $"{bytes / (1024d * 1024 * 1024):F1} GiB",
        >= 1024 * 1024 => $"{bytes / (1024d * 1024):F1} MiB",
        >= 1024 => $"{bytes / 1024d:F1} KiB",
        _ => bytes + " B"
    };

    private sealed record HashedFile(string Sha256, string Md5, long Size, byte[] Header);
}
