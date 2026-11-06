namespace Aegis.Core.Models;

public sealed class FileScanResult
{
    public required string FilePath { get; init; }
    public required string FileName { get; init; }
    public required long Size { get; init; }
    public required string Sha256 { get; init; }
    public required FileKind Kind { get; init; }
    public required ThreatVerdict Verdict { get; init; }
    public required int Score { get; init; }
    public string? ThreatName { get; init; }
    public required IReadOnlyList<Detection> Detections { get; init; }
    public required IReadOnlyList<string> Notes { get; init; }
    public IReadOnlyList<NetworkIndicator> NetworkIndicators { get; init; } = Array.Empty<NetworkIndicator>();
    public PeFileInfo? PeInfo { get; init; }
    public bool CloudQueried { get; init; }
    public string? CloudError { get; init; }
    public required TimeSpan ScanDuration { get; init; }
    public required DateTimeOffset ScannedAt { get; init; }

    public bool IsMalicious => Verdict == ThreatVerdict.Malicious;
    public bool IsPua => Verdict == ThreatVerdict.Pua;
    public bool IsAttention => Verdict == ThreatVerdict.Attention;
    public bool IsSuspicious => Verdict == ThreatVerdict.Suspicious;

    public string VerdictText => Verdict switch
    {
        ThreatVerdict.Malicious => "恶意",
        ThreatVerdict.Pua => "PUA",
        ThreatVerdict.Attention => "重点关注",
        ThreatVerdict.Suspicious => "可疑",
        ThreatVerdict.Clean => "安全",
        ThreatVerdict.Skipped => "已跳过",
        _ => "错误"
    };
}

public sealed record ScanError(string Path, string Message);

public sealed class ScanSummary
{
    public required string ScanId { get; init; }
    public required ScanProfileKind Profile { get; init; }
    public required IReadOnlyList<string> Roots { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required TimeSpan Duration { get; init; }
    public required int FilesScanned { get; init; }
    public required int FilesSkipped { get; init; }
    public required int MaliciousCount { get; init; }
    public required int PuaCount { get; init; }
    public required int AttentionCount { get; init; }
    public required int SuspiciousCount { get; init; }
    public required long BytesScanned { get; init; }
    public required int ErrorCount { get; init; }
    public required bool Cancelled { get; init; }
    public required IReadOnlyList<FileScanResult> Detections { get; init; }
    public required IReadOnlyList<ScanError> Errors { get; init; }
    public required string SignatureVersion { get; init; }
    public required bool CloudEnabled { get; init; }
    public required int CloudQueries { get; init; }

    public bool IsClean => MaliciousCount == 0 && PuaCount == 0 && AttentionCount == 0 && SuspiciousCount == 0 && !Cancelled;

    public string StatusText => Cancelled
        ? "已取消"
        : MaliciousCount > 0
            ? "发现威胁"
            : PuaCount > 0
                ? "发现 PUA"
                : AttentionCount > 0
                    ? "需要重点关注"
                    : SuspiciousCount > 0
                        ? "发现可疑项"
                        : "未发现威胁";
}

public sealed record ScanProgress
{
    public required int FilesScanned { get; init; }
    public required int Detections { get; init; }
    public required int Skipped { get; init; }
    public required string CurrentPath { get; init; }
}

public sealed class ScanOptions
{
    public long MaxFileSizeBytes { get; init; } = 512L * 1024 * 1024;
    public int MaxDegreeOfParallelism { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 2, 4);
    public bool RunHeuristics { get; init; } = true;
    public bool QueryCloud { get; init; } = true;
    public CloudQueryPolicy CloudPolicy { get; init; } = CloudQueryPolicy.SuspiciousOnly;
    public bool UseDefaultExclusions { get; init; } = true;
    public IReadOnlyList<string> UserExclusions { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> AllowedHashes { get; init; } = Array.Empty<string>();
    public bool IncludeHiddenFiles { get; init; } = true;
    public static ScanOptions Default => new();
}

public sealed class ScanRequest
{
    public required ScanProfileKind Profile { get; init; }
    public string? TargetPath { get; init; }
    public required ScanOptions Options { get; init; }

    public static ScanRequest Quick(ScanOptions? options = null) =>
        new() { Profile = ScanProfileKind.Quick, Options = options ?? ScanOptions.Default };

    public static ScanRequest Full(ScanOptions? options = null) =>
        new() { Profile = ScanProfileKind.Full, Options = options ?? ScanOptions.Default };

    public static ScanRequest Custom(string path, ScanOptions? options = null) =>
        new() { Profile = ScanProfileKind.Custom, TargetPath = path, Options = options ?? ScanOptions.Default };
}
