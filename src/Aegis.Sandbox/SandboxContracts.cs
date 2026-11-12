using Aegis.Core.Models;

namespace Aegis.Sandbox;

public sealed class SandboxOptions
{
    public bool Enabled { get; init; } = true;
    public bool AutoRemediate { get; init; } = true;
    public bool AutoBlockNetwork { get; init; } = true;
    public long MinFileSizeBytes { get; init; } = 4 * 1024;
    public long MaxFileSizeBytes { get; init; } = 32L * 1024 * 1024;
    public int MaxRuntimeSeconds { get; init; } = 60;
    public int QueueCapacity { get; init; } = 64;
    public int MaxSubmissionsPer10Minutes { get; init; } = 6;
    public TimeSpan ResultCacheTtl { get; init; } = TimeSpan.FromDays(7);
    public TimeSpan FailureBackoff { get; init; } = TimeSpan.FromMinutes(10);

    public static SandboxOptions Default { get; } = new();
}

public sealed record SandboxCandidate(
    string SourcePath,
    string Sha256,
    long Size,
    int? ProcessId,
    string RuleId,
    string? ParentArchivePath = null,
    string? ArchiveEntryName = null,
    DateTime? ProcessStartTime = null,
    string? AnalysisPath = null,
    string? CleanupDirectory = null)
{
    public bool IsArchiveChild => ParentArchivePath is not null;
}

public sealed record SandboxJob(
    string JobId,
    SandboxCandidate Candidate,
    string StagedPath,
    string WorkDirectory,
    DateTimeOffset QueuedAt);

public sealed record SandboxSignal(string Category, string Detail, int Score);

public sealed class SandboxResult
{
    public required string Sha256 { get; init; }
    public required string FileName { get; init; }
    public required ThreatVerdict Verdict { get; init; }
    public required int Score { get; init; }
    public string? ThreatName { get; init; }
    public required string Summary { get; init; }
    public required IReadOnlyList<SandboxSignal> Signals { get; init; }
    public required IReadOnlyList<NetworkIndicator> Indicators { get; init; }
    public required string Confidence { get; init; }
    public required string EngineVersion { get; init; }
    public required TimeSpan Duration { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public string? Error { get; init; }
}

public sealed class SandboxCoordinatorStatus
{
    public bool Supported { get; init; }
    public bool Available { get; init; }
    public bool Enabled { get; init; }
    public string EngineVersion { get; init; } = string.Empty;
    public int QueueDepth { get; init; }
    public bool Analyzing { get; init; }
    public long Analyzed { get; init; }
    public long Malicious { get; init; }
    public string? LastVerdict { get; init; }
    public string? LastPath { get; init; }
    public long LastScore { get; init; }
    public DateTimeOffset? LastAt { get; init; }
    public string? LastError { get; init; }
}
