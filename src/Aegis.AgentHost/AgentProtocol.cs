using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aegis.AgentHost;

public static class AgentProtocol
{
    public const int Version = 1;
    public const int MaxLineBytes = 256 * 1024;
    public const int MaxJsonDepth = 16;
    public const int HeartbeatIntervalSeconds = 5;
    public const int HeartbeatTimeoutSeconds = 15;
    public const int MaxStringLength = 2048;
    public const int MaxReasonLength = 4096;

    public const string KindAction = "action";
    public const string KindResult = "result";
    public const string KindHello = "hello";
    public const string KindFileBatch = "file_batch";
    public const string KindProcessBatch = "process_batch";
    public const string KindSpecialPath = "special_path";
    public const string KindSystemTick = "system_tick";
    public const string KindScanResult = "scan_result";
    public const string KindSandboxResult = "sandbox_result";
    public const string KindInvestigationOpened = "investigation_opened";
    public const string KindInvestigationUpdate = "investigation_update";
    public const string KindPolicyChanged = "policy_changed";
    public const string KindRecoveryGap = "recovery_gap";
    public const string KindShutdown = "shutdown";

    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        MaxDepth = MaxJsonDepth,
    };
}

/// <summary>Envelope for every message the service writes to the agent's stdin.</summary>
public sealed class AgentOutboundMessage
{
    public int V { get; set; } = AgentProtocol.Version;
    public string Kind { get; set; } = string.Empty;
    public long Seq { get; set; }
    public DateTimeOffset Ts { get; set; } = DateTimeOffset.UtcNow;
    public object? Data { get; set; }

    public static AgentOutboundMessage Create(string kind, object? data, long seq) =>
        new() { Kind = kind, Data = data, Seq = seq };
}

/// <summary>Envelope for every message the agent writes to its stdout.</summary>
public sealed class AgentInboundMessage
{
    public int V { get; set; } = AgentProtocol.Version;
    public string Kind { get; set; } = AgentProtocol.KindAction;
    public string Id { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? CaseId { get; set; }
    public string? DetectionId { get; set; }
    public string[]? Refs { get; set; }
    public string Reason { get; set; } = string.Empty;
    public JsonElement? Args { get; set; }
}

// ---------- hello ----------

public sealed class AgentPolicy
{
    public bool RealtimeEnabled { get; set; } = true;
    public string InvestigationRemediateMode { get; set; } = "auto";
    public bool SandboxEnabled { get; set; } = true;
}

public sealed class AgentLimits
{
    public int MaxActionsPerMinute { get; set; } = 300;
    public int MaxScanTargets { get; set; } = 64;
    public int MaxCaseActions { get; set; } = 20;
    public int MaxFilesPerScan { get; set; } = 10000;
    public int MaxScanSeconds { get; set; } = 600;
}

public sealed class AgentScanRoot
{
    public string RootId { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Kind { get; set; } = "user";
}

public sealed class AgentCaseArtifact
{
    public string ArtifactId { get; set; } = string.Empty;
    public string Type { get; set; } = "file";
    public string Value { get; set; } = string.Empty;
    public string? DetectionId { get; set; }
}

public sealed class AgentCaseSummary
{
    public string CaseId { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? RootPath { get; set; }
    public string? Sha256 { get; set; }
    public string? ThreatName { get; set; }
    public int ArtifactCount { get; set; }
    public int CascadeDepth { get; set; }
    public DateTimeOffset OpenedAt { get; set; }
}

public sealed class AgentScheduleSummary
{
    public string ScheduleId { get; set; } = string.Empty;
    public string Kind { get; set; } = "interval";
    public int? IntervalSeconds { get; set; }
    public int? IdleSeconds { get; set; }
    public int MaxFilesPerRun { get; set; }
    public int MaxCpuPercent { get; set; }
    public bool Enabled { get; set; } = true;
    public string TargetSetId { get; set; } = string.Empty;
}

public sealed class AgentHelloMessage
{
    public int ProtocolVersion { get; set; } = AgentProtocol.Version;
    public string AgentVersion { get; set; } = string.Empty;
    public string SessionToken { get; set; } = string.Empty;
    public AgentPolicy Policy { get; set; } = new();
    public AgentLimits Limits { get; set; } = new();
    public List<AgentScanRoot> ScanRoots { get; set; } = new();
    public List<AgentCaseSummary> OpenCases { get; set; } = new();
    public List<AgentScheduleSummary> Schedules { get; set; } = new();
}

// ---------- sensor events ----------

public sealed class AgentFileEventItem
{
    public string EventId { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public long Size { get; set; }
    public string? Extension { get; set; }
    public DateTimeOffset? CreatedAt { get; set; }
    public string? Sha256 { get; set; }
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string Source { get; set; } = "realtime";
    public string? SpecialPathLabel { get; set; }
}

public sealed class AgentFileBatch
{
    public List<AgentFileEventItem> Events { get; set; } = new();
}

public sealed class AgentProcessEventItem
{
    public string EventId { get; set; } = string.Empty;
    public int Pid { get; set; }
    public string? Path { get; set; }
    public string? CommandLine { get; set; }
    public int? ParentPid { get; set; }
    public string? ParentPath { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public int SessionId { get; set; }
    public bool? Signed { get; set; }
    public string? Signer { get; set; }
}

public sealed class AgentProcessBatch
{
    public List<AgentProcessEventItem> Events { get; set; } = new();
}

public sealed class AgentSpecialPathMessage
{
    public string EventId { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public bool IsDirectory { get; set; }
    public string? Comment { get; set; }
    public string Kind { get; set; } = string.Empty;
    /// <summary>Pre-computed p7b trust verdict: trusted | untrusted | invalid | none.</summary>
    public string P7bTrust { get; set; } = "none";
}

public sealed class AgentDueSchedule
{
    public string ScheduleId { get; set; } = string.Empty;
    public string TargetSetId { get; set; } = string.Empty;
}

public sealed class AgentSystemTickMessage
{
    public string TickId { get; set; } = string.Empty;
    public int IntervalMs { get; set; }
    public double IdleSeconds { get; set; }
    public double CpuPercent { get; set; }
    public int QueueDepth { get; set; }
    public long DroppedEvents { get; set; }
    public int ActiveCases { get; set; }
    public int AgentRttMs { get; set; }
    public List<AgentDueSchedule> DueSchedules { get; set; } = new();
}

public sealed class AgentDetectionEvidence
{
    public string Source { get; set; } = string.Empty;
    public string RuleId { get; set; } = string.Empty;
    public string? Name { get; set; }
    public int Score { get; set; }
    public string? Severity { get; set; }
}

public sealed class AgentIndicatorRef
{
    public string IndicatorId { get; set; } = string.Empty;
    public string Type { get; set; } = "domain";
    public string Value { get; set; } = string.Empty;
}

public sealed class AgentScanResultMessage
{
    public string ScanId { get; set; } = string.Empty;
    public string? DetectionId { get; set; }
    public string? CaseId { get; set; }
    public string Path { get; set; } = string.Empty;
    public string? Sha256 { get; set; }
    public long Size { get; set; }
    public string Kind { get; set; } = "unknown";
    public string Verdict { get; set; } = "clean";
    public int Score { get; set; }
    public string? ThreatName { get; set; }
    public List<AgentDetectionEvidence> Detections { get; set; } = new();
    public List<AgentIndicatorRef> Indicators { get; set; } = new();
    public int? ProcessId { get; set; }
    public string Disposition { get; set; } = "analyzed";
    public string? SkipReason { get; set; }
    public double DurationMs { get; set; }
    public string? Error { get; set; }
}

public sealed class AgentSandboxResultMessage
{
    public string TaskId { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string? Path { get; set; }
    public string Verdict { get; set; } = "clean";
    public int Score { get; set; }
    public string? Summary { get; set; }
    public List<AgentIndicatorRef> Indicators { get; set; } = new();
    public List<string> DroppedFiles { get; set; } = new();
    public List<string> Signals { get; set; } = new();
    public string? Error { get; set; }
}

public sealed class AgentInvestigationOpenedMessage
{
    public string CaseId { get; set; } = string.Empty;
    public string? RootDetectionId { get; set; }
    public string Severity { get; set; } = "high";
    public int CascadeDepth { get; set; }
    public List<AgentCaseArtifact> Artifacts { get; set; } = new();
}

public sealed class AgentInvestigationUpdateMessage
{
    public string CaseId { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public List<AgentCaseArtifact> AddedArtifacts { get; set; } = new();
    public string? LastActionResult { get; set; }
}

public sealed class AgentPolicyChangedMessage
{
    public AgentPolicy Policy { get; set; } = new();
}

public sealed class AgentRecoveryGapMessage
{
    public DateTimeOffset StoppedAt { get; set; }
    public DateTimeOffset ResumedAt { get; set; }
    public long DroppedEventCount { get; set; }
    public double GapSeconds { get; set; }
    public List<string> CancelledJobs { get; set; } = new();
}

public sealed class AgentShutdownMessage
{
    public string Reason { get; set; } = string.Empty;
    public int GraceMs { get; set; } = 3000;
}

// ---------- action result (service -> agent) ----------

public sealed class AgentActionResultMessage
{
    public string ActionId { get; set; } = string.Empty;
    public bool Ok { get; set; }
    public string? Code { get; set; }
    public string? Message { get; set; }
    public object? Data { get; set; }
}
