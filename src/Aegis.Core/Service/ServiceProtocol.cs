namespace Aegis.Core.Service;

public static class ServiceProtocol
{
    public const string PipeName = "NDAS.Service.v1";
    public const string WindowsServiceName = "NDASService";
    public const string WindowsServiceDisplayName = "NDAS 防护服务";
}

public sealed class ServiceRequest
{
    public string Command { get; set; } = "status";
    public ServiceConfiguration? Settings { get; set; }
    public string? Path { get; set; }
}

public sealed class ServiceConfiguration
{
    public bool HipsEnabled { get; set; } = true;
    public bool BlockCritical { get; set; }
    public bool RealtimeProtectionEnabled { get; set; } = true;
    public bool ScanActiveProcesses { get; set; } = true;
    public bool BlockInjection { get; set; } = true;
    public bool BlockRegistry { get; set; } = true;
    public bool IdleScanEnabled { get; set; } = true;
    public int IdleScanIdleMinutes { get; set; } = 10;
    public bool ContinuousScanEnabled { get; set; } = true;
    public int ContinuousScanCpuPercent { get; set; } = 12;
    public string[] AllowedHashes { get; set; } = Array.Empty<string>();
    public bool AutoTerminateProcesses { get; set; }
    public bool AutoDeleteMaliciousP7b { get; set; }
    public bool FirewallAutoBlockEnabled { get; set; }
    public bool SandboxEnabled { get; set; } = true;
    public bool SandboxAutoRemediate { get; set; } = true;
    public bool SandboxAutoBlockNetwork { get; set; } = true;
    public int SandboxMaxRunSeconds { get; set; } = 60;
}

public sealed class ServiceStatus
{
    public bool ServiceRunning { get; set; }
    public bool HipsRunning { get; set; }
    public bool HipsEnabled { get; set; }
    public bool ProcessMonitoringActive { get; set; }
    public bool FileMonitoringActive { get; set; }
    public bool RegistryMonitoringActive { get; set; }
    public bool RealtimeProtectionEnabled { get; set; }
    public bool ScanActiveProcesses { get; set; }
    public bool BlockInjection { get; set; }
    public bool BlockRegistry { get; set; }
    public bool BlockCritical { get; set; }
    public bool IdleScanEnabled { get; set; }
    public int IdleScanIdleMinutes { get; set; }
    public bool IdleScanActive { get; set; }
    public DateTimeOffset? LastIdleScanAt { get; set; }
    public long LastIdleScanFiles { get; set; }
    public long LastIdleScanThreats { get; set; }
    public bool ContinuousScanEnabled { get; set; }
    public int ContinuousScanCpuPercent { get; set; }
    public bool ContinuousScanActive { get; set; }
    public long ContinuousScanFiles { get; set; }
    public long ContinuousScanThreats { get; set; }
    public string? ContinuousScanCurrentPath { get; set; }
    public DateTimeOffset? ContinuousScanStartedAt { get; set; }
    public DateTimeOffset? LastContinuousScanAt { get; set; }
    public bool AutoTerminateProcesses { get; set; }
    public bool AutoDeleteMaliciousP7b { get; set; }
    public bool FirewallAutoBlockEnabled { get; set; }
    public int FirewallBlockedDomains { get; set; }
    public int FirewallBlockedIps { get; set; }
    public string? FirewallLastError { get; set; }
    public bool SandboxSupported { get; set; }
    public bool SandboxAvailable { get; set; }
    public bool SandboxEnabled { get; set; }
    public bool SandboxAutoRemediate { get; set; }
    public string? SandboxEngineVersion { get; set; }
    public int SandboxQueueDepth { get; set; }
    public bool SandboxAnalyzing { get; set; }
    public long SandboxAnalyzed { get; set; }
    public long SandboxMalicious { get; set; }
    public string? SandboxLastVerdict { get; set; }
    public string? SandboxLastPath { get; set; }
    public long SandboxLastScore { get; set; }
    public DateTimeOffset? SandboxLastAt { get; set; }
    public string? SandboxLastError { get; set; }
    public string? LastError { get; set; }
    public int EventCount { get; set; }
    public long ScannedFiles { get; set; }
    public long ThreatsFound { get; set; }
    public string? SignatureVersion { get; set; }
    public int YaraRuleCount { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public List<ServiceEvent> RecentEvents { get; set; } = new();
    public List<string> WatchedPaths { get; set; } = new();
    public List<ServiceUserProfile> Profiles { get; set; } = new();
    public List<string> WatchErrors { get; set; } = new();
    public List<ServiceBlockedFile> BlockedFiles { get; set; } = new();
    public ServiceThreatIncident? ActiveThreat { get; set; }
    public ServiceContainmentStatus? Containment { get; set; }
}

public sealed class ServiceThreatIncident
{
    public string IncidentId { get; set; } = string.Empty;
    public DateTimeOffset DetectedAt { get; set; }
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public bool ProcessStillRunning { get; set; }
}

public sealed class ServiceContainmentStatus
{
    public bool Active { get; set; }
    public string State { get; set; } = ContainmentStates.Idle;
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public string Phase { get; set; } = string.Empty;
    public long FilesScanned { get; set; }
    public long ThreatsFound { get; set; }
    public string? CurrentPath { get; set; }
    public int TerminatedProcesses { get; set; }
    public int GuardSweepKills { get; set; }
    public long CriticalFilesScanned { get; set; }
    public int ThreatsRemediated { get; set; }
    public string? BootRepairResult { get; set; }
    public string? LastError { get; set; }
    public bool ShutdownPending { get; set; }
    public List<string> Actions { get; set; } = new();
}

public static class ContainmentStates
{
    public const string Idle = "idle";
    public const string Starting = "starting";
    public const string Lockdown = "lockdown";
    public const string Scanning = "scanning";
    public const string RepairingBoot = "repairingBoot";
    public const string ShuttingDown = "shuttingDown";
    public const string Completed = "completed";
    public const string Failed = "failed";
    public const string Cancelled = "cancelled";
}

public sealed class ServiceBlockedFile
{
    public string Path { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public DateTimeOffset BlockedAt { get; set; }
    public bool AclApplied { get; set; }
    public bool HandleHeld { get; set; }
}

public sealed class ServiceUserProfile
{
    public string Sid { get; set; } = string.Empty;
    public string ProfilePath { get; set; } = string.Empty;
    public string? Desktop { get; set; }
    public string? Downloads { get; set; }
}

public sealed class ServiceEvent
{
    public DateTimeOffset Timestamp { get; set; }
    public string RuleId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public int Severity { get; set; }
    public string? ProcessPath { get; set; }
    public string? CommandLine { get; set; }
    public string? Target { get; set; }
    public bool Blocked { get; set; }
}
