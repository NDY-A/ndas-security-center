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
    public bool AutoTerminateProcesses { get; set; }
    public bool AutoDeleteMaliciousP7b { get; set; }
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
    public bool AutoTerminateProcesses { get; set; }
    public bool AutoDeleteMaliciousP7b { get; set; }
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
