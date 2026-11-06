using Aegis.Core.Models;

namespace Aegis.App.Services;

public enum AppThemePreference
{
    System,
    Light,
    Dark
}

public sealed class AppSettings
{
    public bool CloudEnabled { get; set; }
    public string CloudEndpoint { get; set; } = string.Empty;
    public CloudQueryPolicy CloudPolicy { get; set; } = CloudQueryPolicy.SuspiciousOnly;
    public bool AgentApiEnabled { get; set; } = true;
    public int AgentApiPort { get; set; } = 17_483;
    public bool AutoUpdateEnabled { get; set; } = true;
    public bool HipsEnabled { get; set; } = true;
    public bool HipsBlockCritical { get; set; }
    public bool RealtimeProtectionEnabled { get; set; } = true;
    public bool RealtimeScanActiveProcesses { get; set; } = true;
    public bool RealtimeBlockInjection { get; set; } = true;
    public bool RealtimeBlockRegistry { get; set; } = true;
    public bool IdleScanEnabled { get; set; } = true;
    public int IdleScanIdleMinutes { get; set; } = 10;
    public bool AutoTerminateProcesses { get; set; }
    public bool AutoDeleteMaliciousP7b { get; set; }
    public bool NotificationsEnabled { get; set; } = true;
    public bool AutoStartEnabled { get; set; }
    public AppThemePreference Theme { get; set; } = AppThemePreference.System;
    public long MaxFileSizeBytes { get; set; } = 512L * 1024 * 1024;
    public bool UseDefaultExclusions { get; set; } = true;
    public List<string> Exclusions { get; set; } = new();
    public List<string> AllowedHashes { get; set; } = new();
}
