using System.Text.Json;
using Aegis.Core.Service;

namespace Aegis.Service;

public sealed class ServiceSettings
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
    public List<string> AllowedHashes { get; set; } = new();
    public bool AutoTerminateProcesses { get; set; }
    public bool AutoDeleteMaliciousP7b { get; set; }
    public bool FirewallAutoBlockEnabled { get; set; }
    public bool SandboxEnabled { get; set; } = true;
    public bool SandboxAutoRemediate { get; set; } = true;
    public bool SandboxAutoBlockNetwork { get; set; } = true;
    public int SandboxMaxRunSeconds { get; set; } = 60;

    public ServiceConfiguration ToConfiguration() => new()
    {
        HipsEnabled = HipsEnabled,
        BlockCritical = BlockCritical,
        RealtimeProtectionEnabled = RealtimeProtectionEnabled,
        ScanActiveProcesses = ScanActiveProcesses,
        BlockInjection = BlockInjection,
        BlockRegistry = BlockRegistry,
        IdleScanEnabled = IdleScanEnabled,
        IdleScanIdleMinutes = IdleScanIdleMinutes,
        ContinuousScanEnabled = ContinuousScanEnabled,
        ContinuousScanCpuPercent = ContinuousScanCpuPercent,
        AllowedHashes = AllowedHashes.ToArray(),
        AutoTerminateProcesses = AutoTerminateProcesses,
        AutoDeleteMaliciousP7b = AutoDeleteMaliciousP7b,
        FirewallAutoBlockEnabled = FirewallAutoBlockEnabled,
        SandboxEnabled = SandboxEnabled,
        SandboxAutoRemediate = SandboxAutoRemediate,
        SandboxAutoBlockNetwork = SandboxAutoBlockNetwork,
        SandboxMaxRunSeconds = SandboxMaxRunSeconds
    };

    public void Apply(ServiceConfiguration configuration)
    {
        HipsEnabled = configuration.HipsEnabled;
        BlockCritical = configuration.BlockCritical;
        RealtimeProtectionEnabled = configuration.RealtimeProtectionEnabled;
        ScanActiveProcesses = configuration.ScanActiveProcesses;
        BlockInjection = configuration.BlockInjection;
        BlockRegistry = configuration.BlockRegistry;
        IdleScanEnabled = configuration.IdleScanEnabled;
        IdleScanIdleMinutes = Math.Clamp(configuration.IdleScanIdleMinutes, 1, 240);
        ContinuousScanEnabled = configuration.ContinuousScanEnabled;
        ContinuousScanCpuPercent = Math.Clamp(configuration.ContinuousScanCpuPercent, 1, 90);
        AllowedHashes = (configuration.AllowedHashes ?? Array.Empty<string>())
            .Where(hash => !string.IsNullOrWhiteSpace(hash))
            .Select(hash => hash.Trim().ToLowerInvariant())
            .Distinct()
            .ToList();
        AutoTerminateProcesses = configuration.AutoTerminateProcesses;
        AutoDeleteMaliciousP7b = configuration.AutoDeleteMaliciousP7b;
        FirewallAutoBlockEnabled = configuration.FirewallAutoBlockEnabled;
        SandboxEnabled = configuration.SandboxEnabled;
        SandboxAutoRemediate = configuration.SandboxAutoRemediate;
        SandboxAutoBlockNetwork = configuration.SandboxAutoBlockNetwork;
        SandboxMaxRunSeconds = Math.Clamp(configuration.SandboxMaxRunSeconds, 30, 300);
    }

    public void Save(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(this, JsonDefaults));
        File.Move(temporary, path, overwrite: true);
    }

    public static ServiceSettings Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var settings = JsonSerializer.Deserialize<ServiceSettings>(File.ReadAllText(path), JsonDefaults);
                if (settings is not null)
                {
                    return settings;
                }
            }
        }
        catch
        {
            // A corrupt settings file falls back to safe defaults.
        }

        return new ServiceSettings();
    }

    private static readonly JsonSerializerOptions JsonDefaults = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };
}
