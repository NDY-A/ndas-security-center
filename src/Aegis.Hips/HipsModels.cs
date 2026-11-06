namespace Aegis.Hips;

public enum HipsSeverity
{
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

public sealed record HipsEvent(
    DateTimeOffset Timestamp,
    string RuleId,
    string Title,
    string Detail,
    HipsSeverity Severity,
    string? ProcessPath = null,
    string? CommandLine = null,
    string? Target = null,
    bool Blocked = false);

public sealed record HipsProcessObservation(
    int ProcessId,
    string? ProcessName,
    string? ProcessPath,
    string? ParentName,
    string? CommandLine);

public sealed class HipsOptions
{
    public bool BlockCritical { get; init; }
    public IReadOnlyList<string> SelfExclusions { get; init; } = Array.Empty<string>();
    public string? LogPath { get; init; }
    public TimeSpan RegistryPollInterval { get; init; } = TimeSpan.FromSeconds(5);
}
