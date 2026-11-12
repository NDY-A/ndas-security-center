namespace Aegis.Core.Models;

public sealed record Detection
{
    public required string RuleId { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    public required int Score { get; init; }
    public required ThreatSeverity Severity { get; init; }
    public required DetectionSource Source { get; init; }
    public string? Evidence { get; init; }
}

public sealed record NetworkIndicator
{
    public required IndicatorKind Kind { get; init; }
    public required string Value { get; init; }
    public required string MatchedValue { get; init; }
    public string? Comment { get; init; }
}

public sealed record PeSectionInfo
{
    public required string Name { get; init; }
    public required long VirtualSize { get; init; }
    public required long RawSize { get; init; }
    public required double Entropy { get; init; }
    public required bool IsExecutable { get; init; }
    public required bool IsWritable { get; init; }
}

public sealed record PeFileInfo
{
    public required string Machine { get; init; }
    public required string Subsystem { get; init; }
    public required bool IsDotNet { get; init; }
    public required bool IsDll { get; init; }
    public required DateTimeOffset? LinkerTimestamp { get; init; }
    public required int SectionCount { get; init; }
    public double? FileEntropy { get; init; }
    public required IReadOnlyList<PeSectionInfo> Sections { get; init; }
    public required IReadOnlyList<string> ImportedDlls { get; init; }
    public required IReadOnlyList<string> ImportedFunctions { get; init; }
    public required bool HasAuthenticodeCertificate { get; init; }
    public string? SignerSubject { get; init; }
    public string? AuthenticodeNote { get; init; }
}
