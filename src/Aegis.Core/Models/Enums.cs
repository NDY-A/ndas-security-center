namespace Aegis.Core.Models;

public enum ThreatSeverity
{
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
}

public enum ThreatVerdict
{
    Clean = 0,
    Suspicious = 1,
    Malicious = 2,
    Error = 3,
    Skipped = 4,
    Pua = 5,
    Attention = 6
}

public enum DetectionSource
{
    Hash,
    Heuristic,
    Cloud,
    BuiltInTest,
    Yara,
    PathIoc
}

public enum FileKind
{
    Unknown,
    PortableExecutable,
    Script,
    MacroDocument,
    Archive,
    Shortcut,
    Document
}

public enum ScanProfileKind
{
    Quick,
    Full,
    Custom
}

public enum ScanJobState
{
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled
}

public enum CloudQueryPolicy
{
    Never = 0,
    SuspiciousOnly = 1,
    ExecutablesAndScripts = 2,
    All = 3
}

public enum CloudVerdict
{
    Clean,
    Unknown,
    Suspicious,
    Malicious,
    Pua
}

public enum IndicatorKind
{
    Domain,
    IpAddress
}
