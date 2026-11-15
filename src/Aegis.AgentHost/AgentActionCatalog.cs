namespace Aegis.AgentHost;

public enum AgentActionKind
{
    Heartbeat,
    LookupIoc,
    LocalAnalyze,
    ScriptClassify,
    SandboxSubmit,
    SandboxStatus,
    SandboxReport,
    QueryFileMetadata,
    ScanPaths,
    ScheduleScan,
    CancelJob,
    SetScanBudget,
    Defer,
    QueryProcessTree,
    QueryNetwork,
    ScanRelated,
    LockFile,
    TerminateProcess,
    BlockNetwork,
    P7bDecide,
    CloseCase,
    FinalVerdict,
    RecordIoc,
}

public sealed record AgentActionSpec(
    string Name,
    AgentActionKind Kind,
    bool RequiresReason,
    bool IsRemediation,
    bool RequiresCase);

/// <summary>
/// The single source of truth for what an agent may ask the service to do.
/// There is deliberately no exclusion, whitelist, allow-hash, configuration,
/// shell or process-spawn action: the capability does not exist in the host.
/// </summary>
public static class AgentActionCatalog
{
    public const string Heartbeat = "heartbeat";

    public const string LookupIoc = "lookup_ioc";
    public const string LocalAnalyze = "local_analyze";
    public const string ScriptClassify = "script_classify";
    public const string SandboxSubmit = "sandbox_submit";
    public const string SandboxStatus = "sandbox_status";
    public const string SandboxReport = "sandbox_report";
    public const string QueryFileMetadata = "query_file_metadata";

    public const string ScanPaths = "scan_paths";
    public const string ScheduleScan = "schedule_scan";
    public const string CancelJob = "cancel_job";
    public const string SetScanBudget = "set_scan_budget";
    public const string Defer = "defer";

    public const string QueryProcessTree = "query_process_tree";
    public const string QueryNetwork = "query_network";
    public const string ScanRelated = "scan_related";

    public const string LockFile = "lock_file";
    public const string TerminateProcess = "terminate_process";
    public const string BlockNetwork = "block_network";
    public const string P7bDecide = "p7b_decide";

    public const string CloseCase = "close_case";
    public const string FinalVerdict = "final_verdict";
    public const string RecordIoc = "record_ioc";

    private static readonly Dictionary<string, AgentActionSpec> Specs = new(StringComparer.Ordinal)
    {
        [Heartbeat] = new(Heartbeat, AgentActionKind.Heartbeat, RequiresReason: false, IsRemediation: false, RequiresCase: false),

        [LookupIoc] = new(LookupIoc, AgentActionKind.LookupIoc, false, false, false),
        [LocalAnalyze] = new(LocalAnalyze, AgentActionKind.LocalAnalyze, true, false, false),
        [ScriptClassify] = new(ScriptClassify, AgentActionKind.ScriptClassify, true, false, false),
        [SandboxSubmit] = new(SandboxSubmit, AgentActionKind.SandboxSubmit, true, false, false),
        [SandboxStatus] = new(SandboxStatus, AgentActionKind.SandboxStatus, false, false, false),
        [SandboxReport] = new(SandboxReport, AgentActionKind.SandboxReport, false, false, false),
        [QueryFileMetadata] = new(QueryFileMetadata, AgentActionKind.QueryFileMetadata, false, false, false),

        [ScanPaths] = new(ScanPaths, AgentActionKind.ScanPaths, true, false, false),
        [ScheduleScan] = new(ScheduleScan, AgentActionKind.ScheduleScan, true, false, false),
        [CancelJob] = new(CancelJob, AgentActionKind.CancelJob, false, false, false),
        [SetScanBudget] = new(SetScanBudget, AgentActionKind.SetScanBudget, false, false, false),
        [Defer] = new(Defer, AgentActionKind.Defer, true, false, false),

        [QueryProcessTree] = new(QueryProcessTree, AgentActionKind.QueryProcessTree, false, false, false),
        [QueryNetwork] = new(QueryNetwork, AgentActionKind.QueryNetwork, true, false, false),
        [ScanRelated] = new(ScanRelated, AgentActionKind.ScanRelated, true, false, true),

        [LockFile] = new(LockFile, AgentActionKind.LockFile, true, true, true),
        [TerminateProcess] = new(TerminateProcess, AgentActionKind.TerminateProcess, true, true, true),
        [BlockNetwork] = new(BlockNetwork, AgentActionKind.BlockNetwork, true, true, true),
        [P7bDecide] = new(P7bDecide, AgentActionKind.P7bDecide, true, true, true),

        [CloseCase] = new(CloseCase, AgentActionKind.CloseCase, true, false, true),
        [FinalVerdict] = new(FinalVerdict, AgentActionKind.FinalVerdict, true, false, false),
        [RecordIoc] = new(RecordIoc, AgentActionKind.RecordIoc, true, false, false),
    };

    public static bool TryGet(string name, out AgentActionSpec spec) =>
        Specs.TryGetValue(name, out spec!);

    public static IReadOnlyCollection<string> Names => Specs.Keys;

    public static IReadOnlyList<AgentActionSpec> All { get; } = Specs.Values.ToArray();

    public static IReadOnlyList<string> RemediationNames { get; } =
        Specs.Values.Where(s => s.IsRemediation).Select(s => s.Name).ToArray();
}
