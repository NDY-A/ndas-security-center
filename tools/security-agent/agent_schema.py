"""Wire schema shared with the C# host (Aegis.AgentHost). Keep in sync with AgentActionCatalog."""

PROTOCOL_VERSION = 1

KIND_ACTION = "action"
KIND_RESULT = "result"
KIND_HELLO = "hello"
KIND_FILE_BATCH = "file_batch"
KIND_PROCESS_BATCH = "process_batch"
KIND_SPECIAL_PATH = "special_path"
KIND_SYSTEM_TICK = "system_tick"
KIND_SCAN_RESULT = "scan_result"
KIND_SANDBOX_RESULT = "sandbox_result"
KIND_INVESTIGATION_OPENED = "investigation_opened"
KIND_INVESTIGATION_UPDATE = "investigation_update"
KIND_POLICY_CHANGED = "policy_changed"
KIND_RECOVERY_GAP = "recovery_gap"
KIND_SHUTDOWN = "shutdown"

A_HEARTBEAT = "heartbeat"
A_LOOKUP_IOC = "lookup_ioc"
A_LOCAL_ANALYZE = "local_analyze"
A_SCRIPT_CLASSIFY = "script_classify"
A_SANDBOX_SUBMIT = "sandbox_submit"
A_SANDBOX_STATUS = "sandbox_status"
A_SANDBOX_REPORT = "sandbox_report"
A_QUERY_FILE_METADATA = "query_file_metadata"
A_SCAN_PATHS = "scan_paths"
A_SCHEDULE_SCAN = "schedule_scan"
A_CANCEL_JOB = "cancel_job"
A_SET_SCAN_BUDGET = "set_scan_budget"
A_DEFER = "defer"
A_QUERY_PROCESS_TREE = "query_process_tree"
A_QUERY_NETWORK = "query_network"
A_SCAN_RELATED = "scan_related"
A_LOCK_FILE = "lock_file"
A_TERMINATE_PROCESS = "terminate_process"
A_BLOCK_NETWORK = "block_network"
A_P7B_DECIDE = "p7b_decide"
A_CLOSE_CASE = "close_case"
A_FINAL_VERDICT = "final_verdict"
A_RECORD_IOC = "record_ioc"

# The host additionally refuses anything not in its catalog. These are the only
# names this daemon will ever emit.
ALLOWED_ACTIONS = frozenset(
    {
        A_HEARTBEAT,
        A_LOOKUP_IOC,
        A_LOCAL_ANALYZE,
        A_SCRIPT_CLASSIFY,
        A_SANDBOX_SUBMIT,
        A_SANDBOX_STATUS,
        A_SANDBOX_REPORT,
        A_QUERY_FILE_METADATA,
        A_SCAN_PATHS,
        A_SCHEDULE_SCAN,
        A_CANCEL_JOB,
        A_SET_SCAN_BUDGET,
        A_DEFER,
        A_QUERY_PROCESS_TREE,
        A_QUERY_NETWORK,
        A_SCAN_RELATED,
        A_LOCK_FILE,
        A_TERMINATE_PROCESS,
        A_BLOCK_NETWORK,
        A_P7B_DECIDE,
        A_CLOSE_CASE,
        A_FINAL_VERDICT,
        A_RECORD_IOC,
    }
)

# Remediation actions are gated by rule checks first and then confirmed by the
# decision model (see agent_daemon.ModelConfirmer).
REMEDIATION_ACTIONS = frozenset({A_LOCK_FILE, A_TERMINATE_PROCESS, A_BLOCK_NETWORK, A_P7B_DECIDE})

HIGH_RISK_EXTENSIONS = frozenset(
    {
        "exe", "dll", "sys", "scr", "cpl", "com", "msi", "msp", "msix", "appx",
        "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd",
        "lnk", "url", "iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "cab",
        "docm", "xlsm", "pptm", "chm",
    }
)

SCRIPT_EXTENSIONS = frozenset({"ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd"})

MAX_ACTIONS_PER_HEARTBEAT = 300
HEARTBEAT_SECONDS = 5
