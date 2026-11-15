"""Pure action constructors. No file, process, network or registry side effects."""

import uuid

from agent_schema import (
    A_BLOCK_NETWORK,
    A_CLOSE_CASE,
    A_DEFER,
    A_FINAL_VERDICT,
    A_LOCAL_ANALYZE,
    A_LOCK_FILE,
    A_LOOKUP_IOC,
    A_QUERY_NETWORK,
    A_QUERY_PROCESS_TREE,
    A_RECORD_IOC,
    A_SANDBOX_SUBMIT,
    A_SCAN_PATHS,
    A_SCRIPT_CLASSIFY,
    A_TERMINATE_PROCESS,
    ALLOWED_ACTIONS,
    KIND_ACTION,
    PROTOCOL_VERSION,
)


def new_id() -> str:
    return uuid.uuid4().hex[:20]


def _action(name: str, reason: str, args: dict | None = None, case_id: str | None = None,
            detection_id: str | None = None) -> dict:
    if name not in ALLOWED_ACTIONS:
        raise ValueError(f"action not in allow-list: {name}")
    message = {
        "v": PROTOCOL_VERSION,
        "kind": KIND_ACTION,
        "id": new_id(),
        "action": name,
        "reason": reason,
        "args": args or {},
    }
    if case_id:
        message["caseId"] = case_id
    if detection_id:
        message["detectionId"] = detection_id
    return message


def heartbeat(model_loaded: bool) -> dict:
    return _action("heartbeat", "keepalive", {"modelLoaded": bool(model_loaded)})


def local_analyze(path_ref: str, reason: str, submit_sandbox: bool = True) -> dict:
    return _action(A_LOCAL_ANALYZE, reason, {"pathRef": path_ref, "submitSandbox": submit_sandbox})


def script_classify(path_ref: str, reason: str) -> dict:
    return _action(A_SCRIPT_CLASSIFY, reason, {"pathRef": path_ref})


def lookup_ioc(sha256: str, reason: str) -> dict:
    return _action(A_LOOKUP_IOC, reason, {"sha256": sha256})


def scan_paths(targets: list[dict], reason: str, max_duration_seconds: int = 120,
               idle_only: bool = False, max_files: int | None = None) -> dict:
    args = {
        "targets": targets,
        "maxDurationSeconds": max_duration_seconds,
        "idleOnly": idle_only,
        "reason": reason,
    }
    if max_files is not None:
        args["maxFiles"] = max_files
    return _action(A_SCAN_PATHS, reason, args)


def sandbox_submit(path_ref: str, reason: str, sha256: str | None = None,
                   process_id: int | None = None) -> dict:
    args = {"pathRef": path_ref}
    if sha256:
        args["sha256"] = sha256
    if process_id:
        args["processId"] = process_id
    return _action(A_SANDBOX_SUBMIT, reason, args)


def query_process_tree(pid: int, reason: str, depth: int = 3) -> dict:
    return _action(A_QUERY_PROCESS_TREE, reason, {"pid": pid, "depth": depth, "maxNodes": 256})


def query_network(reason: str, pid: int | None = None) -> dict:
    args: dict = {"sinceMinutes": 60, "maxRows": 200}
    if pid:
        args["pid"] = pid
    return _action(A_QUERY_NETWORK, reason, args)


def defer(milliseconds: int, reason: str) -> dict:
    return _action(A_DEFER, reason, {"milliseconds": milliseconds})


def lock_file(path_ref: str, case_id: str, reason: str, detection_id: str | None = None) -> dict:
    return _action(A_LOCK_FILE, reason, {"pathRef": path_ref}, case_id=case_id, detection_id=detection_id)


def terminate_process(pid: int, expected_path: str, expected_start_time: str, case_id: str,
                      reason: str, detection_id: str | None = None) -> dict:
    return _action(
        A_TERMINATE_PROCESS,
        reason,
        {"pid": pid, "expectedPath": expected_path, "expectedStartTime": expected_start_time},
        case_id=case_id,
        detection_id=detection_id,
    )


def block_network(indicator_ids: list[str], case_id: str, reason: str) -> dict:
    return _action(A_BLOCK_NETWORK, reason, {"indicatorIds": indicator_ids}, case_id=case_id)


def record_ioc(reason: str, sha256: str | None = None, domain: str | None = None,
               ip: str | None = None, label: str = "Trojan/Agent") -> dict:
    args: dict = {"label": label}
    if sha256:
        args["sha256"] = sha256
    if domain:
        args["domain"] = domain
    if ip:
        args["ip"] = ip
    return _action(A_RECORD_IOC, reason, args)


def final_verdict(verdict: str, reason: str, confidence: float = 0.5,
                  case_id: str | None = None) -> dict:
    return _action(A_FINAL_VERDICT, reason, {"verdict": verdict, "confidence": confidence},
                   case_id=case_id)


def close_case(case_id: str, verdict: str, summary: str, confidence: float = 0.5) -> dict:
    return _action(A_CLOSE_CASE, summary, {"verdict": verdict, "confidence": confidence,
                                           "summary": summary}, case_id=case_id)
