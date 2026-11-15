"""Deterministic scheduling/investigation policy for the NDAS decision agent.

This policy is part of the agent itself. It owns scan scheduling and triage
decisions; remediation candidates are gated by the model confirmer in the
daemon before they reach the host.
"""

import os
import time

import agent_actions as act
from agent_schema import HIGH_RISK_EXTENSIONS

RECENT_SCAN_TTL_SECONDS = 600
IDLE_SCAN_MIN_IDLE_SECONDS = 300
IDLE_SCAN_INTERVAL_SECONDS = 900
MAX_ANALYZE_PER_BATCH = 8
SYSTEM_PATH_MARKERS = (
    "\\windows\\system32",
    "\\windows\\syswow64",
    "\\windows\\winsxs",
    "\\program files\\ndas",
)


class AgentPolicy:
    def __init__(self) -> None:
        self.realtime = True
        self.mode = "auto"
        self.sandbox_enabled = True
        self.roots: dict[str, str] = {}
        self.limits: dict = {}
        self.recent: dict[str, float] = {}
        self.cases: dict[str, dict] = {}
        self.pending: dict[str, dict] = {}
        self.last_idle_scan = 0.0
        self.first_tick_done = False
        self.dropped_events = 0
        self.decisions = 0

    # ---- events ----

    def on_hello(self, data: dict) -> None:
        policy = data.get("policy") or {}
        self.realtime = bool(policy.get("realtimeEnabled", True))
        self.mode = policy.get("investigationRemediateMode") or "auto"
        self.sandbox_enabled = bool(policy.get("sandboxEnabled", True))
        self.limits = data.get("limits") or {}
        self.roots = {}
        for root in data.get("scanRoots") or []:
            root_id = root.get("rootId")
            if root_id:
                self.roots[root_id] = root.get("path") or ""
        self.cases = {}
        for case in data.get("openCases") or []:
            case_id = case.get("caseId")
            if case_id:
                self.cases[case_id] = case

    def on_policy_changed(self, data: dict) -> list[dict]:
        policy = data.get("policy") or {}
        self.realtime = bool(policy.get("realtimeEnabled", self.realtime))
        self.mode = policy.get("investigationRemediateMode") or self.mode
        self.sandbox_enabled = bool(policy.get("sandboxEnabled", self.sandbox_enabled))
        return []

    def handle(self, kind: str, data: dict) -> list[dict]:
        handler = {
            "file_batch": self._on_file_batch,
            "process_batch": self._on_process_batch,
            "special_path": self._on_special_path,
            "system_tick": self._on_tick,
            "scan_result": self._on_scan_result,
            "sandbox_result": self._on_sandbox_result,
            "investigation_opened": self._on_investigation_opened,
            "investigation_update": self._on_investigation_update,
            "recovery_gap": self._on_recovery_gap,
            "policy_changed": self.on_policy_changed,
        }.get(kind)
        if handler is None:
            return []
        return handler(data) or []

    def on_result(self, data: dict) -> None:
        action_id = data.get("actionId") or ""
        pending = self.pending.pop(action_id, None)
        if data.get("ok") is False:
            import sys

            print(
                f"[result] {pending.get('action') if pending else '?'} failed: "
                f"{data.get('code')} {data.get('message')}",
                file=sys.stderr,
            )

    # ---- handlers ----

    def _on_file_batch(self, data: dict) -> list[dict]:
        if not self.realtime:
            return []
        actions: list[dict] = []
        budget = MAX_ANALYZE_PER_BATCH
        for event in data.get("events") or []:
            if budget <= 0:
                break
            event_id = event.get("eventId")
            path = event.get("path") or ""
            if not event_id or not path or self._is_system_path(path):
                continue
            extension = (event.get("extension") or os.path.splitext(path)[1].lstrip(".")).lower()
            if extension not in HIGH_RISK_EXTENSIONS:
                continue
            if self._recently_analyzed(path):
                continue
            self._mark_analyzed(path)
            actions.append(act.local_analyze(event_id, f"实时事件高风险文件: {os.path.basename(path)}"))
            self.decisions += 1
            budget -= 1
        return actions

    def _on_process_batch(self, data: dict) -> list[dict]:
        if not self.realtime:
            return []
        actions: list[dict] = []
        budget = MAX_ANALYZE_PER_BATCH
        for event in data.get("events") or []:
            if budget <= 0:
                break
            event_id = event.get("eventId")
            path = event.get("path") or ""
            if not event_id or not path or self._is_system_path(path):
                continue
            if not path.lower().endswith((".exe", ".dll", ".sys")):
                continue
            if self._recently_analyzed(path):
                continue
            self._mark_analyzed(path)
            actions.append(act.local_analyze(event_id, f"新启动进程映像: {os.path.basename(path)}"))
            self.decisions += 1
            budget -= 1
        return actions

    def _on_special_path(self, data: dict) -> list[dict]:
        event_id = data.get("eventId")
        path = data.get("path") or ""
        if not event_id or not path:
            return []
        if not self.realtime:
            return []
        self._mark_analyzed(path)
        return [act.local_analyze(event_id, f"特殊路径命中: {data.get('label') or os.path.basename(path)}")]

    def _on_tick(self, data: dict) -> list[dict]:
        self.dropped_events = int(data.get("droppedEvents") or self.dropped_events)
        actions: list[dict] = []
        now = time.time()

        if self.realtime and not self.first_tick_done:
            self.first_tick_done = True
            if self.roots:
                actions.append(
                    act.scan_paths(
                        [{"rootId": root_id, "recursive": True, "maxFiles": 200}
                         for root_id in self.roots],
                        "启动后首轮基线扫描（agent 调度）",
                        max_duration_seconds=90,
                    )
                )
                self.last_idle_scan = now
            return actions

        idle_seconds = float(data.get("idleSeconds") or 0)
        cpu = float(data.get("cpuPercent") or 0)
        if (
            self.realtime
            and idle_seconds >= IDLE_SCAN_MIN_IDLE_SECONDS
            and cpu <= 25
            and now - self.last_idle_scan >= IDLE_SCAN_INTERVAL_SECONDS
            and self.roots
        ):
            actions.append(
                act.scan_paths(
                    [{"rootId": root_id, "recursive": True, "maxFiles": 400}
                     for root_id in self.roots],
                    "空闲周期扫描（agent 调度）",
                    max_duration_seconds=180,
                    idle_only=True,
                )
            )
            self.last_idle_scan = now

        if self.dropped_events > 0:
            self.dropped_events = 0
            if self.roots:
                actions.append(
                    act.scan_paths(
                        [{"rootId": root_id, "recursive": True, "maxFiles": 150}
                         for root_id in self.roots],
                        "补偿扫描：事件队列曾溢出",
                        max_duration_seconds=120,
                        idle_only=True,
                    )
                )
        return actions

    def _on_scan_result(self, data: dict) -> list[dict]:
        verdict = data.get("verdict") or "clean"
        path = data.get("path") or ""
        if verdict != "malicious":
            return []

        self._mark_analyzed(path)
        case_id = data.get("caseId")
        detection_id = data.get("detectionId")
        score = data.get("score") or 0
        if not path:
            return []
        if not case_id:
            for candidate, case in self.cases.items():
                if case.get("rootPath") == path:
                    case_id = candidate
                    break
        if not case_id:
            # The host opens the investigation case first; remediation waits.
            return []

        self.cases.setdefault(case_id, {"caseId": case_id, "rootPath": path})
        path_ref = detection_id or path
        return [act.lock_file(path_ref, case_id, f"恶意判定（评分 {score}）", detection_id=detection_id)]

    def _on_sandbox_result(self, data: dict) -> list[dict]:
        return []

    def _on_investigation_opened(self, data: dict) -> list[dict]:
        case_id = data.get("caseId")
        if not case_id:
            return []
        self.cases[case_id] = dict(data)
        actions: list[dict] = []
        for artifact in data.get("artifacts") or []:
            kind = artifact.get("type")
            value = artifact.get("value") or ""
            artifact_id = artifact.get("artifactId") or ""
            if kind == "process":
                try:
                    pid = int(value)
                except (TypeError, ValueError):
                    continue
                if pid > 4:
                    actions.append(act.query_process_tree(pid, f"调查案卷 {case_id}: 进程树扩展"))
            elif kind == "file" and artifact_id and self.realtime:
                actions.append(act.local_analyze(artifact_id, f"调查案卷 {case_id}: 关联文件分析"))
        return actions[:8]

    def _on_investigation_update(self, data: dict) -> list[dict]:
        case_id = data.get("caseId")
        if case_id and case_id in self.cases:
            self.cases[case_id]["status"] = data.get("status") or self.cases[case_id].get("status")
        return []

    def _on_recovery_gap(self, data: dict) -> list[dict]:
        dropped = int(data.get("droppedEventCount") or 0)
        if dropped <= 0 or not self.realtime or not self.roots:
            return []
        return [
            act.scan_paths(
                [{"rootId": root_id, "recursive": True, "maxFiles": 200} for root_id in self.roots],
                "agent 恢复后补偿扫描",
                max_duration_seconds=120,
                idle_only=True,
            )
        ]

    # ---- helpers ----

    def _recently_analyzed(self, path: str) -> bool:
        now = time.time()
        expired = [key for key, at in self.recent.items() if now - at > RECENT_SCAN_TTL_SECONDS]
        for key in expired:
            self.recent.pop(key, None)
        return path.lower() in self.recent

    def _mark_analyzed(self, path: str) -> None:
        if path:
            self.recent[path.lower()] = time.time()

    @staticmethod
    def _is_system_path(path: str) -> bool:
        lowered = path.lower()
        return any(marker in lowered for marker in SYSTEM_PATH_MARKERS)
