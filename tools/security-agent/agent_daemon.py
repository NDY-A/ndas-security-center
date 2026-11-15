#!/usr/bin/env python3
"""NDAS decision agent daemon.

Reads NDJSON events on stdin, writes NDJSON actions on stdout, logs on stderr.
The daemon never touches the filesystem, spawns processes or opens sockets:
every action is validated and executed by NDASService. Remediation actions go
through a model confirmation gate; without an accepting model they are dropped.
"""

import json
import os
import sys
import threading

# The embedded Python ships with a ._pth file (isolated mode), so the script
# directory is not on sys.path automatically.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import agent_actions as act
import agent_model_runtime
import agent_policy
import agent_schema
from agent_schema import KIND_HELLO, KIND_RESULT, KIND_SHUTDOWN, REMEDIATION_ACTIONS


class AgentDaemon:
    def __init__(self) -> None:
        self.model = agent_model_runtime.AgentModelRuntime()
        self.policy = agent_policy.AgentPolicy()
        self._out_lock = threading.Lock()
        self._stderr_lock = threading.Lock()
        self._stop = threading.Event()
        self._actions_sent = 0
        self._confirm_failures = 0

    # ---- output ----

    def send(self, message: dict) -> None:
        line = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        with self._out_lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()
            self._actions_sent += 1

    def log(self, text: str) -> None:
        with self._stderr_lock:
            print(text, file=sys.stderr)
            sys.stderr.flush()

    # ---- remediation gate ----

    def emit_actions(self, actions: list[dict], context: dict) -> None:
        context = dict(context or {})
        context.setdefault("mode", self.policy.mode)
        for action in actions:
            name = action.get("action")
            if name in REMEDIATION_ACTIONS:
                accepted = self.model.confirm_remediation(context, action)
                if not accepted:
                    self._confirm_failures += 1
                    self.log(f"[gate] remediation not confirmed: {name} ({self._confirm_failures})")
                    continue
            self.policy.pending[action["id"]] = action
            self.send(action)

    def heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.send(act.heartbeat(self.model.loaded))
            except Exception as exception:  # noqa: BLE001 - never kill the daemon on write errors
                self.log(f"[heartbeat] send failed: {exception}")
            self._stop.wait(agent_schema.HEARTBEAT_SECONDS)

    # ---- main loop ----

    def run(self) -> int:
        self.log(
            f"[daemon] protocol={agent_schema.PROTOCOL_VERSION} "
            f"model={'loaded' if self.model.loaded else 'rules-only'}"
        )

        heartbeat = threading.Thread(target=self.heartbeat_loop, name="heartbeat", daemon=True)
        heartbeat.start()

        try:
            for raw_line in sys.stdin:
                if self._stop.is_set():
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError as exception:
                    self.log(f"[daemon] bad json: {exception}")
                    continue

                kind = message.get("kind") or ""
                data = message.get("data") or {}

                try:
                    if kind == KIND_HELLO:
                        self.policy.on_hello(data)
                        self.send(act.heartbeat(self.model.loaded))
                        continue
                    if kind == KIND_SHUTDOWN:
                        self.log("[daemon] shutdown requested")
                        break
                    if kind == KIND_RESULT:
                        self.policy.on_result(data)
                        continue

                    actions = self.policy.handle(kind, data)
                    if actions:
                        self.emit_actions(actions, {"kind": kind, "event": self._summarize(data)})
                except Exception as exception:  # noqa: BLE001 - keep serving other events
                    self.log(f"[daemon] handler error for {kind}: {exception}")
        finally:
            self._stop.set()

        self.log(f"[daemon] exit actions={self._actions_sent} confirm_failures={self._confirm_failures}")
        return 0

    @staticmethod
    def _summarize(data: dict) -> dict:
        summary = {}
        for key in ("path", "kind", "verdict", "score", "threatName", "caseId", "detectionId",
                    "status", "label", "p7bTrust"):
            if key in data:
                summary[key] = data[key]
        detections = data.get("detections")
        if isinstance(detections, list):
            summary["detections"] = [
                {k: detection.get(k) for k in ("source", "ruleId", "name", "score") if k in detection}
                for detection in detections[:8]
                if isinstance(detection, dict)
            ]
        if "events" in data and isinstance(data["events"], list) and data["events"]:
            first = data["events"][0]
            summary["firstEvent"] = {k: first.get(k) for k in ("path", "extension", "source") if k in first}
        return summary


def main() -> int:
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - older runtimes may not expose reconfigure
        pass

    return AgentDaemon().run()


if __name__ == "__main__":
    sys.exit(main())
