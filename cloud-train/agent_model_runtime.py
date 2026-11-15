"""ONNX decision-model runtime.

The model is optional: without it the daemon still runs the rule policy for
scheduling, but remediation actions are never emitted (safe default).
"""

import json
import os
import sys


class AgentModelRuntime:
    # The model errs lenient on the synthetic distribution (zero false rejects,
    # ~35% false accepts). Requiring a 1.0 logit margin keeps 93% of true
    # accepts while removing ~36% of false accepts (measured on 200 rows).
    ACCEPT_MARGIN = 1.0

    def __init__(self, model_path: str | None = None):
        here = os.path.dirname(os.path.abspath(__file__))
        self.path = model_path or os.path.join(here, "agent-model.onnx")
        self.session = None
        self.loaded = False
        self._input_name = None
        self._output_names = None
        self._max_context = 1024
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            print(f"[model] not found: {self.path}", file=sys.stderr)
            return
        try:
            import numpy  # noqa: F401  (onnxruntime needs numpy)
            import onnxruntime

            options = onnxruntime.SessionOptions()
            options.intra_op_num_threads = min(4, os.cpu_count() or 1)
            options.log_severity_level = 3
            self.session = onnxruntime.InferenceSession(
                self.path, sess_options=options, providers=["CPUExecutionProvider"]
            )
            self._input_name = self.session.get_inputs()[0].name
            self._output_names = [output.name for output in self.session.get_outputs()]
            self.loaded = True
            print(f"[model] loaded {os.path.basename(self.path)}", file=sys.stderr)
        except Exception as exception:  # noqa: BLE001 - optional component
            print(f"[model] load failed: {exception}", file=sys.stderr)
            self.session = None
            self.loaded = False

    def confirm_remediation(self, context: dict, action: dict) -> bool:
        """Return True only when the model explicitly accepts the action.

        Any failure (model missing, malformed output, timeout) returns False so
        the daemon errs on the side of not remediating.
        """
        if not self.loaded or self.session is None:
            return False
        try:
            prompt = self._build_confirm_prompt(context, action)
            margin = self._decision_margin(prompt)
            if margin > self.ACCEPT_MARGIN:
                return True
            print(f"[model] remediation rejected: margin={margin:.2f}", file=sys.stderr)
            return False
        except Exception as exception:  # noqa: BLE001 - confirmation is best effort
            print(f"[model] confirm failed: {exception}", file=sys.stderr)
            return False

    def _build_confirm_prompt(self, context: dict, action: dict) -> str:
        state = json.dumps(self._confirm_state(context, action), ensure_ascii=False,
                           separators=(",", ":"))[:1500]
        candidate = json.dumps(self._confirm_action(action), ensure_ascii=False,
                               separators=(",", ":"))[:800]
        return (
            "你是 NDAS 本地安全决策模型。判断下面的处置动作是否有充分证据。"
            '只回答 accept 或 reject。\nSTATE:' + state + "\nACTION:" + candidate + "\n"
        )

    @staticmethod
    def _confirm_state(context: dict, action: dict) -> dict:
        """Shape the live decision into the training distribution (flat fields)."""
        event = context.get("event") if isinstance(context, dict) else None
        event = event if isinstance(event, dict) else {}
        detections = event.get("detections")
        sources = []
        if isinstance(detections, list):
            for detection in detections:
                if isinstance(detection, dict) and detection.get("source"):
                    sources.append(str(detection["source"]))
        path = str(event.get("path") or "")
        file_name = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or "unknown"
        name = action.get("action") or ""
        return {
            "file": file_name,
            "kind": str(event.get("kind") or "pe"),
            "verdict": str(event.get("verdict") or "malicious"),
            "score": int(event.get("score") or 0),
            "evidence": sources,
            "case": "root" if (event.get("caseId") or context.get("caseId")) else "none",
            "mode": str(context.get("mode") or "auto"),
            "processRunning": bool(action.get("pid")),
            "p7bTrust": str(event.get("p7bTrust") or "none"),
        }

    @staticmethod
    def _confirm_action(action: dict) -> dict:
        name = action.get("action") or ""
        shaped = {"action": name, "reason": action.get("reason") or ""}
        args = action.get("args") if isinstance(action.get("args"), dict) else {}
        if name == "block_network" and args.get("domain"):
            shaped["domain"] = args["domain"]
        if name == "p7b_decide" and args.get("decision"):
            shaped["decision"] = args["decision"]
        return shaped

    def _decision_margin(self, prompt: str) -> float:
        """Return logit('a') - logit('r') for the first generated token.

        Training targets are a single character, so the decision is the first
        token after the prompt. The exported graph has a dynamic sequence axis,
        so no padding is needed.
        """
        if self.session is None:
            raise RuntimeError("model not loaded")
        import numpy

        limit = min(self._max_context, 512)
        tokens = [256] + list(prompt.encode("utf-8"))[: limit - 1]
        inputs = {self._input_name: numpy.asarray([tokens], dtype=numpy.int64)}
        outputs = self.session.run(self._output_names, inputs)
        last = outputs[0][0, len(tokens) - 1]
        return float(last[ord("a")] - last[ord("r")])
