"""Synthesise remediation-confirmation training rows for the NDAS decision model.

The daemon uses the model only to confirm remediation actions (lock / terminate /
block / p7b). Scheduling is deterministic rule policy, so the training data is a
binary accept/reject task over (state, candidate action) prompts. The prompt text
must match AgentModelRuntime._build_confirm_prompt byte for byte.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

CONFIRM_PROMPT_HEADER = (
    "你是 NDAS 本地安全决策模型。判断下面的处置动作是否有充分证据。"
    "只回答 accept 或 reject。\nSTATE:"
)

SAMPLE_NAMES = ["invoice.pdf.exe", "deepsk_x64.in.15.exe", "qishui-setup.exe", "update.ps1",
                "photo.vbs", "document.hta", "tool.zip", "driver.dll", "setup.msi",
                "chrome_update.js", "invoice_2026.doc.exe", "rundll32_copy.exe"]
STRONG_SOURCES = ["Hash", "Yara", "PathIoc", "BuiltInTest"]
WEAK_SOURCES = ["Heuristic", "MachineLearning", "Cloud"]
ACTIONS = ["lock_file", "terminate_process", "block_network"]
DOMAINS = ["ksudk.com", "qishuivip.com.cn", "mm2027.oss-cn-hangzhou.aliyuncs.com"]


def build_state(rng: random.Random) -> dict:
    verdict = rng.choices(
        ["malicious", "pua", "attention", "benign", "clean"],
        weights=[60, 12, 10, 10, 8])[0]
    strong = rng.random() < 0.85
    sources = rng.sample(STRONG_SOURCES, rng.randint(1, 2)) if strong else []
    sources += rng.sample(WEAK_SOURCES, rng.randint(0 if strong else 1, 2))
    return {
        "file": rng.choice(SAMPLE_NAMES),
        "kind": rng.choice(["pe", "script", "archive"]),
        "verdict": verdict,
        "score": rng.randint(82 if verdict in ("malicious", "pua") else 40, 100),
        "evidence": sources,
        "case": rng.choices(["none", "root", "cascade"], weights=[20, 60, 20])[0],
        "mode": rng.choices(["auto", "report"], weights=[90, 10])[0],
        "processRunning": rng.random() < 0.4,
        "p7bTrust": rng.choice(["none", "none", "trusted", "untrusted", "invalid"]),
    }


def build_action(rng: random.Random, state: dict) -> dict:
    name = rng.choice(ACTIONS + (["p7b_decide"] if state["p7bTrust"] != "none" else []))
    if name == "lock_file":
        return {"action": "lock_file", "reason": "恶意判定后锁定文件"}
    if name == "terminate_process":
        return {"action": "terminate_process", "reason": "恶意进程仍在运行"}
    if name == "block_network":
        return {"action": "block_network", "reason": "恶意样本命中网络指标",
                "domain": rng.choice(DOMAINS)}
    return {"action": "p7b_decide", "reason": "策略文件签名不可信", "decision": "delete"}


def expected_label(state: dict, action: dict) -> str:
    if state["verdict"] != "malicious":
        return "r"
    if state["mode"] == "report" and state["case"] in ("cascade", "none"):
        return "r"
    if not any(source in STRONG_SOURCES for source in state["evidence"]):
        return "r"
    if state["score"] < 85:
        return "r"
    if action["action"] == "p7b_decide":
        return "a" if state["p7bTrust"] in ("untrusted", "invalid") else "r"
    if action["action"] == "terminate_process" and not state["processRunning"]:
        return "r"
    return "a"


def make_confirm_row(rng: random.Random) -> tuple[str, str]:
    state = build_state(rng)
    action = build_action(rng, state)
    prompt = (
        CONFIRM_PROMPT_HEADER
        + json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        + "\nACTION:"
        + json.dumps(action, ensure_ascii=False, separators=(",", ":"))
        + "\n"
    )
    return prompt, expected_label(state, action)


def build(rows_target: int = 8000, seed: int = 20261114) -> list[tuple[str, str]]:
    """Balance accept/reject so the model does not collapse to always-reject."""
    rng = random.Random(seed)
    half = rows_target // 2
    positives: list[tuple[str, str]] = []
    negatives: list[tuple[str, str]] = []
    seen: set[str] = set()
    attempts = 0
    while (len(positives) < half or len(negatives) < rows_target - half) and attempts < rows_target * 200:
        attempts += 1
        prompt, label = make_confirm_row(rng)
        if prompt in seen:
            continue
        bucket = positives if label == "a" else negatives
        limit = half if label == "a" else rows_target - half
        if len(bucket) >= limit:
            continue
        seen.add(prompt)
        bucket.append((prompt, label))
    rows = positives + negatives
    rng.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = build()
    out = Path(__file__).resolve().parent / "agent-data.jsonl"
    with open(out, "w", encoding="utf-8") as handle:
        for prompt, target in rows:
            handle.write(json.dumps({"prompt": prompt, "target": target}, ensure_ascii=False) + "\n")
    accepts = sum(1 for _, label in rows if label == "a")
    print("rows:", len(rows), "accept:", accepts, "reject:", len(rows) - accepts, "->", out)
