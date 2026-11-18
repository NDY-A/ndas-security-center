"""NDAS built-in Speakeasy runner.

Loads a PE sample with the Speakeasy emulator, runs it in user-space emulation
(no real execution of the sample), and writes the behavior report as JSON.
Invoked by NDASService with a low-integrity token inside a job object.

A hardening layer (ndas_env_profile + ndas_antievasion_hooks) overlays a
consistent real-machine persona and patches environment APIs that samples
abuse to detect emulation. Pass --no-hardened for a baseline comparison.
"""

import argparse
import hashlib
import json
import os
import sys
import time
import traceback

MAX_REPORT_BYTES = 19 * 1024 * 1024


def write_error_report(path, message, sample_sha256=None, stats=None):
    report = {
        "report_version": "ndas-runner",
        "sha256": sample_sha256,
        "errors": [{"type": "runner_error", "message": message}],
        "entry_points": [],
        "strings": {},
    }
    if stats is not None:
        report["emulator_stats"] = stats
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, ensure_ascii=False)
    except Exception:
        pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def shrink_report(report):
    strings = report.get("strings")
    if isinstance(strings, dict):
        for scope in strings.values():
            if isinstance(scope, dict):
                for encoding, values in list(scope.items()):
                    if isinstance(values, list) and len(values) > 2000:
                        scope[encoding] = values[:2000]
    for entry in report.get("entry_points", []):
        if isinstance(entry, dict):
            if isinstance(entry.get("events"), list) and len(entry["events"]) > 5000:
                entry["events"] = entry["events"][:5000]
            if isinstance(entry.get("apis"), list) and len(entry["apis"]) > 5000:
                entry["apis"] = entry["apis"][:5000]
            if isinstance(entry.get("dropped_files"), list) and len(entry["dropped_files"]) > 500:
                entry["dropped_files"] = entry["dropped_files"][:500]


def write_report(path, report):
    text = json.dumps(report, ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_REPORT_BYTES:
        shrink_report(report)
        text = json.dumps(report, ensure_ascii=False)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def collect_stats(report, hardened, profile, applied, skipped, started):
    api_count = 0
    instr_count = 0
    exit_reason = ""
    for entry in report.get("entry_points", []):
        if not isinstance(entry, dict):
            continue
        for key in ("apis", "events"):
            value = entry.get(key)
            if isinstance(value, list):
                api_count += len(value)
        try:
            instr_count += int(entry.get("instr_count") or 0)
        except (TypeError, ValueError):
            pass
        error = entry.get("error")
        if not exit_reason and isinstance(error, dict) and error.get("type"):
            exit_reason = "error: %s at %s" % (error.get("type"), error.get("address", "?"))
    return {
        "hardened": bool(hardened),
        "profile": profile,
        "hooks_applied": len(applied),
        "hooks_skipped": skipped,
        "hook_names": applied,
        "api_count": api_count,
        "instr_count": instr_count,
        "wall_ms": int((time.monotonic() - started) * 1000),
        "exit": exit_reason or "ok",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--work-dir", default=".")
    parser.add_argument("--max-run-time", type=int, default=60)
    parser.add_argument("--no-hardened", dest="hardened", action="store_false",
                        help="跳过环境伪装与反反沙箱 hook 层（对照实验用）")
    parser.add_argument("--profile", default="win10-cn-office")
    args = parser.parse_args()
    started = time.monotonic()

    sample = os.path.abspath(args.sample)
    report_path = os.path.abspath(args.report)
    if not os.path.isfile(sample):
        write_error_report(report_path, "样本文件不存在或不可读。")
        return 2

    try:
        sample_sha256 = sha256_file(sample)
    except Exception as exc:
        write_error_report(report_path, "无法计算样本哈希：" + str(exc))
        return 2

    def error_stats(exit_text):
        return {
            "hardened": bool(args.hardened),
            "profile": args.profile,
            "hooks_applied": 0,
            "hooks_skipped": [],
            "hook_names": [],
            "api_count": 0,
            "instr_count": 0,
            "wall_ms": int((time.monotonic() - started) * 1000),
            "exit": exit_text,
        }

    try:
        import speakeasy  # noqa: F401
    except Exception as exc:
        write_error_report(report_path, "Speakeasy 组件不可用：" + str(exc), sample_sha256,
                           error_stats("speakeasy_unavailable"))
        return 2

    runner_dir = os.path.dirname(os.path.abspath(__file__))
    if runner_dir not in sys.path:
        sys.path.insert(0, runner_dir)
    try:
        import ndas_env_profile
        import ndas_antievasion_hooks
        hardening_available = True
    except Exception:
        ndas_env_profile = None
        ndas_antievasion_hooks = None
        hardening_available = False

    try:
        import speakeasy

        config_path = os.path.join(os.path.dirname(speakeasy.__file__), "configs", "default.json")
        with open(config_path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        config["timeout"] = max(10, min(int(args.max_run_time), 600))
        config["max_api_count"] = 100000

        hardened = bool(args.hardened and hardening_available)
        if hardened:
            ndas_env_profile.apply_profile(config, os.path.basename(sample), args.profile)

        emulator = speakeasy.Speakeasy(config=config)
        applied, skipped = [], []
        if hardened:
            applied, skipped = ndas_antievasion_hooks.install(emulator)

        module = emulator.load_module(sample)
        emulator.run_module(module)
        report = emulator.get_report()
        if not isinstance(report, dict):
            raise RuntimeError("Speakeasy 返回了无效的报告对象。")
        if not report.get("sha256"):
            report["sha256"] = sample_sha256
        report["emulator_stats"] = collect_stats(
            report, hardened, args.profile, applied, skipped, started)
        write_report(report_path, report)
        return 0
    except Exception as exc:
        write_error_report(
            report_path,
            "沙箱模拟失败：" + str(exc) + "\n" + traceback.format_exc(limit=3),
            sample_sha256,
            error_stats("runner_exception: " + str(exc).splitlines()[0][:200]),
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
