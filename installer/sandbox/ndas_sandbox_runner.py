"""NDAS built-in Speakeasy runner.

Loads a PE sample with the Speakeasy emulator, runs it in user-space emulation
(no real execution of the sample), and writes the behavior report as JSON.
Invoked by NDASService with a low-integrity token inside a job object.
"""

import argparse
import hashlib
import json
import os
import sys
import traceback

MAX_REPORT_BYTES = 19 * 1024 * 1024


def write_error_report(path, message, sample_sha256=None):
    report = {
        "report_version": "ndas-runner",
        "sha256": sample_sha256,
        "errors": [{"type": "runner_error", "message": message}],
        "entry_points": [],
        "strings": {},
    }
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
        if isinstance(entry, dict) and isinstance(entry.get("events"), list):
            if len(entry["events"]) > 5000:
                entry["events"] = entry["events"][:5000]
        if isinstance(entry, dict) and isinstance(entry.get("dropped_files"), list):
            entry["dropped_files"] = entry["dropped_files"][:500]


def write_report(path, report):
    text = json.dumps(report, ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_REPORT_BYTES:
        shrink_report(report)
        text = json.dumps(report, ensure_ascii=False)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--work-dir", default=".")
    parser.add_argument("--max-run-time", type=int, default=60)
    args = parser.parse_args()

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

    try:
        import speakeasy  # noqa: F401
    except Exception as exc:
        write_error_report(report_path, "Speakeasy 组件不可用：" + str(exc), sample_sha256)
        return 2

    try:
        import speakeasy

        config_path = os.path.join(os.path.dirname(speakeasy.__file__), "configs", "default.json")
        with open(config_path, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        config["timeout"] = max(10, min(int(args.max_run_time), 600))
        config["max_api_count"] = 100000
        emulator = speakeasy.Speakeasy(config=config)
        module = emulator.load_module(sample)
        emulator.run_module(module)
        report = emulator.get_report()
        if not isinstance(report, dict):
            raise RuntimeError("Speakeasy 返回了无效的报告对象。")
        if not report.get("sha256"):
            report["sha256"] = sample_sha256
        write_report(report_path, report)
        return 0
    except Exception as exc:
        write_error_report(
            report_path,
            "沙箱模拟失败：" + str(exc) + "\n" + traceback.format_exc(limit=3),
            sample_sha256,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
