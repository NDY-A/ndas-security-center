"""Compare INT8 vs FP32 decisions and measure single-step latency."""

import json
import os
import statistics
import time

import numpy as np
import onnxruntime

HERE = os.path.dirname(os.path.abspath(__file__))
FP32 = os.path.join(HERE, "agent-model-initializers.onnx")
INT8 = os.path.join(HERE, "agent-model-int8.onnx")
DATA = os.path.join(HERE, "..", "tools", "security-agent", "agent-data.jsonl")

PAD, BOS, EOS, VOCAB = 258, 256, 257, 259


def make_session(path, threads):
    options = onnxruntime.SessionOptions()
    options.intra_op_num_threads = threads
    options.log_severity_level = 3
    return onnxruntime.InferenceSession(path, sess_options=options,
                                        providers=["CPUExecutionProvider"])


def encode(prompt):
    tokens = [BOS] + list(prompt.encode("utf-8"))[:1023]
    return tokens


def decide(session, tokens):
    inputs = {session.get_inputs()[0].name: np.asarray([tokens], dtype=np.int64)}
    logits = session.run(None, inputs)[0][0, len(tokens) - 1]
    token = int(np.argmax(logits))
    return token


def timed(session, seq_len, repeats=3):
    ids = np.random.default_rng(7).integers(0, 256, size=(1, seq_len), dtype=np.int64)
    name = session.get_inputs()[0].name
    session.run(None, {name: ids})  # warm-up
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        session.run(None, {name: ids})
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def main():
    rows = []
    with open(DATA, "r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if index % 500 == 0:
                rows.append(json.loads(line))
    print("validation prompts:", len(rows), flush=True)

    print("loading fp32...", flush=True)
    fp32 = make_session(FP32, 4)
    print("loading int8...", flush=True)
    int8 = make_session(INT8, 4)

    agree = 0
    label_ok_int8 = 0
    label_ok_fp32 = 0
    for row in rows:
        tokens = encode(row["prompt"])
        token32 = decide(fp32, tokens)
        token8 = decide(int8, tokens)
        if token32 == token8:
            agree += 1
        expect = ord(row["target"])
        if token8 == expect:
            label_ok_int8 += 1
        if token32 == expect:
            label_ok_fp32 += 1
    total = len(rows)
    print("first-token agreement int8 vs fp32: %d/%d" % (agree, total), flush=True)
    print("label hit fp32: %d/%d  int8: %d/%d"
          % (label_ok_fp32, total, label_ok_int8, total), flush=True)

    random_agreement = []
    rng = np.random.default_rng(11)
    for _ in range(8):
        ids = rng.integers(0, 256, size=(1, 512), dtype=np.int64)
        out32 = fp32.run(None, {fp32.get_inputs()[0].name: ids})[0][0, -1]
        out8 = int8.run(None, {int8.get_inputs()[0].name: ids})[0][0, -1]
        random_agreement.append(int(np.argmax(out32)) == int(np.argmax(out8)))
        diff = float(np.max(np.abs(out32 - out8)))
        print("random seq512 maxlogitdiff=%.4f" % diff, flush=True)
    print("random-input argmax agreement: %d/8" % sum(random_agreement), flush=True)

    for threads in (1, 4):
        session = make_session(INT8, threads)
        for seq_len in (64, 128, 256, 512):
            seconds = timed(session, seq_len)
            print("int8 threads=%d seq=%d median %.3fs" % (threads, seq_len, seconds), flush=True)

    fp32_64 = timed(fp32, 64, repeats=1)
    print("fp32 threads=4 seq=64 median %.3fs" % fp32_64, flush=True)


if __name__ == "__main__":
    main()
