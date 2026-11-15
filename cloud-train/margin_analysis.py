"""Score margins of the downloaded INT8 model to pick a conservative accept threshold."""

import json

import numpy as np
import onnxruntime

MODEL = r"E:\下载\agent-model-int8_3.onnx"
DATA = r"E:\My_Project\Aegis\tools\security-agent\agent-data.jsonl"
SAMPLE_EVERY = 80

options = onnxruntime.SessionOptions()
options.intra_op_num_threads = 4
options.log_severity_level = 3
session = onnxruntime.InferenceSession(MODEL, sess_options=options, providers=["CPUExecutionProvider"])
input_name = session.get_inputs()[0].name

samples = []
with open(DATA, encoding="utf-8") as handle:
    for index, line in enumerate(handle):
        if index % SAMPLE_EVERY:
            continue
        row = json.loads(line)
        tokens = [256] + list(row["prompt"].encode("utf-8"))[:511]
        label = 97 if row["target"] == "a" else 114
        logits = session.run(None, {input_name: np.asarray([tokens + [label]], dtype=np.int64)})[0][0]
        last = logits[len(tokens) - 1]
        samples.append((row["target"], float(last[97] - last[114])))

accept_margins = [m for t, m in samples if t == "a"]
reject_margins = [m for t, m in samples if t == "r"]
print("n=%d accept=%d reject=%d" % (len(samples), len(accept_margins), len(reject_margins)))
print("accept margin p10/50/90: %.2f %.2f %.2f" % tuple(np.percentile(accept_margins, [10, 50, 90])) if accept_margins else "no accepts")
print("reject margin p10/50/90: %.2f %.2f %.2f" % tuple(np.percentile(reject_margins, [10, 50, 90])) if reject_margins else "no rejects")

print("threshold  true_accept  false_accept  accept_precision  overall_acc")
for threshold in (-2, -1, 0, 0.5, 1, 1.5, 2, 3, 4):
    tp = sum(1 for t, m in samples if t == "a" and m > threshold)
    fn = sum(1 for t, m in samples if t == "a" and m <= threshold)
    fp = sum(1 for t, m in samples if t == "r" and m > threshold)
    tn = sum(1 for t, m in samples if t == "r" and m <= threshold)
    precision = tp / (tp + fp) if tp + fp else float("nan")
    print("%8.1f  %11d  %12d  %16.3f  %11.3f" % (
        threshold, tp, fp, precision, (tp + tn) / len(samples)))
