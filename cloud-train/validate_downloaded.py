"""Measure decision accuracy of the downloaded INT8 model on the training distribution."""

import json
import os

import numpy as np
import onnxruntime

MODEL = r"E:\下载\agent-model-int8_3.onnx"
DATA = r"E:\My_Project\Aegis\tools\security-agent\agent-data.jsonl"
SAMPLE_EVERY = 40

options = onnxruntime.SessionOptions()
options.intra_op_num_threads = 4
options.log_severity_level = 3
session = onnxruntime.InferenceSession(MODEL, sess_options=options, providers=["CPUExecutionProvider"])
input_name = session.get_inputs()[0].name

rows = []
with open(DATA, encoding="utf-8") as handle:
    for index, line in enumerate(handle):
        if index % SAMPLE_EVERY == 0:
            rows.append(json.loads(line))

tp = fp = tn = fn = 0
target_correct = eos_correct = tokens_total = tokens_correct = 0
margins = []
for row in rows:
    tokens = [256] + list(row["prompt"].encode("utf-8"))[:511]
    label = 97 if row["target"] == "a" else 114
    # Feed prompt + label so one forward yields both supervised positions:
    # logits[P-1] predicts the label, logits[P] predicts EOS.
    ids = tokens + [label]
    logits = session.run(None, {input_name: np.asarray([ids], dtype=np.int64)})[0][0]
    first = int(np.argmax(logits[len(tokens) - 1]))
    second = int(np.argmax(logits[len(tokens)]))
    target_correct += int(first == label)
    eos_correct += int(second == 257)
    tokens_correct += int(first == label) + int(second == 257)
    tokens_total += 2
    last = logits[len(tokens) - 1]
    margins.append((row["target"], float(last[97] - last[114])))
    predicted_accept = first == 97
    if row["target"] == "a":
        tp += predicted_accept
        fn += not predicted_accept
    else:
        fp += predicted_accept
        tn += not predicted_accept

n = len(rows)
print("rows=%d" % n)
print("accept hit=%d/%d reject hit=%d/%d" % (tp, tp + fn, tn, tn + fp))
print("decision acc=%.3f  false-accept=%d  false-reject=%d" % ((tp + tn) / n, fp, fn))
print("target acc=%.3f eos acc=%.3f token acc=%.3f" % (
    target_correct / n, eos_correct / n, tokens_correct / tokens_total))

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "margins.json"), "w") as dump:
    json.dump(margins, dump)

print("threshold  true_accept  false_accept  precision  recall  overall")
for threshold in (0.0, 0.5, 1.0, 1.5, 2.0, 2.2, 2.4, 2.6, 2.8):
    ta = sum(1 for t, m in margins if t == "a" and m > threshold)
    fa = sum(1 for t, m in margins if t == "r" and m > threshold)
    acc_n = sum(1 for t, m in margins if (t == "a") == (m > threshold))
    precision = ta / (ta + fa) if ta + fa else float("nan")
    recall = ta / (tp + fn)
    print("%9.1f  %11d  %12d  %9.3f  %6.3f  %7.3f" % (
        threshold, ta, fa, precision, recall, acc_n / n))
