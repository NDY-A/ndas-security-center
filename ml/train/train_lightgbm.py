#!/usr/bin/env python3
"""Train the NDAS PE malware classifier and export ONNX.

Usage: python train_lightgbm.py [csv...]
Default inputs: data/benign-system.csv, data/benign-dike.csv, data/malware-dike.csv
"""
import csv
import json
import os
import sys

import numpy as np
import lightgbm as lgb

HERE = os.path.dirname(os.path.abspath(__file__))
ML_ROOT = os.path.dirname(HERE)
DATA_DIR = os.path.join(ML_ROOT, "data")
MODEL_DIR = os.path.join(ML_ROOT, "model")
SEED = 20261113


def load_csv(paths):
    xs, ys, names = [], [], None
    for path in paths:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            feats = header[2:]
            if names is None:
                names = feats
            elif names != feats:
                raise SystemExit(f"feature schema mismatch in {path}")
            for row in reader:
                ys.append(int(row[0]))
                xs.append([float(v) for v in row[2:]])
    return np.asarray(xs, dtype=np.float32), np.asarray(ys, dtype=np.int32), names


def stratified_split(y, fraction, seed):
    rng = np.random.RandomState(seed)
    idx0 = np.where(y == 0)[0]
    idx1 = np.where(y == 1)[0]
    rng.shuffle(idx0)
    rng.shuffle(idx1)
    n0 = int(len(idx0) * fraction)
    n1 = int(len(idx1) * fraction)
    val = np.concatenate([idx0[:n0], idx1[:n1]])
    train = np.concatenate([idx0[n0:], idx1[n1:]])
    rng.shuffle(train)
    rng.shuffle(val)
    return train, val


def roc_auc(y, scores):
    order = np.argsort(scores)
    ys = y[order]
    ss = scores[order]
    ranks = np.empty(len(ss), dtype=np.float64)
    i = 0
    while i < len(ss):
        j = i
        while j < len(ss) and ss[j] == ss[i]:
            j += 1
        ranks[i:j] = (i + j - 1) / 2.0 + 1.0
        i = j
    pos = float(ys.sum())
    neg = float(len(ys) - pos)
    if pos == 0 or neg == 0:
        return 0.5
    return float((ranks[ys == 1].sum() - pos * (pos + 1) / 2.0) / (pos * neg))


def tpr_at_fpr(y, scores, max_fpr):
    order = np.argsort(-scores)
    ys = y[order]
    total_pos = max(1, int(ys.sum()))
    total_neg = max(1, int(len(ys) - ys.sum()))
    tp = fp = 0
    best = 0.0
    for yi in ys:
        if yi == 1:
            tp += 1
        else:
            fp += 1
        if fp / total_neg > max_fpr:
            break
        best = max(best, tp / total_pos)
    return float(best)


def threshold_for_fpr(y, scores, max_fpr):
    neg_scores = np.sort(scores[y == 0])[::-1]
    allowed = int(len(neg_scores) * max_fpr)
    if allowed <= 0:
        return 1.0
    return float(min(1.0, neg_scores[allowed - 1] + 1e-6))


def main():
    args = sys.argv[1:]
    if args:
        paths = args
    else:
        paths = [
            os.path.join(DATA_DIR, "benign-system.csv"),
            os.path.join(DATA_DIR, "benign-dike.csv"),
            os.path.join(DATA_DIR, "benign-user.csv"),
            os.path.join(DATA_DIR, "malware-dike.csv"),
            os.path.join(DATA_DIR, "malware-user.csv"),
            os.path.join(DATA_DIR, "malware-host.csv"),
        ]
        paths = [p for p in paths if os.path.exists(p)]
    if len(paths) < 2:
        raise SystemExit("need at least two labeled CSVs (benign + malware)")

    x, y, names = load_csv(paths)
    print(f"samples={len(y)} benign={int((y == 0).sum())} malware={int((y == 1).sum())} features={len(names)}")

    train_idx, val_idx = stratified_split(y, 0.2, SEED)
    positives = max(1, int(y.sum()))
    negatives = max(1, int(len(y) - positives))
    dtrain = lgb.Dataset(x[train_idx], label=y[train_idx], feature_name=names)
    dval = lgb.Dataset(x[val_idx], label=y[val_idx], reference=dtrain)

    params = {
        "objective": "binary",
        "metric": "auc",
        "learning_rate": 0.05,
        "num_leaves": 63,
        "min_data_in_leaf": 20,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 1,
        "lambda_l2": 1.0,
        "verbosity": -1,
        "seed": SEED,
        "num_threads": 4,
        "scale_pos_weight": negatives / positives,
    }
    booster = lgb.train(
        params,
        dtrain,
        num_boost_round=1000,
        valid_sets=[dval],
        callbacks=[lgb.early_stopping(60, verbose=False), lgb.log_evaluation(100)],
    )

    val_scores = booster.predict(x[val_idx].astype(np.float64))
    val_y = y[val_idx]
    auc = roc_auc(val_y, val_scores)
    threshold_fpr1 = threshold_for_fpr(val_y, val_scores, 0.01)
    tpr_fpr1 = tpr_at_fpr(val_y, val_scores, 0.01)
    acc = float(((val_scores >= 0.5).astype(np.int32) == val_y).mean())

    gains = booster.feature_importance(importance_type="gain")
    order = np.argsort(-gains)
    top = [(names[i], float(gains[i])) for i in order[:15]]

    os.makedirs(MODEL_DIR, exist_ok=True)
    model_txt = os.path.join(MODEL_DIR, "pe-ml.txt")
    booster.save_model(model_txt)

    onnx_status = "not-exported"
    onnx_path = os.path.join(MODEL_DIR, "pe-ml.onnx")
    try:
        from onnxmltools import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType
        import onnx
        import onnxruntime as ort

        initial_types = [("input", FloatTensorType([None, len(names)]))]
        onnx_model = convert_lightgbm(
            booster, initial_types=initial_types, zipmap=False
        )
        onnx.save(onnx_model, onnx_path)
        sess = ort.InferenceSession(onnx_path)
        probe = x[val_idx[:8]].astype(np.float32)
        ort_out = sess.run(None, {sess.get_inputs()[0].name: probe})
        probs = None
        for value in ort_out:
            arr = np.asarray(value)
            if arr.ndim == 2 and arr.shape[1] == 2:
                probs = arr[:, 1]
                break
        if probs is None:
            raise RuntimeError(f"unexpected ONNX outputs: {[np.asarray(v).shape for v in ort_out]}")
        expected = booster.predict(x[val_idx[:8]].astype(np.float64))
        diff = float(np.max(np.abs(probs - expected)))
        onnx_status = f"ok max_diff={diff:.6g} size={os.path.getsize(onnx_path) / 1048576:.2f}MB"
    except Exception as exc:  # noqa: BLE001
        onnx_status = f"failed: {exc}"

    metrics = {
        "samples": int(len(y)),
        "train_samples": int(len(train_idx)),
        "val_samples": int(len(val_idx)),
        "features": len(names),
        "best_iteration": int(booster.best_iteration or 0),
        "val_auc": auc,
        "val_accuracy_at_0.5": acc,
        "val_tpr_at_fpr_1pct": tpr_fpr1,
        "threshold_fpr_1pct": threshold_fpr1,
        "top_features": top,
        "onnx": onnx_status,
    }
    metrics_path = os.path.join(MODEL_DIR, "metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    if onnx_status.startswith("ok"):
        seed_dir = os.path.join(os.path.dirname(ML_ROOT), "data", "seed", "ml")
        os.makedirs(seed_dir, exist_ok=True)
        with open(onnx_path, "rb") as src, open(os.path.join(seed_dir, "pe-ml.onnx"), "wb") as dst:
            dst.write(src.read())
        with open(metrics_path, "r", encoding="utf-8") as src, open(
            os.path.join(seed_dir, "metrics.json"), "w", encoding="utf-8"
        ) as dst:
            dst.write(src.read())
        print(f"copied model to {seed_dir}")

    print(json.dumps(metrics, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
