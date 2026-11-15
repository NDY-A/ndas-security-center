"""Train the NDAS agent decision model on synthesised trajectories."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import torch
import torch.nn as nn

from make_agent_data import build
from model import AgentLM, BOS, EOS, MAX_CONTEXT

OUT_DIR = Path(__file__).resolve().parent / "runtime"
SEED = 20261114


def build_rows(rows):
    encoded = []
    for prompt, target in rows:
        prompt_bytes = prompt.encode("utf-8", errors="replace")
        target_bytes = target.encode("utf-8", errors="replace")
        ids = [BOS] + list(prompt_bytes) + list(target_bytes) + [EOS]
        if len(ids) > MAX_CONTEXT:
            continue
        # Causal-LM alignment: logits at position p predict ids[p + 1]. The first
        # supervised position is the last prompt byte, which predicts target[0].
        labels = [-100] * len(prompt_bytes) + list(target_bytes) + [EOS] + [-100]
        encoded.append((ids, labels))
    return encoded


def pad_batch(batch, pad_id):
    length = max(len(ids) for ids, _ in batch)
    xs = torch.full((len(batch), length), pad_id, dtype=torch.long)
    ys = torch.full((len(batch), length), -100, dtype=torch.long)
    for i, (ids, labels) in enumerate(batch):
        xs[i, :len(ids)] = torch.tensor(ids)
        ys[i, :len(labels)] = torch.tensor(labels)
    return xs, ys


def main() -> int:
    random.seed(SEED)
    torch.manual_seed(SEED)
    torch.set_num_threads(4)

    rows = build(rows_target=5000)
    encoded = build_rows(rows)
    random.shuffle(encoded)
    split = int(len(encoded) * 0.9)
    train = encoded[:split]
    val = encoded[split:]
    print(f"rows total={len(encoded)} train={len(train)} val={len(val)}", flush=True)

    model = AgentLM()
    params = sum(p.numel() for p in model.parameters())
    print(f"parameters={params / 1e6:.2f}M ({params * 4 / 1048576:.1f} MB fp32)", flush=True)

    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-4, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)
    batch_size = 64
    epochs = 3
    best_acc = 0.0
    best_state = None

    for epoch in range(epochs):
        model.train()
        random.shuffle(train)
        total = 0.0
        steps = 0
        for i in range(0, len(train), batch_size):
            xs, ys = pad_batch(train[i:i + batch_size], 258)
            logits = model(xs)
            loss = criterion(logits.reshape(-1, logits.shape[-1]), ys.reshape(-1))
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total += float(loss)
            steps += 1
            if steps % 100 == 0:
                print(f"epoch {epoch + 1} step {steps} loss={total / steps:.4f}", flush=True)
        model.eval()
        correct = total_tokens = 0
        with torch.no_grad():
            for i in range(0, len(val), batch_size):
                xs, ys = pad_batch(val[i:i + batch_size], 258)
                logits = model(xs)
                pred = logits.argmax(-1)
                mask = ys != -100
                correct += int(((pred == ys) & mask).sum())
                total_tokens += int(mask.sum())
        acc = correct / max(1, total_tokens)
        print(f"epoch {epoch + 1}/{epochs} loss={total / steps:.4f} val_token_acc={acc:.4f}", flush=True)
        if acc >= best_acc:
            best_acc = acc
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), OUT_DIR / "agent-model.pt")
    size = (OUT_DIR / "agent-model.pt").stat().st_size
    metrics = {
        "rows": len(encoded),
        "parameters": int(params),
        "model_bytes": int(size),
        "val_token_accuracy": best_acc,
        "epochs": epochs,
    }
    (OUT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=1), encoding="utf-8")
    print(json.dumps(metrics, indent=1), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
