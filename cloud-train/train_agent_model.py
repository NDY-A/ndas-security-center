"""Train the 300M NDAS decision model (confirmation task) on a Colab T4.

Features baked in (no post-hoc patching needed):
- SDPA attention model (see model.py) with causal mask only
- AMP mixed precision
- batch 16 / 3 epochs / early stop at val acc 0.92
- checkpoint every epoch to NDAS_CKPT_DIR (Google Drive) with --resume
"""
from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

# Reduce CUDA allocator fragmentation before torch initialises.
os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

import torch
import torch.nn as nn

from make_agent_data import build
from model import AgentLM, BOS, EOS, MAX_CONTEXT

OUT_DIR = Path(__file__).resolve().parent / "runtime"
SEED = 20261114
CHECKPOINT_DIR = Path(os.environ.get("NDAS_CKPT_DIR", str(OUT_DIR)))
CHECKPOINT = CHECKPOINT_DIR / "checkpoint.pt"

BATCH_SIZE = int(os.environ.get("NDAS_BATCH_SIZE", "16"))
EPOCHS = int(os.environ.get("NDAS_EPOCHS", "3"))
TARGET_ACC = float(os.environ.get("NDAS_TARGET_ACC", "0.92"))


def build_rows(rows):
    encoded = []
    for prompt, target in rows:
        prompt_bytes = prompt.encode("utf-8", errors="replace")
        target_bytes = target.encode("utf-8", errors="replace")
        ids = [BOS] + list(prompt_bytes) + list(target_bytes) + [EOS]
        if len(ids) > MAX_CONTEXT:
            continue
        # Causal-LM alignment: logits at position p predict ids[p + 1].
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


def save_checkpoint(model, optimizer, epoch, best_acc, best_state):
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "model": model.state_dict(),
            "optimizer": optimizer.state_dict(),
            "epoch": epoch,
            "best_acc": best_acc,
            "best_state": best_state,
        },
        CHECKPOINT,
    )


def main() -> int:
    random.seed(SEED)
    torch.manual_seed(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"device={device} batch={BATCH_SIZE} epochs={EPOCHS}", flush=True)

    rows = build(rows_target=15000)
    encoded = build_rows(rows)
    random.shuffle(encoded)
    split = int(len(encoded) * 0.9)
    train = encoded[:split]
    val = encoded[split:]
    print(f"rows total={len(encoded)} train={len(train)} val={len(val)}", flush=True)

    model = AgentLM().to(device)
    params = sum(p.numel() for p in model.parameters())
    print(f"parameters={params / 1e6:.1f}M ({params * 4 / 1073741824:.2f} GB fp32)", flush=True)

    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-4, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss(ignore_index=-100)
    best_acc = 0.0
    best_state = None
    start_epoch = 0
    use_amp = device.type == "cuda"
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    if use_amp:
        print("AMP enabled (mixed precision)", flush=True)

    if "--resume" in sys.argv and CHECKPOINT.exists():
        checkpoint = torch.load(CHECKPOINT, map_location="cpu", weights_only=False)
        model.load_state_dict(checkpoint["model"])
        model.to(device)
        optimizer.load_state_dict(checkpoint["optimizer"])
        start_epoch = checkpoint["epoch"] + 1
        best_acc = checkpoint.get("best_acc", 0.0)
        best_state = checkpoint.get("best_state")
        print(f"resumed at epoch {start_epoch}, best_acc={best_acc:.4f}", flush=True)

    for epoch in range(start_epoch, EPOCHS):
        model.train()
        random.shuffle(train)
        total = 0.0
        steps = 0
        for i in range(0, len(train), BATCH_SIZE):
            xs, ys = pad_batch(train[i:i + BATCH_SIZE], 258)
            xs = xs.to(device)
            ys = ys.to(device)
            with torch.amp.autocast("cuda", enabled=use_amp):
                logits = model(xs)
                loss = criterion(logits.reshape(-1, logits.shape[-1]), ys.reshape(-1))
            optimizer.zero_grad()
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
            total += float(loss.detach())
            steps += 1
            if steps % 50 == 0:
                print(f"epoch {epoch + 1} step {steps} loss={total / steps:.4f}", flush=True)
        model.eval()
        correct = total_tokens = 0
        with torch.no_grad():
            for i in range(0, len(val), BATCH_SIZE):
                xs, ys = pad_batch(val[i:i + BATCH_SIZE], 258)
                xs = xs.to(device)
                ys = ys.to(device)
                with torch.amp.autocast("cuda", enabled=use_amp):
                    logits = model(xs)
                pred = logits.argmax(-1)
                mask = ys != -100
                correct += int(((pred == ys) & mask).sum())
                total_tokens += int(mask.sum())
        acc = correct / max(1, total_tokens)
        print(f"epoch {epoch + 1}/{EPOCHS} loss={total / steps:.4f} val_token_acc={acc:.4f}", flush=True)
        if acc >= best_acc:
            best_acc = acc
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        save_checkpoint(model, optimizer, epoch, best_acc, best_state)
        if acc >= TARGET_ACC:
            print("early stop: target accuracy reached", flush=True)
            break

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
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
    }
    (OUT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=1), encoding="utf-8")
    print(json.dumps(metrics, indent=1), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
