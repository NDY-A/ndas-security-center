"""Byte-level decoder model with memory-efficient SDPA attention (300M params)."""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

PAD = 258
BOS = 256
EOS = 257
VOCAB = 259
MAX_CONTEXT = 1024


class AgentBlock(nn.Module):
    """Pre-norm transformer block using scaled_dot_product_attention.

    Right-padded inputs are safe with the causal mask alone, so no padding mask
    is needed and no per-layer mask materialisation happens.
    """

    def __init__(self, dim: int, heads: int, ff: int, dropout: float = 0.1):
        super().__init__()
        self.heads = heads
        self.dim = dim
        self.norm1 = nn.LayerNorm(dim)
        self.qkv = nn.Linear(dim, dim * 3, bias=False)
        self.proj = nn.Linear(dim, dim, bias=False)
        self.norm2 = nn.LayerNorm(dim)
        self.ff1 = nn.Linear(dim, ff, bias=False)
        self.ff2 = nn.Linear(ff, dim, bias=False)
        self.drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        batch, length, dim = x.shape
        h = self.norm1(x)
        qkv = self.qkv(h).reshape(batch, length, 3, self.heads, dim // self.heads)
        qkv = qkv.permute(2, 0, 3, 1, 4)
        q, k, v = qkv[0], qkv[1], qkv[2]
        attn = F.scaled_dot_product_attention(q, k, v, attn_mask=mask)
        attn = attn.transpose(1, 2).reshape(batch, length, dim)
        x = x + self.drop(self.proj(attn))
        x = x + self.drop(self.ff2(F.gelu(self.ff1(self.norm2(x)))))
        return x


class AgentLM(nn.Module):
    def __init__(self, dim: int = 1024, heads: int = 16, layers: int = 24, ff: int = 4096):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, dim, padding_idx=PAD)
        self.pos = nn.Embedding(MAX_CONTEXT, dim)
        self.blocks = nn.ModuleList(AgentBlock(dim, heads, ff) for _ in range(layers))
        self.norm = nn.LayerNorm(dim)
        self.head = nn.Linear(dim, VOCAB, bias=False)
        # Float additive mask: SDPA adds it to the scores, so -inf above the
        # diagonal is causal. A bool mask here would mean "participate" in SDPA
        # and let every position attend to future tokens (label leakage).
        mask = torch.triu(torch.full((MAX_CONTEXT, MAX_CONTEXT), float("-inf")), diagonal=1)
        self.register_buffer("causal_mask", mask, persistent=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        batch, length = x.shape
        pos = torch.arange(length, device=x.device).unsqueeze(0).expand(batch, length)
        h = self.emb(x) + self.pos(pos)
        mask = self.causal_mask[:length, :length]
        for block in self.blocks:
            h = block(h, mask)
        return self.head(self.norm(h))


def encode_bytes(text: str, limit: int = MAX_CONTEXT) -> list:
    return list(text.encode("utf-8", errors="replace")[:limit])


def decode_tokens(tokens: list) -> str:
    out = bytearray()
    for token in tokens:
        if token in (PAD, BOS, EOS):
            if token == EOS:
                break
            continue
        if 0 <= token < 256:
            out.append(token)
    return out.decode("utf-8", errors="replace")


@torch.no_grad()
def generate(model: AgentLM, prompt: str, max_new: int = 192, temperature: float = 0.0) -> str:
    model.eval()
    ids = [BOS] + encode_bytes(prompt)
    ids = ids[-(MAX_CONTEXT - max_new - 1):]
    tensor = torch.tensor([ids], dtype=torch.long)
    produced: list[int] = []
    for _ in range(max_new):
        logits = model(tensor)[0, -1]
        token = int(torch.argmax(logits))
        if token == EOS:
            break
        produced.append(token)
        tensor = torch.cat([tensor, torch.tensor([[token]], dtype=torch.long)], dim=1)
        if tensor.shape[1] >= MAX_CONTEXT:
            break
    return decode_tokens(produced)
