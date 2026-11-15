"""Byte-level decoder model shared by the agent trainer and runtime."""
from __future__ import annotations

import torch
import torch.nn as nn

PAD = 258
BOS = 256
EOS = 257
VOCAB = 259
MAX_CONTEXT = 1024


class AgentLM(nn.Module):
    def __init__(self, dim: int = 192, heads: int = 4, layers: int = 4, ff: int = 576):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, dim, padding_idx=PAD)
        self.pos = nn.Embedding(MAX_CONTEXT, dim)
        layer = nn.TransformerEncoderLayer(
            d_model=dim, nhead=heads, dim_feedforward=ff,
            dropout=0.1, batch_first=True, activation="gelu",
            norm_first=True)
        self.encoder = nn.TransformerEncoder(layer, num_layers=layers)
        self.norm = nn.LayerNorm(dim)
        self.head = nn.Linear(dim, VOCAB, bias=False)
        # Precomputed causal mask keeps torch.onnx export traceable.
        mask = torch.triu(torch.full((MAX_CONTEXT, MAX_CONTEXT), float("-inf")), diagonal=1)
        self.register_buffer("causal_mask", mask, persistent=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        batch, length = x.shape
        pos = torch.arange(length, device=x.device).unsqueeze(0).expand(batch, length)
        h = self.emb(x) + self.pos(pos)
        mask = self.causal_mask[:length, :length]
        h = self.encoder(h, mask=mask, src_key_padding_mask=x == PAD)
        return self.head(self.norm(h))


def encode_bytes(text: str, limit: int = MAX_CONTEXT) -> list[int]:
    data = text.encode("utf-8", errors="replace")[:limit]
    return list(data)


def decode_tokens(tokens: list[int]) -> str:
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
        if temperature <= 0:
            token = int(torch.argmax(logits))
        else:
            probs = torch.softmax(logits / temperature, dim=-1)
            token = int(torch.multinomial(probs, 1))
        if token == EOS:
            break
        produced.append(token)
        tensor = torch.cat([tensor, torch.tensor([[token]], dtype=torch.long)], dim=1)
        if tensor.shape[1] >= MAX_CONTEXT:
            break
    return decode_tokens(produced)
