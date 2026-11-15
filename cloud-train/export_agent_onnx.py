"""Export the trained 300M model to ONNX, then INT8-quantize to ~300MB.

SDPA has no direct ONNX lowering on older exporters, so the export temporarily
swaps in an eager matmul/softmax implementation (numerically identical).
"""
from __future__ import annotations

from pathlib import Path

import torch
import torch.nn.functional as F

from model import AgentLM

HERE = Path(__file__).resolve().parent
RUNTIME = HERE / "runtime"
OUT = HERE / "agent-model.onnx"
OUT_INT8 = HERE / "agent-model-int8.onnx"


def eager_sdpa(query, key, value, attn_mask=None, dropout_p=0.0, is_causal=False, **kwargs):
    scale = query.size(-1) ** -0.5
    scores = torch.matmul(query, key.transpose(-2, -1)) * scale
    if attn_mask is not None:
        # Mirror PyTorch SDPA semantics exactly: bool True = participate,
        # float masks are added to the scores.
        if attn_mask.dtype == torch.bool:
            scores = scores.masked_fill(attn_mask.logical_not(), float("-inf"))
        else:
            scores = scores + attn_mask
    probs = torch.softmax(scores, dim=-1)
    if dropout_p > 0:
        probs = F.dropout(probs, dropout_p)
    return torch.matmul(probs, value)


def main() -> int:
    state_path = RUNTIME / "agent-model.pt"
    if not state_path.exists():
        raise SystemExit(f"missing trained weights: {state_path}")

    model = AgentLM()
    model.load_state_dict(torch.load(state_path, map_location="cpu"))
    model.eval()
    for parameter in model.parameters():
        parameter.requires_grad_(False)

    class Wrapper(torch.nn.Module):
        def __init__(self, inner: torch.nn.Module) -> None:
            super().__init__()
            self.inner = inner

        def forward(self, tokens: torch.Tensor) -> torch.Tensor:
            with torch.no_grad():
                return self.inner(tokens)

    original_sdpa = F.scaled_dot_product_attention
    F.scaled_dot_product_attention = eager_sdpa
    try:
        dummy = torch.randint(0, 256, (1, 512), dtype=torch.long)
        export_kwargs = dict(
            input_names=["tokens"],
            output_names=["logits"],
            dynamic_axes={"tokens": {1: "seq"}, "logits": {1: "seq"}},
            opset_version=17,
            do_constant_folding=True,
        )
        try:
            torch.onnx.export(Wrapper(model), (dummy,), str(OUT), dynamo=False, **export_kwargs)
        except TypeError:
            torch.onnx.export(Wrapper(model), (dummy,), str(OUT), **export_kwargs)
    finally:
        F.scaled_dot_product_attention = original_sdpa
    print("fp32 written", OUT, round(OUT.stat().st_size / 1073741824, 2), "GB")

    import numpy as np
    import onnxruntime

    session = onnxruntime.InferenceSession(str(OUT), providers=["CPUExecutionProvider"])
    rng = np.random.default_rng(3)
    probe = rng.integers(0, 256, size=(1, 64), dtype=np.int64)
    mutated = probe.copy()
    mutated[0, 32:] = rng.integers(0, 256, size=(32,), dtype=np.int64)
    early_a = session.run(None, {"tokens": probe})[0][0, :32]
    early_b = session.run(None, {"tokens": mutated})[0][0, :32]
    leak = float(np.max(np.abs(early_a - early_b)))
    print("causality check early-diff:", leak, flush=True)
    if leak > 1e-4:
        raise SystemExit("exported model is not causal; refuse to quantize")

    try:
        import gc

        # Free the torch weights before quantization so the two peaks do not stack.
        del model
        gc.collect()

        from onnxruntime.quantization import QuantType, quantize_dynamic

        quantize_dynamic(model_input=str(OUT), model_output=str(OUT_INT8), weight_type=QuantType.QInt8)
        print("int8 written", OUT_INT8, round(OUT_INT8.stat().st_size / 1048576, 1), "MB")
    except Exception as exception:  # noqa: BLE001 - quantization is optional
        print("int8 quantization skipped:", exception)

    try:
        import numpy as np
        import onnxruntime

        target = OUT_INT8 if OUT_INT8.exists() else OUT
        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = 4
        session = onnxruntime.InferenceSession(str(target), sess_options=options,
                                               providers=["CPUExecutionProvider"])
        ids = np.asarray([torch.randint(0, 256, (512,)).numpy()], dtype=np.int64)
        outputs = session.run(None, {"tokens": ids})
        print("onnx smoke ok:", target.name, outputs[0].shape)
    except Exception as exception:  # noqa: BLE001 - smoke is advisory
        print("onnx smoke skipped:", exception)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
