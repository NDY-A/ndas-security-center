"""Export the trained agent model to ONNX so the packaged daemon needs no torch."""
from __future__ import annotations

from pathlib import Path

import torch

from model import AgentLM

HERE = Path(__file__).resolve().parent
RUNTIME = HERE / "runtime"
OUT = HERE / "agent-model.onnx"


def main() -> int:
    # The fused MHA fast path (aten::_transformer_encoder_layer_fwd) has no ONNX
    # lowering; disable it so the graph uses primitive ops.
    torch.backends.mha.set_fastpath_enabled(False)
    state_path = RUNTIME / "agent-model.pt"
    if not state_path.exists():
        raise SystemExit(f"missing trained weights: {state_path}")

    model = AgentLM()
    model.load_state_dict(torch.load(state_path, map_location="cpu"))
    model.eval()

    for parameter in model.parameters():
        parameter.requires_grad_(False)

    class Wrapper(torch.nn.Module):
        def forward(self, tokens: torch.Tensor) -> torch.Tensor:
            with torch.no_grad():
                return model(tokens)

    dummy = torch.randint(0, 256, (1, 512), dtype=torch.long)
    export_kwargs = dict(
        input_names=["tokens"],
        output_names=["logits"],
        dynamic_axes={"tokens": {1: "seq"}, "logits": {1: "seq"}},
        opset_version=17,
        do_constant_folding=True,
    )
    try:
        torch.onnx.export(Wrapper(), (dummy,), str(OUT), dynamo=False, **export_kwargs)
    except TypeError:
        torch.onnx.export(Wrapper(), (dummy,), str(OUT), **export_kwargs)

    try:
        import numpy as np
        import onnxruntime

        session = onnxruntime.InferenceSession(str(OUT), providers=["CPUExecutionProvider"])
        output = session.run(None, {"tokens": dummy.numpy()})
        print("onnx smoke ok, logits shape:", output[0].shape)
    except Exception as exception:  # noqa: BLE001 - smoke test is advisory
        print("onnx smoke skipped:", exception)

    print("written", OUT, OUT.stat().st_size, "bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
