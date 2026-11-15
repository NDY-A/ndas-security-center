"""Tiny-model check: the ONNX export must be causal and use initializer weights."""

import os
import tempfile

import numpy as np
import onnx
import onnxruntime
import torch
import torch.nn.functional as F

from export_agent_onnx import eager_sdpa
from model import AgentLM

torch.manual_seed(0)
model = AgentLM(dim=64, heads=4, layers=2, ff=128)
model.eval()

out_path = os.path.join(tempfile.gettempdir(), "ndas-tiny-causal.onnx")
original = F.scaled_dot_product_attention
F.scaled_dot_product_attention = eager_sdpa
try:
    dummy = torch.randint(0, 256, (1, 32), dtype=torch.long)
    torch.onnx.export(model, (dummy,), out_path, input_names=["tokens"],
                      output_names=["logits"], dynamic_axes={"tokens": {1: "seq"}, "logits": {1: "seq"}},
                      opset_version=17, do_constant_folding=True, dynamo=False)
finally:
    F.scaled_dot_product_attention = original

proto = onnx.load(out_path, load_external_data=False)
print("initializers:", len(proto.graph.initializer))
print("constant nodes:", sum(1 for n in proto.graph.node if n.op_type == "Constant"))

session = onnxruntime.InferenceSession(out_path, providers=["CPUExecutionProvider"])
name = session.get_inputs()[0].name
rng = np.random.default_rng(3)
a = rng.integers(0, 256, size=(1, 32), dtype=np.int64)
b = a.copy()
b[0, 16:] = rng.integers(0, 256, size=(16,), dtype=np.int64)
la = session.run(None, {name: a})[0]
lb = session.run(None, {name: b})[0]
early_diff = float(np.max(np.abs(la[0, :16] - lb[0, :16])))
late_diff = float(np.max(np.abs(la[0, 16:] - lb[0, 16:])))
print("max diff at positions 0-15 (must be 0):", early_diff)
print("max diff at positions 16-31 (must be >0):", late_diff)
print("CAUSAL OK" if early_diff == 0.0 and late_diff > 0 else "CAUSAL BROKEN")
