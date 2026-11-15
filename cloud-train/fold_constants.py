"""Fold tensor-valued Constant nodes into graph initializers.

The torch legacy exporter captured the model weights as closure constants, so
all 100 large tensors live in Constant node attributes. ONNX Runtime's
quantizer only recognizes initializers, and re-serializing inlined external
data blows past protobuf's 2GB limit.
"""

import os
import time

import onnx
from onnx import TensorProto

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "agent-model.onnx")
FOLDED = os.path.join(HERE, "agent-model-initializers.onnx")
EXT_DATA = "agent-model-initializers.data"

if os.path.exists(FOLDED):
    print("folded model already exists:", FOLDED)
    raise SystemExit(0)

t0 = time.time()
print("loading fp32 model with external data...", flush=True)
model = onnx.load(SRC)

graph = model.graph
kept = []
folded = 0
for node in graph.node:
    value = None
    if node.op_type == "Constant" and len(node.output) == 1:
        for attribute in node.attribute:
            if attribute.name == "value" and attribute.type == onnx.AttributeProto.TENSOR:
                value = attribute.t
                break
    if value is None:
        kept.append(node)
        continue
    if value.data_location != TensorProto.DEFAULT:
        raise SystemExit("tensor still external after load: " + node.output[0])
    value.name = node.output[0]
    graph.initializer.append(value)
    folded += 1

del graph.node[:]
graph.node.extend(kept)
print("folded %d constant nodes, initializers now %d, nodes left %d"
      % (folded, len(graph.initializer), len(graph.node)), flush=True)

print("saving with external data...", flush=True)
onnx.save_model(model, FOLDED, save_as_external_data=True,
                all_tensors_to_one_file=True, location=EXT_DATA,
                size_threshold=1024)
print("done in %.1f s, main file %.2f MB"
      % (time.time() - t0, os.path.getsize(FOLDED) / 1048576), flush=True)
