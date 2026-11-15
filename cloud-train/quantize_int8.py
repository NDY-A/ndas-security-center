import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "agent-model-initializers.onnx")
DST = os.path.join(HERE, "agent-model-int8.onnx")

if not os.path.exists(SRC):
    raise SystemExit("missing fp32 onnx: " + SRC)
if os.path.exists(DST):
    print("int8 output already exists, remove it first:", DST)
    raise SystemExit(2)

t0 = time.time()
print("quantizing %s (%.2f GB)" % (SRC, os.path.getsize(SRC) / 1073741824), flush=True)

from onnxruntime.quantization import QuantType, quantize_dynamic

quantize_dynamic(model_input=SRC, model_output=DST, weight_type=QuantType.QInt8)

size_mb = os.path.getsize(DST) / 1048576
print("done in %.1f s, int8 size %.1f MB" % (time.time() - t0, size_mb), flush=True)
