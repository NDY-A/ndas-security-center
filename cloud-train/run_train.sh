#!/usr/bin/env bash
# NDAS 300M decision-model cloud training (Colab T4 / any CUDA GPU).
# First run: bash run_train.sh
# Resume:    bash run_train.sh --resume
set -euo pipefail
cd "$(dirname "$0")"
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
export NDAS_CKPT_DIR="${NDAS_CKPT_DIR:-/content/drive/MyDrive/ndas-agent}"

python -m pip install --quiet --disable-pip-version-check onnxruntime onnx numpy

echo "[1/4] generating confirmation dataset (15000 rows)"
python make_agent_data.py

echo "[2/4] training (304M params / SDPA / AMP / batch 16 / 3 epochs)"
python train_agent_model.py "$@"

echo "[3/4] exporting ONNX + INT8 quantization"
python export_agent_onnx.py

echo "[4/4] done - download agent-model-int8.onnx (about 300MB)"
ls -la agent-model-int8.onnx agent-model.onnx runtime/metrics.json 2>/dev/null || true
echo "Put agent-model-int8.onnx into the repo as tools/security-agent/agent-model.onnx"
