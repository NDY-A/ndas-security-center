"""Generate a one-click Colab notebook that embeds the cloud training scripts."""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = [
    "model.py",
    "make_agent_data.py",
    "train_agent_model.py",
    "export_agent_onnx.py",
    "agent_model_runtime.py",
]
OUT = HERE / "ndas-agent-colab.ipynb"


def code(source: str, cell_id: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "id": cell_id,
        "metadata": {},
        "outputs": [],
        "source": source,
    }


def markdown(source: str, cell_id: str) -> dict:
    return {"cell_type": "markdown", "id": cell_id, "metadata": {}, "source": source}


cells = [
    markdown(
        "# NDAS 决策模型训练（Colab 免费 T4）\n"
        "\n"
        "**2026-11-14 修复**：旧版 SDPA bool 掩码语义用反（能看未来 token，标签泄漏），"
        "旧 checkpoint 全部作废，必须从头重训。**不要用旧断点续训。**\n"
        "\n"
        "1. 菜单：代码执行程序 → 更改运行时类型 → **T4 GPU**\n"
        "2. 从上到下依次运行各单元格（训练格不带 --resume，会重新开始并覆盖 Drive 旧断点）\n"
        "3. 断线重连后先重跑 writefile 各格，再用「续训」格（仅限本次训练产生的断点）\n"
        "\n"
        "模型规格：300M 参数（dim 1024 / 24 层），INT8 导出约 300MB。\n"
        "总耗时：T4 + AMP 估计 40-60 分钟/轮，3 轮（早停 0.92）。\n"
        "导出格自带因果自检：早期位置 diff 必须为 0，否则拒绝量化。",
        "intro",
    ),
    code(
        "!nvidia-smi\n"
        "import torch\n"
        "print('torch', torch.__version__, '| cuda', torch.cuda.is_available())\n"
        "!mkdir -p /content/agent",
        "gpu-check",
    ),
    code("!pip install -q onnxruntime onnx numpy", "deps"),
]

for index, name in enumerate(FILES):
    text = (HERE / name).read_text(encoding="utf-8")
    cells.append(code(f"%%writefile /content/agent/{name}\n" + text, f"write-{index}"))

cells.extend(
    [
        code(
            "from google.colab import drive\n"
            "drive.mount('/content/drive')\n"
            "import os\n"
            "os.environ['NDAS_CKPT_DIR'] = '/content/drive/MyDrive/ndas-agent'\n"
            "os.makedirs(os.environ['NDAS_CKPT_DIR'], exist_ok=True)\n"
            "print('checkpoints ->', os.environ['NDAS_CKPT_DIR'])",
            "mount-drive",
        ),
        code(
            "%cd /content/agent\n"
            "!python make_agent_data.py\n"
            "!python train_agent_model.py",
            "train",
        ),
        code("%cd /content/agent\n!python train_agent_model.py --resume", "resume"),
        code("%cd /content/agent\n!python export_agent_onnx.py", "export"),
        code(
            "import os, shutil\n"
            "candidates = ['/content/agent/agent-model-int8.onnx', '/content/agent/agent-model.onnx']\n"
            "src = next((p for p in candidates if os.path.exists(p)), None)\n"
            "if src is None:\n"
            "    print('no exported model found; run the export cell first')\n"
            "else:\n"
            "    dst = '/content/drive/MyDrive/ndas-agent/' + os.path.basename(src)\n"
            "    shutil.copy(src, dst)\n"
            "    print('saved to Drive:', dst, '| size MB:', round(os.path.getsize(src)/1048576, 1))\n"
            "    from google.colab import files\n"
            "    files.download(src)",
            "download",
        ),
    ]
)

notebook = {
    "cells": cells,
    "metadata": {
        "colab": {"provenance": [], "gpuType": "T4"},
        "kernelspec": {"display_name": "Python 3", "name": "python3"},
        "language_info": {"name": "python"},
        "accelerator": "GPU",
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

OUT.write_text(json.dumps(notebook, ensure_ascii=False, indent=1), encoding="utf-8")
print("written", OUT, OUT.stat().st_size, "bytes,", len(cells), "cells")
