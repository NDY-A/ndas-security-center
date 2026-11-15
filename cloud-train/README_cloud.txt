NDAS 决策模型云训练包（300M 参数，Colab T4）
===========================================

最终版（2026-11-14 修复 causal mask）：
- 重要：旧版 bool 掩码在 SDPA 中等于“看未来”，训练时标签泄漏（val 1.0 是假的），
  旧 checkpoint / 旧 ONNX 全部作废。重训必须从头开始，不要 --resume 旧断点。
- model.py                SDPA 注意力 / 304M 参数（dim1024×24层）/ 浮点 -inf 因果 mask
- make_agent_data.py      处置确认合成数据（a/r 单字符标签，4000/4000 平衡）
- train_agent_model.py    AMP + batch16 + 3 轮 + 提前停(0.92) + Drive 断点续训
- export_agent_onnx.py    导出 ONNX（SDPA 临时 eager 替换）+ INT8 量化（~300MB）
- agent_model_runtime.py  推理端参考（与 daemon 一致）
- run_train.sh            一键脚本（可传 --resume）

Colab 用法（ndas-agent-colab.ipynb 已内置一切）
1. 打开 colab.research.google.com，上传 ndas-agent-colab.ipynb
2. 代码执行程序 → 更改运行时类型 → T4 GPU
3. 从上到下运行；挂 Drive 时允许授权
4. 断线重连后：重跑 writefile 各格 + 续训格（--resume）
5. 导出完成后运行下载格，把 agent-model-int8.onnx 放回
   tools/security-agent/agent-model.onnx

CLI 用法（任意 CUDA 机器）
    bash run_train.sh            # 首次
    bash run_train.sh --resume   # 断线续训

性能参考（T4 16GB）
- batch 16 / SDPA / AMP：约 2-5 分钟/轮（15000 样本）
- 显存约 8-9GB；OOM 时设 NDAS_BATCH_SIZE=8 再跑
- 达标线 val_token_acc ≥ 0.92（早停），低于 0.85 加大数据到 40000 行

验证指标
- 训练日志每 50 步 loss、每轮 val_token_acc
- 导出格先做因果自检（早期位置 diff 必须为 0），再 fp32 ~1.2GB → INT8 ~300MB
- 本地部署验收：单次确认推理 ≤1.5 秒（确认超时 2 秒）
- 若 Colab 导出/量化 OOM：下载 runtime/agent-model.pt，本地用
  quantize_int8.py + run-limited.ps1（6GB Job Object 上限）处理
