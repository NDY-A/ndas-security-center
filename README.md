# NDAS 安全中心（NDAS Security Center）

一个面向 Windows 的本地防护工具：本地病毒库 + YARA + 启发式分析 + PE 机器学习模型 +
用户态 HIPS，带 WinUI 3 界面和 LocalSystem 防护服务。**当前为公测版（Public Beta）**，
安装包未代码签名。

NDAS is a local Windows security tool combining signature matching, a C#
YARA subset engine, heuristics, a native PE machine-learning classifier,
user-mode HIPS, a WinUI 3 UI and a LocalSystem protection service. This is an
**unsigned public beta**.

## 功能

- **扫描**：哈希 / 域名 / IP / 路径 IOC、YARA（内置 Elastic 规则集）、PE 与脚本启发式、云信誉接口
- **机器学习**：C++ 原生提取 108 维 PE 静态特征，LightGBM 模型经 ONNX Runtime 本地推理；
  ML 分数只作加权信号（单独最高 Pua 级），与哈希/YARA/启发式叠加后才可能判定恶意
- **实时防护**：监控新启动进程与活动程序，扫描桌面/下载新增文件；命中后 ACL + 独占句柄锁定文件
- **闲时扫描**：系统空闲约 10 分钟后扫描用户桌面/下载/启动、公用桌面、Program Files、ProgramData
- **主动防护（HIPS）**：进程链、注入/侧载、Run/RunOnce 注册表变更；可选自动终止
- **处置**：检测即锁定、恶意进程自动终止、恶意 `SiPolicy.p7b` 备份后删除
- **通知**：威胁通知；未处理威胁每分钟重复提醒；关闭实时防护时显示红色警示并通知
- **服务自愈**：`NDASService` 崩溃后由 SCM 每 30 秒尝试重启（3 次，1 天重置）
- **自动化接口**：`http://127.0.0.1:17483`，仅回环、Bearer 鉴权

## 系统要求

- Windows 10 19041+ / Windows 11，x64
- 安装需要管理员权限（注册 LocalSystem 服务和防火墙/文件 ACL 操作）
- 运行界面需要 .NET 8 与 Windows App SDK（Release 包为自包含，无需预装）

## 构建

```powershell
# 开发构建
dotnet build Aegis.sln -c Debug -p:Platform=x64

# Release 自包含发布 + MSI（需要 WiX 5：dotnet tool install --global wix）
powershell -ExecutionPolicy Bypass -File installer/build-msi.ps1
```

产物位于 `dist/`（已在 `.gitignore` 中排除）。主程序工程为
`src/Aegis.App`，服务为 `src/Aegis.Service`，核心引擎为 `src/Aegis.Core`，
HIPS 为 `src/Aegis.Hips`，ML 托管桥为 `src/Aegis.ML`，原生特征提取与推理为
`native/AegisMl`（需 VS C++ 工具链；MSI 构建脚本会自动编译）。

模型训练：`ml/train/train_lightgbm.py`（LightGBM → ONNX，特征由
`AegisMlDump` 导出，训练/推理共用同一 C++ 特征实现）。

## 安装与卸载

从 [Releases](../../releases) 下载 `NDAS-rs_p0.0.6.0a-win-x64.msi`，右键以管理员
安装。未签名包会触发 SmartScreen，请确认来源后继续。卸载可在“应用和功能”中完成；
卸载服务前请先在程序设置中关闭实时防护/退出托盘进程。

## 数据与更新

- 内置病毒库（`data/seed`）来自
  [NDY-A/malware-egress-blocklist](https://github.com/NDY-A/malware-egress-blocklist)。
- 更新通过 GitHub Raw / jsDelivr 拉取清单与 YARA 规则，带防回滚版本号比较。
- YARA 规则来自 Elastic `protections-artifacts`，按 **Elastic License 2.0** 分发，
  见 `data/seed/yara/LICENSE-elastic.txt` 与 `THIRD-PARTY-NOTICES.md`。
- PE ML 模型（`data/seed/ml/pe-ml.onnx`）由公开数据集
  [DikeDataset](https://github.com/iosifache/DikeDataset) 与本机良性 PE 采样训练，
  训练指标记录在 `data/seed/ml/metrics.json`。

## 安全边界

NDAS 是用户态防护，不是内核驱动；HIPS 与注入检测是启发式，存在漏报/误报。
请仅在你有权管理的系统上使用。自动化接口只监听回环地址并要求 Bearer 密钥。

## 许可证

源代码使用 **MIT License**（见 `LICENSE`）。第三方组件的许可证见
`THIRD-PARTY-NOTICES.md`。IOC 数据为 CC0-1.0，Elastic YARA 规则为 ELv2。
