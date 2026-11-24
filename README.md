# NDAS 安全中心（NDAS Security Center）

一个面向 Windows 的本地防护工具：本地病毒库 + YARA + 启发式分析 + PE 机器学习模型 +
用户态 HIPS，带 WinUI 3 界面和 LocalSystem 防护服务。**当前为公测版（Public Beta）**，
安装包未代码签名。

NDAS is a local Windows security tool combining signature matching, a C#
YARA subset engine, heuristics, a native PE machine-learning classifier,
user-mode HIPS, a WinUI 3 UI and a LocalSystem protection service. This is an
**unsigned public beta**.

## 功能

- **扫描**：哈希 / 域名 / IP / 路径 IOC、YARA（内置 Elastic 规则集 + 可更新的 Defender 转化扩展包）、PE 与脚本启发式、云信誉接口
- **增强型规则引擎 II**（可选，默认关闭）：加载约 9.7 万条扩展 YARA 规则，
  **至少占用 5 GB 内存**，在「威胁和防护设置」中开启后重启 NDAS 生效
- **保护历史**：独立页面集中展示本次运行的扫描发现与主动防护事件，扫描结果可直接隔离 / 删除 / 加入白名单
- **机器学习**：C++ 原生提取 109 维 PE 静态特征（含 Authenticode 签名校验状态），LightGBM 模型经
  ONNX Runtime 本地推理；ML 分数只作加权信号（单独最高 Pua 级），与哈希/YARA/启发式
  叠加后才可能判定恶意；签名校验失败 + ML 中等分 = 白加黑宿主篡改联合规则
- **实时防护**：监控新启动进程与活动程序，扫描桌面/下载新增文件；命中后 ACL + 独占句柄锁定文件
- **闲时扫描**：系统空闲约 10 分钟后扫描用户桌面/下载/启动、公用桌面、Program Files、ProgramData
- **持续后台扫描**：常驻扫描引擎默认开启，永不停歇轮转系统关键位置（桌面/下载/启动、
  Program Files、ProgramData、Temp、System32），全部经过 ML 模型；进程 CPU 占用上限 12%
- **主动防护（HIPS）**：进程链、注入/侧载、Run/RunOnce 注册表变更；可选自动终止
- **处置**：检测即锁定、恶意进程自动终止、恶意 `SiPolicy.p7b` 备份后删除
- **通知**：威胁通知；未处理威胁每分钟重复提醒；关闭实时防护时显示红色警示并通知
- **服务自愈**：`NDASService` 崩溃后由 SCM 每 30 秒尝试重启（3 次，1 天重置）
- **自保护守卫（NdasGuard）**：SYSTEM 守卫服务 + 10 个哨兵进程每秒互检；任一哨兵或
  `NDASService`/`NdasGuard` 服务被终止会在约 1 秒内自动重建；普通用户无法结束哨兵进程。
  安全模式下守卫自动停用——**正常模式下无法卸载/停止守卫，卸载请进入安全模式**；
  升级安装由安装包自动让位，无需手动处理
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

# 无 Agent 版：不打包 AI 决策 Agent 及其模型，安装体积更小
powershell -ExecutionPolicy Bypass -File installer/build-msi.ps1 -WithoutAgent
```

产物位于 `dist/`（已在 `.gitignore` 中排除）。每次发版同时产出两个变体：
`NDAS-…-win-x64.msi`（完整）与 `NDAS-…-noagent-win-x64.msi`（不含
`Program Files\NDAS\Agent`）。两者共用升级代码，切换变体建议先卸载或带版本号升级安装。主程序工程为
`src/Aegis.App`，服务为 `src/Aegis.Service`，核心引擎为 `src/Aegis.Core`，
HIPS 为 `src/Aegis.Hips`，ML 托管桥为 `src/Aegis.ML`，原生特征提取与推理为
`native/AegisMl`（需 VS C++ 工具链；MSI 构建脚本会自动编译）。

模型训练：`ml/train/train_lightgbm.py`（LightGBM → ONNX，特征由
`AegisMlDump` 导出，训练/推理共用同一 C++ 特征实现）。

## 安装与卸载

从 [Releases](../../releases) 下载 `NDAS-rs_p0.0.14.0a-win-x64.msi`（完整版）或
`NDAS-rs_p0.0.14.0a-noagent-win-x64.msi`（不含 AI 决策 Agent，体积更小），右键以管理员
安装。未签名包会触发 SmartScreen，请确认来源后继续。

**卸载**：自保护守卫运行时无法在正常模式卸载。请进入安全模式后在
“应用和功能”中卸载（守卫在安全模式自动停用）。正常模式下的卸载尝试会被守卫
恢复；升级到新版本时安装包会自动暂停守卫，无需进入安全模式。

## 数据与更新

- 内置病毒库（`data/seed`）来自
  [NDY-A/malware-egress-blocklist](https://github.com/NDY-A/malware-egress-blocklist)。
- 更新源按顺序尝试：GitHub Raw → GitHub Web Raw → jsDelivr → jsDelivr CDN，
  每个请求带防缓存查询参数；候选文件的 SHA-256 与字节数会在提交前校验。
- 更新是原子替换：新库先写入临时目录并完整解析验证，全部通过后才整体替换
  `%LOCALAPPDATA%\NDAS\signatures\current`，旧库保留在 `previous` 以便回滚。
- YARA 规则来自 Elastic `protections-artifacts`，按 **Elastic License 2.0** 分发，
  见 `data/seed/yara/LICENSE-elastic.txt` 与 `THIRD-PARTY-NOTICES.md`。
- PE ML 模型（`data/seed/ml/pe-ml.onnx`）由公开数据集
  [DikeDataset](https://github.com/iosifache/DikeDataset) 与本机良性 PE 采样训练，
  训练指标记录在 `data/seed/ml/metrics.json`。

### 扩展 YARA 规则包

- 扩展包托管在独立仓库
  [NDY-A/ndas-extended-yara](https://github.com/NDY-A/ndas-extended-yara)：根目录
  `manifest.json` 列出 14 个规则分片（`defender-patterns-part*.yara`，合计约 9.7 万条规则）
  的名称、字节数与 SHA-256；更新器按 raw.githubusercontent → GitHub Raw Web →
  jsDelivr ×2 的顺序尝试从该仓库下载，全部不可用时回退到
  `NDY-A/malware-egress-blocklist` 的 `data/yara/defender/` 旧位置。分片安装到
  `signatures/current/yara/` 并逐一校验 SHA-256 与字节数。
- 包清单与本地已安装清单一致时，更新器直接复用本地已校验分片（复制后重新校验），
  不重复下载上百 MB。
- **扩展包必须完整**：任一分片下载或校验失败时，该更新源整体判为失败并自动
  改试下一个源（`raw.githubusercontent.com` 不可达时通常由 jsDelivr 兜底）；
  源返回 404（本身不提供扩展包）不算失败。0.0.13.0a 及更早版本会把扩展包失败
  静默吞掉并照常提交——2026-11-24 的降级事故（2026.11.23.58 仅含 1,121 条规则、
  扩展包缺失）即由此导致。
- **增强型规则引擎 II**（设置 → 威胁和防护设置）：控制是否把扩展分片装入内存。
  默认关闭；启用后进程**至少占用 5 GB 内存**。保存后需**重启 NDAS** 生效
  （服务模式还需重启 NDASService）。开关只影响加载，不影响更新器照常下载并校验
  扩展包；界面用「已加载 N 条 YARA 规则」显示当前实际加载数量。
- **规则数骤减保护**：提交前比较候选库与当前库清单中的 YARA 规则总数，
  候选低于当前值的 50% 时拒绝更新并在界面报错，保护检测能力。
  确认要接受降级时，设置环境变量 `NDAS_ALLOW_YARA_REGRESSION=1` 后重启 NDAS 再更新。
- **版本防回滚**：候选版本号按点分整数比较，必须严格大于本地
  `manifest.json` 中的 `version` 才会安装。
- **手动恢复 / 回滚**：`signatures/previous` 保存上一次成功安装的完整快照。
  手动回滚时把 `previous\yara` 下缺失的扩展包文件复制回 `current\yara`，
  同步 `current\manifest.json` 的 `files` 条目与 `counts.yaraRules`，
  并把 `version` 改为比本地当前值更高的编号；应用内模式在 NDAS 启动或更新成功后
  加载新快照，服务模式还会每 10 分钟自动检查并重载——改完重启 NDAS 即可立即生效。
- 已知限制：每次重载都会完整解析全部 YARA 规则并重建匹配结构；加载 9.7 万条
  扩展规则时进程峰值内存约 4–5 GB、单次重载需数十秒 CPU。规则集越大，
  启动与重载开销越高。

## 安全边界

NDAS 是用户态防护，不是内核驱动；HIPS 与注入检测是启发式，存在漏报/误报。
请仅在你有权管理的系统上使用。自动化接口只监听回环地址并要求 Bearer 密钥。

## 许可证

源代码使用 **MIT License**（见 `LICENSE`）。第三方组件的许可证见
`THIRD-PARTY-NOTICES.md`。IOC 数据为 CC0-1.0，Elastic YARA 规则为 ELv2。
