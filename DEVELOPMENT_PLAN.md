# WasmSentinel 开发计划（2026-10-16）

**适用范围**：从现在到 AsiaCCS 2027 Cycle 2 截稿（2026-12-11 AoE，剩 56 天）及其后的工程收尾。
**取代**：`CCS2026_ROADMAP.md`、`RESEARCH.md`、`SESSION_STATE.md`（三者描述的目标会议与实验状态已过期，建议归档到 `docs/history/`）。
**补充**：`IMPROVEMENT_PLAN.md`（2026-10-13 的仓库卫生方案）的 P0（push）与 P1（27 GB 日志）已于 2026-10-16 完成，见 §1.1 与 `RESEARCH_LOG.md`。

本文件所有事实均为 2026-10-16 实查结果，证据路径见附录 C。凡写"❌"的条目，意思是**论文里的主张在仓库里找不到产生它的实验**，不是说主张一定为假。

---

## 0. 一页摘要

| 项 | 现状 |
|---|---|
| 代码 | Go host 3.9K 行 + Rust 规则 2.9K 行 + BPF C 291 行 + Python 评估 7.7K 行。`go build ./cmd/main.go` 通过；`go build ./...` 失败（eBPF 包缺 bpf2go 生成物）；Rust 17 个单测通过；0 个 Go 测试 |
| 运行形态 | 主程序实际使用 **/proc 轮询采集器 + 简化 Wasm 引擎**。eBPF 采集器与零拷贝通道代码存在但**未接入主程序** |
| 论文 | `paper-dimva/`（LNCS，19 页，2026-02-28 编译）。核心数字之间互相矛盾，且 **8 类主张在仓库里没有真实实验来源**（§1.4） |
| 投稿 | 邮箱与仓库均无 DIMVA/ICICS 投稿记录，按未投出处理。研究组合（`~/Projects/RESEARCH_PORTFOLIO_2026H2.md` §4.2）已把本项目定为 **AsiaCCS 2027 C2，截稿 12-11，C 档"必补实验"** |
| 仓库风险 | ~~origin/main 停在 2025-09-05；本地领先 2 个 commit + 174 项脏改动，仍未 push~~ **2026-10-16 已解决**：2 个 commit 已 push，脏改动分主题提交（`RESEARCH_LOG.md`）；10-13 的物理备份仍在 `/backup/git-bundles/2026-10-13/` |
| 体积 | `logs/` 是单个 27 GB 的 demo 运行日志（2026-01-29 至 04-28，内容是 webhook 连接拒绝刷屏），无实验价值。**2026-10-16 已删除**（含每日快照里的 4 个硬链接），compose 已加日志轮转 |

**北极星**：12-11 投出一篇"每个数字都能从论文追溯到脚本、JSON 与 commit"的 AsiaCCS 论文。11-20 设 Go/No-Go 门禁；过不了就不投，改为 arXiv 技术报告 + 开源 release，不浪费一次带名拒稿。

**三条硬约束**（来自研究组合的指导原则 ③ 与 §6 失效统计）：
1. 换渠道前必须先补实验，没有"直接投"的路线。
2. 测部署物（真正跑在 Wasm 沙箱里的模块、真正接了 eBPF 的 host），不测替身（sklearn/PyTorch 模型、Python n-gram）。
3. 凡是脚本里写着 `simulated` 的结果，要么变成真实测量，要么从论文里删除。弱/崩掉的 baseline（autoencoder F1 0.04）替换，不是删掉了事。

---

## 1. 上下文恢复（实查）

### 1.1 仓库、副本与备份

- **2026-10-16 起**实体目录为 `~/Engineering/WasmSentinel`（NVMe）；`/data/EngineeringFrozen/WasmSentinel` 现在是指向它的 symlink；HDD 旧副本改名为 `/data/EngineeringFrozen/WasmSentinel.hdd-ro-2026-10-16`，不再更新，确认无误后可删。旧状态：实体在 HDD，`~/Engineering/WasmSentinel` 为 symlink。`/data/ProjectsGit-2026-08-01/WasmSentinel` 是同一 HEAD 的旧快照，当前树是它的超集，可忽略。`SESSION_STATE.md` 与 `evaluation/benchmarks/wasm_benchmark.py` 里硬编码的 `/home/coder-gw/Projects/WasmSentinel` 已不存在。
- 远端 `origin/main = 42eb1cd`（2025-09-05）。本地 `main` 领先 2 个 commit（2026-02-01：DIMVA 论文与评估基础设施）。
- 脏改动 174 项：127 项是 `rules/suspicious-shell/target/` 的删除（构建产物曾被提交）、24 项 untracked（`host/internal/ebpf/`、`host/internal/bridge/`、`rules/ml-detector/`、`paper/`、`config/`、`demo-ui/`、`monitoring/grafana/`、`test-datasets/modern-attacks/` 等真正的源码）、23 项已跟踪文件修改。
- 备份：`/backup/git-bundles/2026-10-13/` 含 `WasmSentinel.bundle`、`-dotgit.tar.gz`、`-untracked.tar.gz`、`-uncommitted.patch`；`/backup/EngineeringFrozen-offdisk/current/WasmSentinel` 为 10-13/10-15 的整目录 rsync。物理盘不同，`IMPROVEMENT_PLAN.md` P0 的"至少 tar 一份"已满足。
- 被 git 跟踪的不该跟踪的东西：32 MB 二进制 `wasm-threat-detector`；`evaluation/datasets/raw/ADFA-LD` 以 gitlink（嵌套仓）形式入库；`evaluation/datasets/raw/LID-DS`（465 MB）是 LID-DS **框架代码仓**而非录制数据，未跟踪。
- `logs/wasm-threat-detector.log` 27 GB：docker-compose demo 从 1-29 跑到 4-28，日志里 8,267 次 webhook `connection refused`、4,149 次 "Threat detected"。不是任何论文表格的来源。**2026-10-16 已删除。**

### 1.2 代码现状：什么能跑、什么只是存在

**Go host（`host/`）**

| 组件 | 文件 | 状态 |
|---|---|---|
| 入口 | `cmd/main.go` (318) | 使用 `engine.NewSimpleEngine` + `collector.NewProcessCollector/NewNetworkCollector`（1 秒 `/proc` 轮询，`exec` 外部命令取进程表） |
| 简化引擎 | `internal/engine/simple_engine.go` (263) | **每个事件新建 Store + Instance**；事件字节写到线性内存固定偏移 1024，无 guest 侧 alloc 协议；无 fuel、无内存上限、无超时；WASI 继承 stdout/stderr；只取 `detect()` 返回的 i32 威胁等级 |
| 完整引擎 | `internal/engine/wasm_engine.go` (256) | 存在但 main 未使用 |
| eBPF 采集 | `internal/ebpf/ebpf_collector.go` (544) + `bpf/sentinel.bpf.c` (291) | 6 个 hook（execve、sched_exit、openat、tcp_connect、inet_csk_accept、raw sys_enter）。BPF C 用本机 clang 21 可编译通过（实测）。Go 侧缺 `bpf2go` 生成物，**不编译**，且 main 未接入 |
| 零拷贝桥 | `internal/bridge/zero_copy.go` (515) | 二进制事件缓冲区实现，只被 ebpf 包引用，main 未接入 |
| 指标 | `cmd/main.go:startMetricsServer` | `/metrics` 输出的是 `time.Now().Unix()`，**不是真实计数** |
| 测试 | — | 0 个 `_test.go` |
| 依赖 | `go.mod` | wasmtime-go v17、cilium/ebpf v0.12.3，均为 2023 年末版本 |

**Rust 规则（`rules/`）**

| 组件 | 状态 |
|---|---|
| `ml-detector/`（2.5K 行） | STIDE（6-gram）+ MLP + hybrid 调度；`cargo test --release` 17/17 通过（实测）。导出 `init/detect/detect_extended/train/get_stats/free_result` |
| 嵌入权重 `src/weights.rs` | **64→32→16→1，约 2.6K 参数**。论文描述的是 340 维输入、[128,64,32,16]（19,201 参数，`train/best_model_weights.json` 558 KB）。部署物与论文描述的模型不是同一个 |
| hybrid 的非 syscall 路径 | `detect_process` 是 `/tmp/`、`sh -c`、关键字匹配；`detect_network` 是端口表；`detect_file` 是敏感路径表。**只有 syscall 事件走 STIDE/MLP** |
| `rules/wasm/ml_detector.wasm` | 184 KB，2026-01-04 构建 |
| `suspicious-shell/` | 362 行示例规则；其 `target/` 已被本地删除，demo 需要重建 |
| `opa-policy/` | Rego 示例，与主流程无关 |

**本机工具链**：Go 1.26、Rust 1.97.1、clang 21、bpftool 7.7、内核 7.0.0 且 `/sys/kernel/btf/vmlinux` 存在、Docker 29.8、2× RTX 3090。**缺**：`wasm32-wasip1` target、`wasmtime` CLI、Python `wasmtime`、`bpf2go`、Falco/Tetragon 镜像。conda 环境 `fisherkd` 有 torch 2.5.1 + sklearn 1.7.2 可直接复用。

**CI（`.github/workflows/ci.yml`）**：一旦把 `host/internal/ebpf` 推上去，`go test ./...` 会因该包不编译而红；`actions-rs/*` 已停止维护；Docker Hub 推送依赖不存在的 secrets。

### 1.3 论文现状（`paper-dimva/`）

- 标题 *WasmSentinel: High-Performance Runtime Threat Detection with Sandboxed Machine Learning*，LNCS，19 页，29 条参考文献，无缺失 bib key。
- 同一指标多处矛盾：MLP F1 在摘要 0.87、引言 0.84、表 1 0.840±0.005、结论 0.87；MLP 延迟 90 µs（摘要）/ 45 µs（引言）/ 0.2 µs（表 1）。
- 悬空引用 2 处：`app:implementation`、`fig:threshold-analysis`（`main.log` 实证）。
- `paper/`（CCS 草稿，acmart，12 页，2026-01-04）是现成的 ACM 模板底稿，内容基于更早的 F1 0.72 结果。

### 1.4 证据链审计（论文主张 → 实际来源 → 状态）

| # | 论文主张 | 实际来源 | 状态 |
|---|---|---|---|
| 1 | MLP F1 0.840±0.005，延迟 0.2 µs，"5-fold CV 多次试验，p 值" | `evaluation/scripts/ml_baseline_comparison.py` 的 **PyTorch MLP**（GPU 批量推理时间摊到每样本）；`ml_comparison_results_v2.json` 每个模型只有 **2 个取值**；工作区版本把 MLP 训 20 epoch、LSTM/Transformer/GNN 只训 10 epoch | ⚠️ 测的不是 Wasm 部署物；baseline 训练预算不公平；统计量不成立 |
| 2 | N-gram recall 0.86 / F1 0.53；延迟中位 33 µs、P99 290 µs | `run_real_experiments.py` 的 **Python** 6-gram 实现，`real_experiments_20260201_123408.json` | ✅ 真实数据，但不是 Wasm 模块 |
| 3 | （论文未用）Wasm 模型 F1 0.72 | `rules/ml-detector/train/results/EXPERIMENT_REPORT.md`，NumPy 训练；5-fold CV 实为 F1 0.61 | ✅ 真实，且这才是接近部署物的数 |
| 4 | Falco 逻辑延迟 120 µs、E2E 8 ms、120 MB，"两系统实现了等价规则" | `evaluation/results/20251231_231729/comparison_report.md` 标注 **source = literature**；`falco_comparison.py` 内存采样报错 `No memory samples collected` | ❌ 无测量 |
| 5 | nginx 开销 <1%（74,908 vs 77,087 req/s） | `real_workload_test.py:run_monitored_benchmark` 写死 `monitoring = 'simulated'`，监控臂就是再跑一遍 baseline；JSON 里的数（90,279 / 77,231）与论文也对不上 | ❌ 无监控对照 |
| 6 | 沙箱 5/5 逃逸被阻止 | `sandbox_isolation_test.py:simulate_test` 的 `simulated_results` 字典**硬编码**全部 blocked | ❌ 无执行 |
| 7 | 零拷贝比 JSON 快 5×（165→33 µs） | bridge 未接入 host；仓库里没有任何脚本产出 165 | ❌ 无来源 |
| 8 | fuel 10M 指令、256 MB 内存上限（评估节）/ 64 MB、100 ms 超时（实现节）、TOCTOU "formal guarantee" | `SimpleEngine` 没有任何限制；两节数字互相矛盾 | ❌ 未实现 |
| 9 | CVE-2024-21626 / 1086 检出 100% | `test-datasets/modern-attacks/` 是 bash/python 复现 syscall 序列的模拟脚本 | ⚠️ 需如实称作 syscall-pattern replay |
| 10 | 误报/漏报成因 38/31/21%、42/35/23% | 仓库内无任何脚本或数据产出这些比例；ADFA-LD 没有 apt/编译器类标注 | ❌ 疑为无来源 |
| 11 | "8,500 LOC"，"single binary with embedded eBPF bytecode" | 实测约 7.1K；二进制未嵌入 eBPF | ⚠️ |
| 12 | Autoencoder baseline F1 0.04 | 真实跑出，但模型崩了（precision 0.02） | ❌ 作为对照不可用（研究组合 §6 已将其列为拒稿型缺陷） |
| 13 | LID-DS 15 场景 F1 0.72（旧 SESSION_STATE） | `evaluate_lid_ds.py:simulate_lid_ds_evaluation` 硬编码 | ❌ 已正确地没进 DIMVA 稿，今后也不得复活 |

### 1.5 投稿状态与目标会议

- Gmail 检索 `DIMVA 2026`、`ICICS 2026`、`WasmSentinel after:2026/01/01`：没有任何投稿确认、审稿或决定邮件；仓库无 `*-submitted` tag 或 frozen PDF。**结论：DIMVA/ICICS 均未投出**（请用户确认）。
- 目标：**AsiaCCS 2027 Cycle 2**（CCF-C）。官方 CFP 实查（2026-10-16）：
  - 截稿 2026-12-11 AoE；早拒 2027-02-05；rebuttal 03-08 至 03-12；通知 03-31；camera-ready 05-07。
  - ACM sigconf 双栏，**正文 ≤12 页**，参考文献与标注清楚的附录另加 ≤10 页；双盲；作者名单提交后不可增减。
  - **必须**有 ≤半页的 *Open Science* 附录（可为匿名 artifact 链接，审稿期间须可访问）；无正式 artifact evaluation。
  - 需选一个 track；"用 ML 解决安全问题"归领域 track（Software Security 或 Web and Network Security），不归 AI Security。
  - Cycle 1 被拒稿件不得投 Cycle 2（本项目未投 C1，无此限制）。
- 研究组合对本项目的三条"必补"：替换崩掉的 autoencoder baseline；用 PR 曲线把 Recall 66% 变成选定工作点；加标准 HIDS baseline。本计划把这三条扩成 §3 的 E1。

---

## 2. 目标、定位与决策点

### 2.1 论文定位调整（建议）

现稿的卖点是"沙箱里的 MLP 在 ADFA-LD 上打败 LSTM/Transformer/GNN"。这条线有三个致命弱点：数字来自 PyTorch 而非 Wasm；DL baseline 训练预算被压缩；ADFA-LD 本身年代久、上限低。继续沿这条线补实验，最好的结果也只是"在一个 2013 年的数据集上，一个 MLP 和 Transformer 差不多"。

建议把主张换成**系统论文**的三条，ML 只作为负载而不是命门：

- **C1 可行性与代价**：把 HIDS 检测逻辑（n-gram + MLP）放进 Wasm 沙箱，在真实 eBPF 事件流下的端到端延迟、吞吐与资源开销，与"同一逻辑原生 Go 实现"及 Falco/Tetragon 相比处在什么量级。零拷贝通道 vs JSON 通道是其中一个消融。
- **C2 隔离性可实证**：恶意规则（读文件、连网、死循环、内存炸、spawn、越界）在 host 里加载后的真实行为日志，以及 fuel/内存上限的开销。
- **C3 检测等价性**：同一模型在 NumPy、原生 Rust、Wasm 三路推理数值一致；准确率用 PR 曲线 + 明示的工作点报告，对照是经典 HIDS（STIDE）、一个正常的无监督方法与训满的监督 baseline。不再声称"优于 DL"。

"first system to run ML inference inside a Wasm sandbox for threat detection"这类首创声明在定稿前必须过一次 prior-art 检索（至少核对 wasm-bpf / eunomia-bpf、WasmEdge WASI-NN、Envoy/Proxy-Wasm 过滤器、Falco 插件框架），否则删掉。

### 2.2 决策点

| 日期 | 决策 | 判据 |
|---|---|---|
| **10-19** → **2026-10-25 已定：Track A** | 走 Track A（AsiaCCS 全量）还是 Track B（只做工程收尾 + arXiv 报告） | Phase 0 完成；用户确认可投入 ≥25 人日 |
| **11-20** | Go / No-Go | E1、E3、E4、E6 有真实 JSON；`/claim-verify` 对初稿全部可追溯；无任何 `simulated` 残留 |
| **12-09** | 投 / 不投 | `/submission-preflight AsiaCCS` 返回 PASS 或 CONDITIONAL PASS |

---

## 3. 工作分解

每个阶段写明**产出**与**验收**。编号用于后续 `RESEARCH_LOG.md` 与 commit message 引用。

### Phase 0 止血与地基（10-16 至 10-19，约 2 人日）— **2026-10-16 全部完成**，逐项结果与证据见 `RESEARCH_LOG.md`

| 编号 | 任务 | 验收 |
|---|---|---|
| P0.1 ✅ | 把实体目录拉回 SSD（如 `~/Projects/WasmSentinel`），symlink 反向指过去；`/data` 上的副本只读 | `IMPROVEMENT_PLAN.md`"不要在 /data 上开发"的约束满足 |
| P0.2 ✅ | 先 push 现有 2 个 commit 到 `origin/main`；把 untracked 源码（ebpf、bridge、ml-detector、paper、config、monitoring、modern-attacks）分主题提交；`target/`、`logs/`、32 MB 二进制、`datasets/raw/` 不提交 | `git status` 干净；`git log origin/main..HEAD` 为空 |
| P0.3 ✅ | `.gitignore` 增加 `wasm-threat-detector`、`evaluation/datasets/raw/`、`*.wasm`（产物改由 release 分发）；`git rm --cached` 二进制；ADFA-LD gitlink 改为 `scripts/fetch_datasets.sh` | 仓库 pack 不再增长；新人 clone 后 `fetch_datasets.sh` 可取回数据 |
| P0.4 ✅ | 删除 27 GB `logs/wasm-threat-detector.log`（**先征得用户确认**）；`docker-compose*.yml` 加日志轮转 | `du -sh logs` < 10 MB |
| P0.5 ✅ | 工具链：`rustup target add wasm32-wasip1`；`go install github.com/cilium/ebpf/cmd/bpf2go@latest`；`conda create -n wasmsentinel --clone fisherkd && pip install wasmtime`；安装 wasmtime CLI；`docker pull falcosecurity/falco:latest cilium/tetragon` | `cargo build --target wasm32-wasip1 --release` 产出新 wasm；`python -c "import wasmtime"` 通过 |
| P0.6 ✅ | 修 CI：eBPF 包加 `//go:build linux && ebpf` 或在 CI 里 `go generate`；`actions-rs` 换 `dtolnay/rust-toolchain`；删除 Docker Hub 推送与 codecov（或 `continue-on-error`）；加 `cargo test` for `ml-detector` | CI 全绿 |
| P0.7 ✅ | 归档过期文档到 `docs/history/`：`CCS2026_ROADMAP.md`、`RESEARCH.md`、`SESSION_STATE.md`、`README_backup.md`、`paper/EVALUATION_GAP_ANALYSIS.md`；新建 `RESEARCH_LOG.md` | 根目录只剩 README、本计划、IMPROVEMENT_PLAN、CONTRIBUTING、DEPLOYMENT、QUICKSTART、DEMO、TEST_REPORT |

### Phase 1 让系统成为论文描述的系统（10-20 至 11-02，约 9 人日）— **2026-10-18 提前完成**，逐项见 `RESEARCH_LOG.md`

| 编号 | 任务 | 验收 |
|---|---|---|
| P1.1 ✅ 2026-10-17（vmlinux.h 未重生成，CO-RE 在 7.0 上已验证） | 接入 eBPF 采集器：`main.go` 增 `--collector=ebpf|proc`；重生成 `vmlinux.h`；升级 cilium/ebpf 到当前版本；6 个 hook 在 7.0 内核上逐个验证 | `sudo ./wasm-threat-detector --collector=ebpf` 能看到 execve/openat/connect 事件 |
| P1.2 ✅ 2026-10-17（wasmtime-go 升级顺延，见 `RESEARCH_LOG.md`） | Wasm 引擎重写（可基于 `wasm_engine.go`）：每规则一个长寿 Store/Instance（或池）；guest 导出 `alloc/free`；`StoreLimits` 内存上限、fuel 预算、epoch 超时；WASI 零能力（不继承 stdout/stderr）；升级 wasmtime-go | 引擎单测覆盖：正常检测、超 fuel、超内存、trap 隔离不影响其他规则 |
| P1.3 ✅ 2026-10-18（实测端到端 2.1×，非 5×；ml_detector 侧待 P1.4） | 零拷贝通道接入：`bridge` 的二进制事件直写 guest 线性内存；保留 JSON 路径并用 flag 切换（这就是消融的两臂） | 两条路径对同一事件给出相同检测结果 |
| P1.4 ✅ 2026-10-18（1,400 条输入 max diff 2e-6；发现旧模块从未用训练权重） | ml-detector：用 `embed_weights.py` 真正嵌入训练得到的模型（统一为一个版本，论文与代码一致）；`detect_extended` 返回分数；增加 Wasm 与 NumPy 推理一致性测试 | 1,000 条输入上 max abs diff < 1e-5 |
| P1.5 ✅ 2026-10-18 | 真实 Prometheus 指标（`prometheus/client_golang`）；修 `wasm_benchmark.py` 等脚本里的绝对路径 | `/metrics` 的 `threats_total` 随告警递增 |
| P1.6 ✅ 2026-10-18 | Go 测试：engine、bridge、collector 单测 + 一个端到端测试（回放 ADFA-LD 轨迹 → 告警） | `go test -race ./...` 通过；CI 跑 |
| P1.7 ✅ 2026-10-18（WasmSentinel / `wasmsentinel` / `github.com/GeoffreyWang1117/WasmSentinel/host`） | 名称统一：模块路径 `github.com/wasm-threat-detector/host`、二进制 `wasm-threat-detector` 与项目名 WasmSentinel 三者择一 | README/脚本/compose 一致 |

### Phase 2 实验重做（11-03 至 11-20，约 11 人日）

通用要求：每个实验一个脚本、一个输出 JSON（带 git commit、内核、硬件、时间戳）、一个画图脚本；`make reproduce` 一键重跑；论文里的每个数字能 `grep` 到 JSON。结果放 `evaluation/results/2026-11/`。

| 编号 | 实验 | 设计要点 | 不可砍 |
|---|---|---|---|
| E1 ✅ 2026-10-25（重跑含模块内 RF 臂：Wasm 森林 0.897 = sklearn 森林，MLP 0.730 AUPRC，`make e1`） | 检测准确率（ADFA-LD） | 推理跑在 **Wasm 模块**上（Python wasmtime 或 host 回放模式）。5-fold × 3 seeds，报 **PR 曲线 + AUPRC**，明示工作点（如 FPR ≤ 5% 下的 recall）。baseline：STIDE/n-gram、Isolation Forest 或 one-class SVM（替换崩掉的 autoencoder；若保留 AE，必须只用 normal 训练并在验证集选阈值）、Random Forest、训满并早停的 LSTM。配对检验按 fold 做，报 CI。 | ✅ |
| E2 ✅ 2026-10-25（重跑含森林：MLP 三路 max diff 1.9e-6、森林 3.0e-8，引擎 2.1 µs，`make e2`） | Wasm vs native 一致性与单次推理开销 | 同一模型 NumPy / 原生 Rust / Wasm 三路输出一致；Wasm 内推理延迟与 host 调用开销分开报；吞吐 | ✅ |
| E3 ✅ 2026-10-25（重跑含森林臂：可持续 MLP 18.3K/15.1K、森林 21.4K/17.0K eps，`make e3`） | 端到端延迟与吞吐 | eBPF 事件 → 告警；JSON 臂 vs 零拷贝臂；1K / 10K / 50K events/s；P50/P99/P999 | ✅ |
| E4 ✅ 2026-10-26 重跑（默认森林：nginx −4.4% / Falco −9.2% / Tetragon −17.5%，`make e4`；机器有 vLLM 与其他容器） | 系统开销（真实监控臂） | nginx(wrk) / redis(redis-benchmark) / postgres(pgbench) × {无监控, WasmSentinel, Falco, Tetragon}，每格 ≥5 次；报吞吐 Δ、CPU%、RSS 与 CI。`real_workload_test.py` 的 `simulated` 分支删除 | ✅（Tetragon 列可砍）|
| E5 ✅ 2026-10-26 重跑（默认森林：三系统 3×20/20，延迟 0.7–2.9 ms，`make e5`） | Falco/Tetragon 公平对比 | 同一规则集（读 `/etc/shadow`、`/tmp` 可执行、反弹 shell 序列）在三系统实现；真实检出、延迟、内存采样 | ⚠️ 可缩到只对 Falco |
| E6 ✅ 2026-10-18（11/11，`make isolation`） | 沙箱隔离 | 真实编译 7 个恶意 Wasm 模块（读文件、连网、死循环、内存炸、spawn、越界访问、读 host 内存），在 host 里加载，记录 trap/fuel/limit 日志；写成 CI 测试长期存在。`sandbox_isolation_test.py` 的硬编码字典删除 | ✅ |
| E7 | 现代攻击 | 现有模拟脚本如实称为 syscall-pattern replay；若时间允许在容器里跑真实 PoC | 可砍 |
| E8 | 第二数据集 | LID-DS 2021 真实录制或 CB-DS；做不到就在 Limitations 写明单数据集 | 可砍 |

砍的顺序：E7 → E8 → E5 的 Tetragon → E4 的 Tetragon → E3 的 50K 负载点。E1、E2、E3（至少两臂）、E4（至少 nginx + Falco）、E6 不可砍。

### Phase 3 论文重写（11-14 起与 Phase 2 并行，12-09 定稿，约 9 人日）

| 编号 | 任务 |
|---|---|
| W1 | 新建 `paper-asiaccs/`（✅ 10-25 骨架 + Evaluation/Related Work 初稿；参考文献逐条核 DOI——10-25 已清掉 5 条编造或无据的条目），以 `paper/`（acmart）为模板底稿，`\documentclass[sigconf,anonymous,review]{acmart}`；12 页正文预算：Intro 1.5、Background+Threat 1.5、Design 3、Impl 0.75、Eval 4、Related+Discussion 1、Conclusion 0.25 |
| W2 | 按 §2.1 重写贡献与摘要；威胁模型保留 A_ext / A_loc / A_rule 三级，去掉 "formal guarantee" 措辞；TOCTOU 段落只有在 P1.3 实现并有测试时才保留 （✅ 10-31 贡献段按三条主张重写，以默认森林为准，E3 同时给 MLP / 森林两个饱和点，Cost 项写入 CPU 163% 与 pgbench 下丢 45%；摘要只改「application cost」一处措辞，整体留到 W6 门禁前再过；威胁模型 10-25 的新稿已无 "formal guarantee" 与 TOCTOU 段，三级攻击者改为 Trusted / Untrusted / 必须保证 / 范围外四段，不再改；见 `RESEARCH_LOG.md` 2026-10-31） |
| W3 | Evaluation 按 E1 至 E6 重排；删除所有 `simulated` 来源的表格、误报成因百分比、文献数字充当测量的行；Limitations 写明：ADFA-LD 年代、单数据集、模拟 CVE、未做 mimicry/对抗实验（10-31 用户拍板追加：E3 正文与图改以森林行为主叙事、MLP 降为对照行；随后引言、摘要、结论、讨论里的 E3 头条数字只引森林的宏，`\eThreeAchievedBinFiftyKRf` 等）（✅ 10-31 完成：E3 森林为主叙事、表格森林行在前、图改画森林臂，引言 / 摘要 / 结论 / 讨论只引森林宏；Limitations 补「未做 mimicry / 对抗评估、E5 为手写触发而非攻击语料、pgbench 下守护进程饱和丢事件」；全文 grep 无 simulated / literature / 误报成因百分比 / CVE 主张；小节顺序保留按问题排列 E2→E3→E4→E5→E6→E1（Questions 段给出 Q1–Q4 到实验的映射），未改成数字序；见 `RESEARCH_LOG.md` 2026-10-31） |
| W4 | Open Science 附录：anonymous.4open.science 仓（代码、结果 JSON、`make reproduce`、预构建 wasm）；投稿前验证链接可匿名访问 |
| W5 | Related work 补 prior-art（见 §2.1 末段），用 `/scout` 与 `/ref-check` |
| W6 | 门禁顺序：`/paper-audit`（悬空引用）→ `/claim-verify`（数字 ↔ JSON）→ `/self-review` → `/nonexpert-review` → `/final-reviewer` → `/submission-preflight AsiaCCS`；每次通过记入 `RESEARCH_LOG.md` |
| W7 | 投出当天：git tag `asiaccs2027-c2-submitted`，归档 `archive/asiaccs2027-c2-submitted.pdf` 与 supplementary zip（`/supplement-pack`） |

### Phase 4 开源与工程收尾（12-12 起，不阻塞投稿）

- README 重写：先回答"防谁、能力边界在哪"（`IMPROVEMENT_PLAN.md` P3），再讲架构；删掉不存在的 Kubernetes 清单、SIEM 集成、"v1.1 路线图"；徽章只保留 CI 真能产生的。
- `DEMO.md` / `TEST_REPORT.md` / `DEPLOYMENT.md` / `QUICKSTART.md` 按新二进制与新 flag 重写；`demo-website/` 与 `demo-ui/` 二选一。
- Release v0.2.0：Linux amd64 二进制 + 预构建 wasm + `SHA256SUMS`；Docker 镜像由 CI 构建（若能）。
- 后续研究方向（AsiaCCS 之后再议）：mimicry/对抗鲁棒性；多租户规则并发隔离与资源记账；Wasm component model / WASI-NN 作为推理后端；规则热更新与签名验证（供应链）。

---

## 4. 时间线

| 周 | 日期 | 里程碑 |
|---|---|---|
| W0 | 10-16 至 10-19 | Phase 0 全部完成；**10-19 决策点**（Track A / B） |
| W1 | 10-20 至 10-26 | P1.1 eBPF 接入可见事件；P1.2 引擎重写合入 |
| W2 | 10-27 至 11-02 | P1.3 零拷贝两臂可切换；P1.4 模型统一；P1.6 测试与 CI 绿 |
| W3 | 11-03 至 11-09 | E1、E2 出 JSON 与图；E6 恶意模块全部编译并入 CI |
| W4 | 11-10 至 11-16 | E3、E4 出数；W1 模板与骨架；W2 贡献定稿 |
| W5 | 11-17 至 11-23 | E5；**11-20 Go/No-Go**；W3 Evaluation 初稿 |
| W6 | 11-24 至 11-30 | 全文初稿；`/paper-audit` + `/claim-verify` 过 |
| W7 | 12-01 至 12-07 | `/self-review` → `/nonexpert-review` → `/final-reviewer`；按意见修 |
| W8 | 12-08 至 12-11 | W4 匿名仓、`/submission-preflight`；**12-09 投/不投**；12-11 AoE 截稿 |

人时合计约 31 人日，落在 56 个日历日内，要求平均每周 ≥4 个工作日投入。研究组合 §4.2 指出当前真正的约束是人力而非算力；若无法保证，10-19 应选 Track B。

**Track B 最小集合**（约 6 人日）：Phase 0 全部 + P1.2 引擎限额 + E6 真实沙箱测试 + README 重写 + arXiv 技术报告（把 §1.4 的 ❌ 项全部删掉后如实报告 F1 0.72 / 0.61 的结果）。

---

## 5. 风险与应对

| 风险 | 概率 | 应对 |
|---|---|---|
| cilium/ebpf v0.12.3 / wasmtime-go v17 与 Go 1.26、内核 7.0 不兼容 | 高 | P0.5 直接升级到当前版本并接受 API 迁移成本；`vmlinux.h` 本机重生成 |
| 7.0 内核上 kprobe `tcp_connect` / `inet_csk_accept` 签名变化 | 中 | 改用 `fentry/fexit` 或 tracepoint `sock:inet_sock_set_state` |
| Falco 需 modern-bpf 驱动、Tetragon 需 privileged，本机环境折腾超时 | 中 | 先只对 Falco（`falco:latest` 默认 modern eBPF）；Tetragon 列可砍 |
| ADFA-LD 上 Wasm 模型 F1 到不了 0.84 | 高 | 按 §2.1 定位，报 PR 曲线与工作点，不追数字；论文不以 F1 排名为主张 |
| 人力被申请季占满 | 高 | 10-19 决策点；Track B 预案；砍实验顺序已定 |
| 匿名仓泄露身份（路径、作者名、邮箱） | 中 | `/supplement-pack` 的身份扫描；注意 `evaluation/results/real_workload/*.json` 内含主机名与路径 |
| 投稿后被指自我重复 | 低 | 本项目此前未投出，无此风险；仍用 `/overlap-check` 对 TinyInfer-WASM 等兄弟项目扫一遍 |

---

## 6. 明确不做的事

- 不在 `/data` HDD 上继续开发（先完成 P0.1）。
- 不复活 LID-DS 模拟结果、不保留任何 `simulated` 分支作为论文证据。
- 不做 Kubernetes、SIEM、规则市场、Web 管理界面（README 旧路线图全部作废）。
- 不在 ADFA-LD 之外再训练新模型族去"打败 Transformer"。
- 不在 prior-art 检索前使用 "first" / "novel" 作为主张。
- 不删除 `paper-dimva/`：它是历史稿，归档即可；新稿在 `paper-asiaccs/`。

---

## 附录 A 常用命令

```bash
# 构建
cd host && go build -o ../wasm-threat-detector ./cmd/main.go
cd rules/ml-detector && cargo build --target wasm32-wasip1 --release
cd host/internal/ebpf && make            # 生成 bpf2go 绑定（P0.5 之后）

# 测试
cd host && go test -race ./...
cd rules/ml-detector && cargo test --release

# 运行（P1.1 之后）
sudo ./wasm-threat-detector --collector=ebpf --rules rules/wasm --metrics-port 8080

# 实验（Phase 2 之后）
conda activate wasmsentinel && make reproduce      # 产出 evaluation/results/2026-11/

# 论文
cd paper-asiaccs && latexmk -pdf main.tex
```

## 附录 B 文件地图与处置

| 路径 | 性质 | 处置 |
|---|---|---|
| `IMPROVEMENT_PLAN.md` | 2026-10-13 卫生方案 | 保留，P0 状态在本文件 §1.1 更新 |
| `CCS2026_ROADMAP.md`、`RESEARCH.md`、`SESSION_STATE.md`、`README_backup.md` | 过期 | 移至 `docs/history/` |
| `paper/` | CCS 草稿（acmart） | 作为 `paper-asiaccs/` 模板底稿 |
| `paper-dimva/` | DIMVA 稿（LNCS，含 ❌ 主张） | 归档，不再编辑 |
| `evaluation/results/20251231_*`、`adfa_ld_*` | 12 月早期结果 | 保留作历史，论文不引用 |
| `evaluation/results/real_experiments/` | Python n-gram 真实结果 | 保留；被 E1/E2 的 Wasm 结果取代 |
| `evaluation/results/overhead/`、`real_workload/` | 混有 literature/simulated | 保留目录，论文只引用 2026-11 新结果 |
| `evaluation/scripts/sandbox_isolation_test.py`（已于 2026-10-18 删除，由 E6 取代）、`evaluate_lid_ds.py` 的模拟分支 | 伪证据 | 删除分支，脚本改为真实执行或移除 |
| `ml_comparison_results_v2.json`（根目录） | 2 折结果 | 移入 `evaluation/results/2026-02/` 并标注 |
| `logs/wasm-threat-detector.log` | 27 GB 运行日志 | 确认后删除 |
| `wasm-threat-detector`（二进制） | 32 MB 产物 | 取消跟踪，改 release 分发 |
| `texput.log` | 编译残留 | 删除 |

## 附录 C 本次核查的证据路径

- 仓库：`git status --short`、`git log --format='%h %ad %s' --date=short`、`git ls-remote --heads origin`、`/backup/git-bundles/2026-10-13/`
- 构建：`cd host && go build ./...`（失败于 `internal/ebpf`）、`go build ./cmd/main.go`（成功）、`cargo test --release`（17/17）、`clang -target bpf -c sentinel.bpf.c`（成功）
- 引擎行为：`host/internal/engine/simple_engine.go:132-223`；指标：`host/cmd/main.go:startMetricsServer`
- 模型不一致：`rules/ml-detector/src/weights.rs:7-10,437-438,554-555,569-570`；`rules/ml-detector/src/mlp.rs:26-27`；`paper-dimva/sections/appendix.tex`
- 模拟证据：`evaluation/scripts/real_workload_test.py:489-505`；`evaluation/scripts/sandbox_isolation_test.py:216-299`；`evaluation/scripts/evaluate_lid_ds.py:214-266`
- 文献数字：`evaluation/results/20251231_231729/comparison_report.md:15`；`evaluation/results/overhead/falco_comparison_results.json`
- 训练预算：`git diff -- evaluation/scripts/ml_baseline_comparison.py`
- 论文矛盾与悬空引用：`paper-dimva/main.tex`（摘要）、`sections/introduction.tex`、`sections/evaluation.tex:30-40`、`sections/conclusion.tex`、`paper-dimva/main.log`
- 投稿状态：Gmail 检索 `DIMVA 2026` / `ICICS 2026` / `WasmSentinel after:2026/01/01` 无命中
- 目标会议：`~/Projects/RESEARCH_PORTFOLIO_2026H2.md:236,462,484,577`；AsiaCCS 2027 官方 CFP（asiaccs2027.cityu.edu.mo/call-for-papers）
