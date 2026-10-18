# WasmSentinel 研究日志

按日期倒序。每条写清：做了什么、证据在哪、下一步。任务编号对应 `DEVELOPMENT_PLAN.md` §3。

## 2026-10-18 · E6 沙箱隔离实验（完成，替换硬编码的 "5/5 blocked"）

**做了什么**

- `rules/adversarial/`：10 个故意越界的规则模块（Rust → wasm32-wasip1，共 348 KB）：读 /etc/passwd、列 /、写 /tmp；枚举环境变量与 argv；TCP 连接；8 MiB 刷 stdout/stderr；读时钟（允许的能力，作对照）；16 MiB 步长撑内存直到被拒；一次申请 1 GiB；死循环；`proc_exit(3)`；无界递归。
- `host/internal/engine/adversarial_test.go`：在默认限额（64 MiB / 5×10⁷ fuel / 100 ms）下逐个加载、调用、记录结果、确认邻居规则不受影响、确认下一次调用引擎已恢复；`WASMSENTINEL_RESULTS_DIR` 设置时写出 `isolation.json` 与 `isolation.md`。
- 根目录 `Makefile`：`make isolation` / `make parity` / `make reproduce` → `evaluation/results/2026-11/`（附 README 说明每个文件的生成命令）。CI 新增 `isolation` job，在 ubuntu-latest 上重跑并把表格贴进 job summary。
- 删除 `evaluation/scripts/sandbox_isolation_test.py`（整个脚本是 `simulate_test` 的硬编码字典）。

**结果（本机，commit 见 git log）**：11/11 包含。

| 模块 | 结果 | 耗时 |
|---|---|---|
| fs_read / env_leak / net_connect / stdout_flood | 全部返回 0：读不到、看不到、连不上、刷不出去 | ≤ 1.6 ms |
| clock | 返回 1：时钟是允许的能力（论文里要写明白） | 0.01 ms |
| mem_bomb_graceful | 到 32 MiB 时 `try_reserve` 失败停下（Vec 翻倍 + 拷贝需要 80 MiB 瞬时），实例内存 49.1 MiB < 64 MiB | 20 ms |
| mem_bomb_abort | 1 GiB 请求被 limiter 直接拒绝 → 分配器 abort → trap；实例重建 | 0.06 ms |
| cpu_spin（fuel） | `fuel` trap | 3.5 ms |
| cpu_spin（仅超时） | `timeout` trap | 104 ms |
| proc_exit | `exit` trap | 0.03 ms |
| stack_overflow | trap | 2 ms |

**一个诚实的标注**：一次性申请 1 GiB 时线性内存根本没有增长（grow 被整体拒绝），引擎无法把这个 abort 和普通 `unreachable` 区分开，只能标为通用 `trap`；"被拒绝、实例重建、邻居无感"三条都成立，但论文表格里这一行的类别要写 trap 而不是 memory。wasmtime-go 的静态 limiter 没有回调，要精确归类需要换成带回调的 limiter（升级到 v49 后看 API）。

## 2026-10-18 · P1.7 命名统一（完成）

三个名字收敛为一个：项目 **WasmSentinel**，二进制 / 容器 / 镜像 / compose 服务 **`wasmsentinel`**，Go 模块 **`github.com/GeoffreyWang1117/WasmSentinel/host`**（与仓库地址一致）。

- 57 个文件、248 处替换（脚本化，按"先具体后一般"的顺序：模块路径 → GitHub URL → 旧指标名 `wasm_threat_detector_total_threats` / `_threats_by_severity` → `wasmsentinel_threats_total` → `WASM-ThreatDetector` → `wasm-threat-detector` → `wasm-sentinel`）。`docs/history/`、`paper*/`、`evaluation/results/`、三份计划/日志文件保留历史写法。
- 路径随之变化：配置 `/etc/wasmsentinel/config.yaml`、日志 `/var/log/wasmsentinel.log`、用户配置 `~/.wasmsentinel.yaml`、Grafana 面板文件 `wasmsentinel.json`、compose 网络 `wasmsentinel-*`。`CONTRIBUTING.md` 里不存在的 `security@…org` 邮箱改为 GitHub Security Advisories。
- 验收：`go build/vet/test -race` 全绿；`./wasmsentinel --collector=replay` 冒烟正常；四个 compose 文件 `docker compose config` 通过；CI / Pages workflow、config、Prometheus 配置、Grafana JSON 解析正常。

**Phase 1 至此全部完成**（P1.1–P1.7）。下一步是 10-19 决策点与 Phase 2 实验；Phase 2 开工前必须先解决"STIDE 正常库没人加载"（见 P1.4 / P1.6 观察）。

## 2026-10-18 · P1.6 测试与端到端回放（完成）

**做了什么**

- 事件循环从 `main.go` 搬进 `host/internal/pipeline`：`Run(ctx, Config)` 合并采集器通道、驱动引擎、交给输出链，返回 `Stats{Events, Alerts, DetectErrors, OutputErrors, Elapsed}`；采集器全部关闭或 ctx 取消时结束。合并队列改为**背压**（阻塞发送），不再在管道里静默丢事件；内核侧丢弃由 eBPF 采集器自己计数。
- `collector.ReplayCollector`（`--collector=replay`，`--replay-file` 文件或目录、`--replay-eps`、`--replay-loop`）：把 ADFA-LD 格式的 syscall 号轨迹按 eBPF 事件形状回放（经 `EventFromEBPF`，含二进制载荷），每条轨迹一个 pid，播完关闭通道 → 进程自行退出并打印 Pipeline / Rule statistics。这就是 E3 吞吐实验的驱动器。
- 测试：`pipeline` 三个用例——50 个事件经两个采集器全部送达两条规则、指标计数一致；取消即停且 `Elapsed` 正确；**端到端**：真实模块 + `testdata/adfa_attack_hydra_ftp.txt`（306 个 syscall）在 `EncodingBinary` 下回放，两条规则各 306 次调用且全部走 `detect_raw`、0 错误、告警只来自 ml_detector。`collector` 四个回放用例（解析、顺序与 pid、节流与循环、坏路径）。
- 顺手修掉 `Run` 的 `Elapsed` 永远为 0（defer 改写的是值拷贝）。

**验收**：`go test -race ./...` 七个包全绿（collector / ebpf / engine / metrics / pipeline / wire），CI 跑同一套。CLI 冒烟：`--collector=replay --event-encoding=binary` 回放两条轨迹 611 个 syscall，自动退出，ml_detector 606 告警、suspicious_shell 0 告警，最大单次延迟 276 µs，fuel 总量 3.8×10⁸。

**观察**：STIDE 正常库为空时几乎每个 syscall 事件都升级到 MLP 深路径并报警（306 → 301）；这不是 bug，是 P1.4 已记录的"没人加载 STIDE 库"问题，E1 前必须给 `init` 配置或 `train` 一条真实加载路径，否则在线路径的告警量没有意义。

## 2026-10-18 · P1.5 真实 Prometheus 指标（完成）

**做了什么**

- 删除假的 `/metrics`（把 `time.Now().Unix()` 当计数器输出）和 `output.PrometheusOutputHandler` 桩；新建 `host/internal/metrics`（prometheus/client_golang v1.25.0，私有 registry）。
- 指标（namespace `wasmsentinel`）及来源：`threats_total{rule,severity}` 来自输出链；`events_total{type}`、`events_dropped_total`、`detect_latency_seconds` 来自事件循环；`rule_calls_total{rule,encoding}`、`rule_errors_total{rule,kind}`、`rule_fuel_total{rule}`、`rule_latency_seconds{rule}` 来自引擎新增的 `Observer` 钩子（每次规则调用一次回调，含 fuel 与错误类别）；`rule_memory_bytes`、`rule_reinstantiations_total`、`rule_positive_calls_total` 抓取时读引擎快照；`collector_records_total`、`collector_dropped_total`、`collector_events_total{type}` 读 eBPF 采集器快照；`build_info{collector,encoding,wasmtime}`；外加 Go 运行时与进程采集器（`process_resident_memory_bytes` 等，E4 的开销测量直接用）。
- `main.go` 接线：引擎 `SetObserver`、输出链加 metrics handler、eBPF 采集器注册、事件循环计时与丢弃计数；`/metrics` 走 `promhttp`，`/health` 保留。
- 顺带：评估脚本里的 `/home/coder-gw/...` 绝对路径改为相对仓库（`run_experiments.py`、`train_mlp.py`、`wasm_benchmark.py`、`evaluate_lid_ds.py`、`quick_test.sh`）；`go.mod` 随依赖升到 go 1.26。

**验收**：`metrics` 包单测抓取文本并断言 21 个序列。本机 proc 模式冒烟，两次抓取间隔 3 s：`events_total{type="process"}` 943 → 1,071，`threats_total` 各严重度同步递增（suspicious_shell critical 316 → 412，ml_detector low 14 → 26），`rule_memory_bytes` 1.18 MB / 1.38 MB，`rule_fuel_total` 累计 5.6×10⁷，RSS 81.5 MB，`/health` 200。

**观察**：proc 采集器启动时把现存进程全部当作新事件（3 s 内 943 个），suspicious_shell 对其中约 99% 报警（root + shell 名就够分），ml_detector 去掉未训练的 MLP 后只报 16 个。规则质量归 E1 / E7。

## 2026-10-18 · P1.4 模型与 ABI 统一（完成）

**发现（比改动本身更重要）**

- 部署的 ml_detector **从未使用训练权重**：`HybridDetector::with_config` 用 `MlpDetector::with_config(config.mlp)` 构造，权重是确定性公式的伪随机初始化；宿主从不调用 `load_mlp_weights`，`with_embedded_weights` 只在单测里出现。
- 即便用上权重也对不上：Rust 给 MLP 喂的是按 syscall **名**分类的另一套 64 维特征（`mlp::features::extract_syscall_features`），训练用的是按 syscall **号**计算的 `train_mlp.extract_features`（46 维有值）。进程事件还把进程特征塞进这个 syscall 模型。
- 嵌入的 weights.rs 是 64-32-16-1（6,785 参数）的 `mlp_weights.json`，论文描述的是 128-64-32-16（19,201 参数）的 `best_model_weights.json`。
- 结论：DIMVA 稿里任何"Wasm 内 MLP"的检测数字都不可能来自这个模块；§1.4 的 ❌ 有了机制层面的原因。

**做了什么**

- `features::adfa_features`：逐行移植 Python `extract_features`（Counter 的首现顺序、`most_common` 的稳定排序、全部按 f64 计算再转 f32）。类别集合混用 ABI 编号（0/1 是 x86_64，56/57 是 aarch64，ADFA-LD 是 i386），原样保留，换特征集是 E1 的评估问题。
- `weights.rs` 由 `embed_weights.py` 从 `best_model_weights.json` 重新生成：128-64-32-16，19,201 参数，`MODEL_SHA256` `1ee0c5d2…`，阈值 0.7（EXPERIMENT_REPORT 阈值分析）。`MlpDetector::with_embedded_weights` 的结构从 `HIDDEN_SIZES` 读取，不再写死。
- `hybrid.rs` 重写在 `EventFields` 上（JSON 与二进制同一套代码）：MLP 永远是嵌入模型，config 只能改阈值；syscall 路径按进程维护 syscall 号窗口（默认 100）喂 `adfa_features`；进程 / 网络 / 文件只走规则；处理 `process_exit` 释放状态；`max_processes`（默认 4096）按最近访问淘汰。
- 新导出 `mlp_score`、`mlp_features`、`model_info`（结构、参数量、阈值、来源、sha256）；`detect_extended` 继续返回 `anomaly_score`。
- `train/verify_wasm_parity.py`：用 wasmtime-py 加载模块，对 1,000 条合成序列 + 400 条 ADFA-LD 轨迹逐条比较 NumPy 参考与 Wasm 的特征与分数；`--write-golden` 生成 `train/fixtures/features_golden.json`（18 例），`tests/parity_golden.rs` 在 `cargo test` 里对照，CI 不需要 Python；CI 的 ml-detector job 另跑 1,000 条合成序列的 wasmtime 对照。
- 来源说明写在 `rules/ml-detector/MODEL.md`。

**验收**：1,400 条输入，特征最大绝对差 **0**（逐位一致），分数最大绝对差 **1.97×10⁻⁶** < 10⁻⁵（第 32 条，长度 100：0.371615 vs 0.371613）。Rust 21 个单测 + golden 测试通过；Go 全绿，JSON/二进制对等测试仍通过。hybrid 迁到 trait 后 ml_detector 二进制路径 4.4 µs（JSON 8.1 µs），P1.3 时是 18.9 µs。

**给 E1 的输入**

- 训练用整条轨迹（数百到数千 syscall），线上是 100 长窗口：训练/部署分布不一致，离线评估按整轨迹做，在线窗口是部署选择，论文要写明。
- STIDE 正常库目前没人加载（`train` 导出存在，宿主不调用）：空库让所有 n-gram 异常、全部走 MLP。E1 和部署都需要一条加载路径。
- STIDE 窗口是全局的，多进程交错会混；ADFA 回放是单轨迹顺序，不受影响。

## 2026-10-18 · P1.3 二进制事件通道（完成；含一个推翻预期的测量）

**做了什么**

- 定义二进制事件载荷（Go `host/internal/wire`，Rust `rules/sentinel-abi`）：16 B 头（magic `WSB1`、版本、记录长度、字符串区长度）+ 内核记录原样 592 B + 宿主解析好的字符串（user、group、syscall_name，NUL 结尾）。记录从 ring buffer 到 guest 线性内存只经过一次拷贝，不经过 Go 结构体编码或 JSON。
- `events.Event` 增加 `Binary []byte`（不序列化），eBPF 适配层每个事件构造一次；`ebpf.Event` 保留 `Raw` 记录并提供 `Record()` 逆向编码（测试与回放用）。
- 引擎：`--event-encoding=json|binary`；规则可选导出 `detect_raw(ptr,len)`；binary 模式下有二进制形式且规则导出 `detect_raw` 时走 raw，否则该规则回退 JSON（JSON 每事件最多序列化一次）；`InvokeRaw`、`RuleStats.CallsRaw`；缺导出时返回 `abi` 类错误且不丢实例。
- 两个规则 crate 都导出 `detect_raw`。sentinel-abi 提供 `to_value()`（从记录重建与 Go `EventFromEBPF` 相同的 JSON 结构）和 `EventFields` trait（`JsonEvent` / `RawEvent` 两个视图，直接按字段读取、不建树）。suspicious-shell 的三段检测逻辑改写到 trait 上；ml-detector 暂用 `to_value()`。
- 删除 `host/internal/bridge/zero_copy.go`（515 行，自定义格式，从未被引用）。
- CI 的 Rust matrix 加入 `rules/sentinel-abi`。

**验收**：`TestRawAndJSONPathsAgreeOnRealModules` 用 9 个覆盖全部事件类型的内核记录，对 suspicious_shell 与 ml_detector 各开两份实例（一份喂 JSON，一份喂二进制），逐条比较 level，全部相等且含正例；sentinel-abi 内 `raw_view_matches_json_view` 逐访问器比较两个视图；suspicious-shell crate 内 `raw_and_json_paths_agree`。`go test -race ./...` 全绿（collector / ebpf / engine / wire 四个包）。

**测量（本机单 goroutine，`-benchtime 2s`）**

| 基准 | JSON | binary | 备注 |
|---|---|---|---|
| suspicious_shell 单次调用，`to_value()` 重建 JSON 树的第一版 | 7.6 µs | **8.1 µs** | 更慢：建树的分配量与 serde_json 文本解析相当，"省掉解析"只是把成本搬了地方 |
| suspicious_shell 单次调用，改为 `EventFields` 直接读记录 | 7.8 µs | **4.2 µs** | −46%；剩余 4.2 µs 中约 2.2 µs 是引擎调用开销 |
| ml_detector 单次调用（仍用 `to_value()`） | 17.5 µs | 18.9 µs | 同第一行的原因；P1.4 把 hybrid.rs 迁到 trait 上 |
| 端到端：适配层转换 + `DetectThreat`（suspicious_shell） | 11.7 µs / 39 allocs / 2.5 KB | **5.6 µs / 26 allocs / 1.8 KB** | 2.1×，省掉 `json.Marshal` 与 guest 解析 |

**结论与对论文的影响**：论文草稿里"零拷贝 5×（165→33 µs）"没有来源，本次实测给出的是 **2.1×（端到端）**，且前提是规则按字段读记录；一旦规则在 guest 内重建通用 JSON 结构，收益归零。E3 应报告两臂的端到端数字与这个前提。命名上不再用"zero-copy"：ring buffer → guest 至少一次拷贝，文稿改称 binary direct-write / in-place record。

**遗留**：ml_detector 的 raw 路径仍建树（P1.4 一并迁移）；默认编码保持 `json`，E3 两臂对比后再定默认值。

## 2026-10-17 · P1.1 eBPF 采集器接入（完成）

**做了什么**

- `bpf/sentinel.bpf.c` 重写：事件结构按自然对齐排布（592 B，无 `packed`，C/Go 布局一致，Go 侧用 bpf2go `-type event` 直接生成）；exec 钩子从 `syscalls/sys_enter_execve` 换成 `sched/sched_process_exec`（exec 成功后触发，从 `mm->arg_start..arg_end` 读完整 argv，≤256 B，NUL 分隔）；exit 只记线程组 leader 并带退出码；网络字段用 CO-RE 读；raw `sys_enter` 允许列表扩到 20 个高风险 syscall（clone/fork/execve/kill/ptrace/setuid/setgid/pivot_root/prctl/chroot/mount/umount2/init_module/unshare/setns/finit_module/memfd_create/bpf/execveat/clone3）；ring buffer 256 KiB → 1 MiB。
- cilium/ebpf v0.12.3 → v0.22.0（go.mod `go 1.25.0`，Dockerfile 换 `golang:1.26-bookworm`）。
- `host/internal/ebpf` 重写：`--ebpf-hooks` 逐钩子挂载、原子计数、`Stop()` 不再持锁等 goroutine（旧实现会死锁）、解码走生成的 `sentinelEvent`；x86_64 syscall 名表（385 项）由 `/usr/include/x86_64-linux-gnu/asm/unistd_64.h` 生成。
- `collector.EBPFCollector` 适配层：内核事件 → `events.Event`，字段名与规则一致（`data.process.{executable,command_line,user,…}`、`data.file.{path,operation}`、`data.network.{dest_ip,dest_port,direction}`、`data.{syscall_nr,syscall_name}`）；exit 事件类型为 `process_exit`，规则不会把同一进程算两次；uid/gid → 用户名缓存。
- `main.go`：`--collector=proc|ebpf`（默认 proc，不需特权）、`--ebpf-hooks`；config 键同名。
- `rules/ml-detector/src/hybrid.rs`：syscall 事件改从 `data` 下读字段（兼容扁平记录）。
- 单测 10 个（无需 root）：记录大小 592、exec/截断 argv/网络/syscall 解码、钩子解析、允许列表都有名字；适配层对 exec/exit/file/network/syscall 的 JSON 形状。

**验收（7.0.0-34-generic，本机无免密 sudo，用 `docker run --privileged --pid=host -v /:/host … chroot /host` 以 root 身份运行主机二进制）**

| 运行 | 结果 |
|---|---|
| 全部 6 钩子，16 s，主机侧跑 `bash -c 'cat /etc/hostname; ls /tmp; id -un'`、`curl 127.0.0.1:1`、`rm -rf <不存在路径>` | 6 个钩子全部挂上；收到 30,670 条、丢 0：file_open 26,352 / syscall 2,917 / process_exit 815 / process_exec 515 / network_connect 71。exec 事件带完整 argv（`["bash","-c","cat /etc/hostname > /dev/null; …"]`）与解析后的路径 `/usr/bin/bash`；connect 带目标 `172.64.155.209:443`；syscall 命名为 `bpf`、`prctl` |
| 仅 connect,accept，9 s，`curl 127.0.0.1:22` ×3 | 13 connect + 3 accept（`sshd`，对端 `127.0.0.1:39626/39642/39644`） |
| 规则侧（第一轮） | 两条规则各 27,996 次调用，0 trap，最大延迟 220 µs / 444 µs；suspicious_shell 标记 4,182、ml_detector 3,168 |

**观察 / 限制**
- `openat` 占事件量 86%（空闲桌面约 1,650/s）；忙机器上用 `--ebpf-hooks=exec,exit,connect,accept,syscall` 去掉它，或在 P1.3/E3 做内核侧过滤。
- IPv6 连接只带 `family=10`，地址为空（事件结构没留 16 B 字段），后续需要时扩展结构。
- ml_detector 实例内存 1.18 → 1.31 MB（`process_states` 随 pid 增长，没有淘汰）——P1.4 处理。
- 关闭时 `dropped_after_cancel` 585：ctx 取消后到钩子卸载之间的事件，预期行为。
- `vmlinux.h` 未重生成：CO-RE 重定位在 7.0 内核上加载成功，现有头文件够用；需要时 `make -C host/internal/ebpf vmlinux`。
- 用 `--log-level trace` 可逐条打印内核事件（argv、目标地址、syscall 名），用于核对。

## 2026-10-17 · P1.2 引擎限额（完成；wasmtime-go 升级顺延）

**做了什么**（`host/internal/engine/`，替换 `simple_engine.go` 与 `wasm_engine.go`）

- 每条规则一个长寿 Store/Instance，跨事件复用；事件 JSON 写进 guest 用 `alloc` 导出的缓冲区（按需翻倍增长），不再写固定偏移 1024（那块地址落在 Rust 的 shadow stack 里）。
- Guest ABI v2：必须导出 `memory`、`alloc(i32)->i32`、`dealloc(i32,i32)`、`detect(i32,i32)->i32`，可选 `init(i32,i32)->i32`（实例化后以 (0,0) 调用一次）。两个 Rust crate 各加 10 行 alloc/dealloc；没有 alloc 的旧模块在加载时被拒绝，错误信息指明缺哪个导出。
- 三重限额，互相独立、可单独关闭：`Store.Limiter` 线性内存上限（默认 64 MiB；超限时 guest 内 `memory.grow` 失败，Rust 分配器 abort → 记为 `memory` trap）；fuel 指令预算（默认 5×10⁷/次）；epoch 墙钟超时（默认 100 ms，后台 ticker 周期 = timeout/10 夹在 1–10 ms）。
- Trap 处理：任何 trap（unreachable / fuel / 超时 / 内存 / `proc_exit`）都丢弃该规则的实例，下一次调用从已编译 Module 重建；其它规则各有自己的 Store，不受影响。
- WASI 零能力：`NewWasiConfig()` 不继承 stdio、无 env、无 args、无 preopen。
- 每规则统计 `Stats()`：calls / threats / errors / traps 分五类 / reinstantiations / fuel（last、total）/ latency（last、max、total）/ 当前内存；`main.go` 退出时逐规则打日志（P1.5 接 Prometheus 时直接用）。
- 新 flag 与 config 键：`--rule-memory-mb`、`--rule-fuel`、`--rule-timeout`。

**验收（`go test -race ./...` 全绿，14 个用例）**

| 用例 | 覆盖 |
|---|---|
| InvokeReturnsGuestLevel / DetectThreatMapsLevelsAndOrdersRules | 正常检测、level→severity 映射、规则按名字序执行 |
| FuelBudgetStopsRunawayRule | 死循环 guest 在 2×10⁶ fuel 处被切断，`TrapFuel`；邻居规则照常，再次调用自动重建 |
| EpochDeadlineStopsRunawayRule | fuel 关闭、30 ms 超时：在 ≥30 ms、≪2 s 内中断，`TrapTimeout` |
| MemoryCapIsEnforcedInsideTheGuest | 8 页上限下 guest 的 grow 循环恰好停在 8 页；初始 2 页的模块在 1 页上限下拒绝加载 |
| TrapIsIsolatedAndInstanceIsReplaced | `unreachable` 只影响本规则，Reinstantiations=1，后续调用正常 |
| WasiHasNoCapabilities | guest 看到 0 个环境变量、0 个参数；写 fd 1 不会出现在宿主 stdout |
| LoadRejectsModuleWithoutAllocator / LargeEventGrowsGuestBuffer / UnloadAndUnknownRule / ConcurrentInvocations / CloseIsIdempotent | ABI 校验、300 KiB 事件、卸载、8 goroutine 并发（-race）、Close 幂等 |
| RealSuspiciousShellRule / RealMLDetectorLoadsAndRuns | 真实模块：良性 `ls` 不报，`bash -c 'rm -rf …'` 报 critical；ml_detector 带 `init` 正常加载运行（模块未构建时 skip） |

测试桩是 7 个 WAT 文件（`testdata/`），用 `wasmtime.Wat2Wasm` 编译，CI 不需要 Rust 即可覆盖全部限额路径。

**数字（本机，单 goroutine）**

| 指标 | 值 | 来源 |
|---|---|---|
| 引擎每次调用开销（stub guest，256 B） | 2.2 µs，13 allocs | `BenchmarkInvokeEcho` |
| suspicious_shell 一次检测（含 JSON 解析） | 6.2 µs | `BenchmarkRealSuspiciousShell` |
| fuel / 事件 | suspicious_shell ≈ 6.3×10⁴，ml_detector ≈ 1.6×10⁵ | 6 s 冒烟运行的退出统计（各 1,096 次调用） |
| 单规则最大延迟（冒烟） | 134 µs / 496 µs | 同上 |
| 实例线性内存 | 1,179,648 B（Rust 1 MiB 栈 + 数据） | 同上 |

默认 fuel 5×10⁷ 对现有规则有 300–800 倍余量；真正的阈值在 E3 用 ADFA-LD 回放再定。

**顺延：wasmtime-go v17 → v49。** 本机此刻对 proxy.golang.org、goproxy.cn、GitHub codeload 的大文件下载只有 2–6 KB/s，v49 模块包 11 分钟只到 2.4 MB，已中止。v17 已具备 `SetFuel/GetFuel`、`Limiter`、`SetEpochDeadline`、`IncrementEpoch`、`Trap.Code`、`Error.ExitStatus` 全部所需 API，代码对 v49 只差 import 路径。网络恢复后：`go -C host get github.com/bytecodealliance/wasmtime-go/v49@v49.0.0`，改两处 import，`go mod tidy`，同时把 Dockerfile 的 `golang:1.21` 升到 v49 要求的版本。

**顺带观察**：/proc 采集器 + 关键词规则下，6 s 内 1,096 个事件被 suspicious_shell 全部标记（root + 常见 shell 名就能凑够分），ml_detector 对每个进程事件都给 level 2。检测质量属 P1.4 / E1 范畴，这里只记录。

## 2026-10-16 · Phase 0 止血与地基（全部完成）

**用户确认的决策**：DIMVA 2026 / ICICS 2026 均未投出；目标会议为 AsiaCCS 2027 Cycle 2（截稿 2026-12-11 AoE）；27 GB 日志可删。

| 编号 | 结果 | 证据 / 命令 |
|---|---|---|
| P0.1 | 实体目录迁至 `~/Engineering/WasmSentinel`（NVMe）；`/data/EngineeringFrozen/WasmSentinel` 改为 symlink；HDD 旧副本保留为 `/data/EngineeringFrozen/WasmSentinel.hdd-ro-2026-10-16`（不再更新） | `readlink -f /data/EngineeringFrozen/WasmSentinel` |
| P0.2 | push `a293001`、`83e8819` → `origin/main`；工作区按主题提交（见 `git log --oneline 83e8819..main`） | `git log origin/main..HEAD` 为空 |
| P0.3 | `.gitignore` 新增 `*.wasm`、`/wasm-threat-detector`、`evaluation/datasets/raw/`、`.claude/`，保留 `host/internal/ebpf/sentinel_bpfel.o`；取消跟踪 32 MB 二进制、`rules/suspicious-shell/target/`（127 文件）和两个没有 `.gitmodules` 的 gitlink；新增 `scripts/fetch_datasets.sh`（钉住 ADFA-LD `68bedf5`、LID-DS `587d158`） | `git ls-files | grep -c target/` → 0 |
| P0.4 | 删除 `logs/wasm-threat-detector.log`（27,156,108,061 B）及其在 `/data/EngineeringBackup/snapshots/daily/daily.2026-10-{14,15,16}_*/WasmSentinel/logs/` 的 4 个硬链接（不删硬链接空间不会释放）；4 个 compose 文件给检测器加 json-file 20 MB × 5 轮转；`config/config.yaml` 默认 `log-file: ""`（stdout）；showcase 仍写文件供 demo-ui 读取并已注释 | `df /data` used 5.2T → 5.1T |
| P0.5 | `rustup target add wasm32-wasip1`；conda env `wasmsentinel`（clone 自 `fisherkd`：torch 2.5.1+cu121、sklearn 1.7.2、wasmtime 49.0.0）；wasmtime CLI 49.0.3 → `~/.local/bin/wasmtime`（release tarball，sha256 已核）；`falcosecurity/falco:latest`、`quay.io/cilium/tetragon:v1.7.1` 已 pull；bpf2go 不单独安装，`go generate` 用 go.mod 钉住的 cilium/ebpf v0.12.3 | `conda run -n wasmsentinel python -c "import wasmtime"` |
| P0.6 | `host/internal/ebpf`：go:generate 加 `-D__TARGET_ARCH_x86 -target bpfel`（缺它 clang 报错），生成并提交 `sentinel_bpfel.{go,o}`；删未用 import；`go build ./...`、`go vet`、`gofmt`、`go test -race` 本地通过。两个 Rust crate `cargo fmt`、`cargo test --release`（ml-detector 17/17）、wasm32-wasip1 构建通过。CI 重写为 `go` / `wasm-rules`（matrix 两 crate）/ `ebpf`（重生成绑定并 diff）/ `release`（仅 tag）四个 job，换用 setup-go v5、dtolnay/rust-toolchain、upload-artifact v4、softprops/action-gh-release v2；删除 Docker Hub push、codecov、nancy、actions-rs | CI run 38963081060（c17f8d4）：go ✅、两个 wasm-rules ✅、ebpf ❌（runner 缺 `bpf/bpf_helpers.h`）→ 加 `libbpf-dev` 后 run 38963364381（aa7ae17）四个 job 全绿；Pages 部署 run 38963081351 ✅ |
| P0.7 | `CCS2026_ROADMAP.md`、`RESEARCH.md`、`SESSION_STATE.md`（→ `_2026-01-04`）、`README_backup.md`、`paper/EVALUATION_GAP_ANALYSIS.md` 移入 `docs/history/`（附 README 说明为何过期）；`ml_comparison_results_v2.json` 移入 `evaluation/results/2026-02/` 并标注为 smoke run；删 `texput.log` | 根目录 `ls *.md` |

**顺手修的**：README / README_cn / QUICKSTART / CONTRIBUTING / DEMO / `docs/development.md` / `test-datasets/evaluation/*.sh` 里的 `wasm32-wasi` → `wasm32-wasip1`（旧 target 名已被 Rust 移除）；`scripts/build.sh` 现在构建两个 crate 并把 `.wasm` 放进 `rules/wasm/`。

**注意事项**
- `rules/wasm/ml_detector.wasm` 不再入库。本地重建的模块（172,355 B，rustc 1.97.1）与 2026-01-04 的旧模块（184 KB）哈希不同；P1.4 统一模型版本时一并处理。
- `docker-compose.yml` 里的 fluentd 仍 tail `/var/log/wasm-threat-detector.log`，默认改 stdout 后它读不到内容；ELK 演示链路如要保留，改用 Docker fluentd 日志驱动（Phase 4）。
- clippy 未纳入 CI：ml-detector 有大量 warning，suspicious-shell 2 个；P1 重构时清理。
- 旧 HDD 副本与每日快照共享 inode（备份脚本用 `--link-dest`）：在 `.hdd-ro-2026-10-16` 上原地改文件会同时改掉快照，不要在那里工作。
- `evaluation/datasets/raw/` 现为 git-ignore；本机数据仍在原位，新机器用 `scripts/fetch_datasets.sh`。

**下一步**：10-19 决策点（Track A 全量投稿 / Track B 工程收尾 + arXiv），见 `DEVELOPMENT_PLAN.md` §2.3。无论哪条 Track，P1.2（引擎限额）先做。
