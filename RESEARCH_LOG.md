# WasmSentinel 研究日志

按日期倒序。每条写清：做了什么、证据在哪、下一步。任务编号对应 `DEVELOPMENT_PLAN.md` §3。

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
