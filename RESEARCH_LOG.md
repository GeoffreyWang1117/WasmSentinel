# WasmSentinel 研究日志

按日期倒序。每条写清：做了什么、证据在哪、下一步。任务编号对应 `DEVELOPMENT_PLAN.md` §3。

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
