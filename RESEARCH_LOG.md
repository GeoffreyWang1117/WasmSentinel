# WasmSentinel 研究日志

按日期倒序。每条写清：做了什么、证据在哪、下一步。任务编号对应 `DEVELOPMENT_PLAN.md` §3。

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
