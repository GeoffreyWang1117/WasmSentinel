# evaluation/results/2026-11

每个文件都由仓库里的一条命令生成；论文（AsiaCCS 2027 C2）只引用这个目录。重新生成：`make reproduce`（或单项 `make isolation` / `make parity` / `make e1` … `make e5`）。

| 目录 / 文件 | 实验 | 生成命令 | 来源代码 |
|---|---|---|---|
| `isolation/isolation.json`, `isolation.md` | E6 沙箱隔离：10 个故意越界的 Wasm 模块、11 个用例，在默认限额下由引擎处理 | `make isolation` | `rules/adversarial/`，`host/internal/engine/adversarial_test.go` |
| `parity/parity.txt` | P1.4 模型一致性：NumPy 参考实现 vs Wasm 模块，1,000 条合成序列 + 400 条 ADFA-LD 轨迹 | `make parity` | `rules/ml-detector/train/verify_wasm_parity.py` |
| `e1/e1_results.json`, `e1_summary.md`, `e1_pr_curves.{json,png,pdf}` | E1 检测准确率：ADFA-LD 5 折 × 3 种子，MLP 每折在 NumPy 训练、权重装进模块、分数全部来自模块 `mlp_score`；基线 STIDE / Isolation Forest / Random Forest / LSTM | `make e1`（LSTM 在 CPU 上约 4 h） | `evaluation/scripts/e1_adfa_eval.py`, `plot_e1.py` |
| `e2/e2_results.json`, `e2_summary.md` | E2 同一模型三种实现（NumPy / 原生 Rust / Wasm）的一致性与每次调用成本；Go 引擎 `go test -bench` | `make e2` | `evaluation/scripts/e2_consistency.py`, `host/internal/engine/*_test.go` |
| `e3/e3_results.json`, `e3_summary.md` | E3 端到端延迟与吞吐：ADFA-LD 轨迹按 syscall 事件回放进完整管道，1K/10K/50K eps × {json, binary} × 3 | `make e3` | `evaluation/scripts/e3_throughput.py`，`host/internal/pipeline` |
| `e4/e4_results.json`, `e4_summary.md` | E4 应用开销：nginx (wrk) / redis (redis-benchmark) / postgres (pgbench) × {none, wasmsentinel, falco, tetragon}，每格 5 次交错重复 | `make e4`（需要 docker 与特权容器） | `evaluation/scripts/e4_overhead.py`, `monitors.py`, `evaluation/configs/` |
| `e5/e5_results.json`, `e5_summary.md` | E5 同一三种检测（读 /etc/shadow、/tmp 可执行、连 :4444）在 WasmSentinel / Falco / Tetragon 上的检出、告警延迟、RSS、CPU，各 20 次 | `make e5`（需要 docker 与特权容器） | `evaluation/scripts/e5_fair_comparison.py`, `monitors.py`, `evaluation/configs/` |

JSON 里带 `generated` 时间戳与限额；提交到仓库的是本机（Ubuntu 26.04，Linux 7.0.0-34，wasmtime-go v17）的一次运行，CI 的 `isolation` job 在 ubuntu-latest 上重跑同一测试并把表格贴到 job summary。

计时类实验（E2 的计时部分、E3、E4、E5）在本机（AMD Ryzen 9 5950X，32 逻辑核，121 GiB）上跑，期间用户自己的 vLLM 服务常驻、约占 2.5 核；每个 JSON 的 `provenance` 记录 commit、模块 sha256 与时间。E1 的 `provenance.git_dirty=true` 来自未跟踪文件（见 RESEARCH_LOG 2026-10-25 E1 条目），跟踪文件与记录的 commit 一致。
