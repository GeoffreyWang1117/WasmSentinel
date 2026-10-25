# evaluation/

论文（AsiaCCS 2027 Cycle 2）只引用 `results/2026-11/`；那个目录里每个文件都由仓库根目录 `Makefile` 的一条命令生成，见 `results/2026-11/README.md`。其余 `results/*` 子目录是 2025-12 至 2026-02 的历史产物，保留作追溯，**论文不引用**（其中 `overhead/` 的 Falco 数字是文献值，`real_workload/` 的"监控臂"是模拟的，`real_experiments/` 的 MLP 是 PyTorch 而非 Wasm 模块——见 `DEVELOPMENT_PLAN.md` §1.4）。

## 实验与脚本（2026-11 流水线）

| 实验 | 命令 | 脚本 | 产出 |
|---|---|---|---|
| E1 ADFA-LD 检测准确率，推理在 Wasm 模块内 | `make e1` | `scripts/e1_adfa_eval.py`、`scripts/plot_e1.py` | `e1/e1_results.json`、`e1_summary.md`、`e1_pr_curves.{json,pdf}` |
| E2 同一模型三种实现的一致性与单次延迟 | `make e2` | `scripts/e2_consistency.py` + `rules/ml-detector/examples/native_score.rs` | `e2/e2_results.json` |
| E3 端到端延迟与吞吐（回放采集器，JSON vs 二进制） | `make e3` | `scripts/e3_throughput.py` | `e3/e3_results.json` |
| E4 nginx / redis / postgres 在四种监控臂下的开销 | `make e4` | `scripts/e4_overhead.py`、`scripts/monitors.py` | `e4/e4_results.json` |
| E5 同一三种检测在 WasmSentinel / Falco / Tetragon | `make e5` | `scripts/e5_fair_comparison.py`、`configs/*-e5-*` | `e5/e5_results.json` |
| E6 沙箱隔离（10 个越界模块） | `make isolation` | `host/internal/engine/adversarial_test.go`、`rules/adversarial/` | `isolation/isolation.{json,md}` |
| 模型一致性（NumPy vs Wasm） | `make parity` | `rules/ml-detector/train/verify_wasm_parity.py` | `parity/parity.txt` |
| 论文数字宏 | `make -C paper-asiaccs numbers` | `scripts/paper_numbers.py` | `paper-asiaccs/tables/numbers.tex` |

`make reproduce` 依次跑完以上全部。每个 JSON 带 `provenance`（git commit、内核、CPU、库版本、wasm sha256、时间戳）。

## 前提

```bash
scripts/fetch_datasets.sh ADFA-LD          # evaluation/datasets/raw/ADFA-LD（git 忽略）
conda create -n wasmsentinel --clone <env with torch+sklearn> && conda run -n wasmsentinel pip install wasmtime
./scripts/build.sh                         # 主机二进制 + 两个规则模块
```

E2/E3/E4/E5 是计时实验，要在空闲机器上跑；E4/E5 需要 docker（监控器以特权容器运行，负载容器只发布到 127.0.0.1）。E1、E2 一致性、E6、parity 在任何机器上都能跑，也在 CI 里跑（E6、parity）。

## 历史目录（不引用）

- `results/20251231_*`、`results/adfa_ld_*`：12 月早期结果
- `results/real_experiments/`：Python 6-gram 与 PyTorch 基线（非 Wasm）
- `results/overhead/`、`results/real_workload/`：含文献值与模拟臂
- `results/2026-02/`：2 折 smoke run（附 README）
- `scripts/run_real_experiments.py`、`evaluate_adfa_ld.py`、`ml_baseline_comparison.py`、`evaluate_lid_ds.py`、`real_workload_test.py`、`benchmarks/wasm_benchmark.py`：生成上述历史结果的脚本，保留但不再维护
