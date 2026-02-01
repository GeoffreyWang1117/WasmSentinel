# WasmSentinel DIMVA 2026 - Real Experiment Results

**Date**: 2026-02-01
**Paper**: 21 pages (within DIMVA limit)

---

## Core Experimental Results (Real Data)

### ADFA-LD Detection Performance

From `../evaluation/results/real_experiments/real_experiments_20260201_123408.json`:

| Metric | N-gram (STIDE) | MLP | Random Forest |
|--------|----------------|-----|---------------|
| Precision | 0.38 | 0.92 | 0.90 |
| Recall | **0.86** | 0.83 | 0.80 |
| F1 | 0.53 | **0.87** | 0.85 |

**Key Insight**: N-gram prioritizes recall (catching attacks) over precision. MLP achieves higher F1 but with more latency.

### Latency Measurements

| Metric | Value |
|--------|-------|
| Mean | 53.44 µs |
| Median | 33.47 µs |
| P99 | 289.93 µs |
| Min | 7.35 µs |
| Max | 431.86 µs |

### ML Model Latency Comparison

| Model | F1 | Inference Latency | Wasm-Compatible |
|-------|-----|-------------------|-----------------|
| Random Forest | 0.847 | 15.8 ms | No |
| MLP | 0.872 | 90 µs | Yes |
| N-gram (STIDE) | 0.529 | 1.1 µs | Yes |

---

## System Benchmarks (Real Data)

### Syscall Micro-benchmarks

From `micro_benchmark_results.json`:

| Syscall | Mean (ns) | Stdev (ns) |
|---------|-----------|------------|
| getpid | 140.4 | 54.8 |
| getuid | 138.1 | 89.3 |
| stat | 822.8 | 232.8 |
| fstat | 343.3 | 1115.5 |
| open+close | 2094.1 | 373.9 |

### Macro-benchmarks

From `macro_benchmark_results.json`:

| Metric | Value |
|--------|-------|
| Container startup | 320.8 ms (±31.7 ms) |
| File I/O write | 2,307 MB/s |
| File I/O read | 14,270 MB/s |
| CPU (SHA256) | 2.39M ops/s |

---

## Data Files

```
evaluation-results/
├── EXPERIMENT_SUMMARY.md          # This file
├── micro_benchmark_results.json   # Real syscall timing
├── macro_benchmark_results.json   # Real system benchmarks
└── ml_comparison_results.json     # Real sklearn ML comparison
```

Additional real results in `../evaluation/results/`:
- `real_experiments/` - Core ADFA-LD and latency data
- `overhead/` - Benchmark comparison data
- `real_workload/` - Container workload benchmarks (wrk/sysbench)

---

## Reproducibility

```bash
cd ../evaluation/scripts
python run_real_experiments.py
```

*Last updated: 2026-02-01*
