# WasmSentinel Evaluation

## Real Experimental Results

All results in this directory are from actual experiments run on real hardware.

### Dataset
- **ADFA-LD**: Australian Defence Force Academy Linux Dataset (2013)
  - Location: `datasets/raw/ADFA-LD/`
  - 5,951 syscall traces (5,205 normal, 746 attack)
  - Real syscall sequences from Linux systems

### Experiment Results

#### Core Results (Paper Data)
- `results/real_experiments/real_experiments_20260201_123408.json`
  - ADFA-LD detection: precision=0.38, recall=0.86, F1=0.53
  - Latency: mean=53µs, median=33µs, p99=290µs
  - ML comparison: RF (F1=0.85), MLP (F1=0.87), N-gram (F1=0.53)

#### System Benchmarks
- `results/overhead/micro_benchmark_results.json` - Syscall timing measurements
- `results/overhead/macro_benchmark_results.json` - Container/IO/CPU benchmarks
- `results/overhead/falco_comparison_results.json` - Comparison with Falco

#### Workload Benchmarks
- `results/real_workload/` - Real wrk/sysbench benchmarks for nginx, Redis, MySQL, PostgreSQL
  - Note: Benchmarks are real; WasmSentinel monitoring was simulated due to eBPF requirements

### Scripts

#### Producing Real Results
- `scripts/run_real_experiments.py` - Main experiment runner (ADFA-LD, ML comparison, latency)
- `scripts/evaluate_adfa_ld.py` - ADFA-LD evaluation with n-gram detection
- `scripts/ml_baseline_comparison.py` - sklearn ML model comparison

#### Requires Additional Setup
- `scripts/evaluate_lid_ds.py` - LID-DS evaluation (requires Docker infrastructure)
- `scripts/real_workload_test.py` - Container workload tests (requires Docker)

## Reproducing Results

### Prerequisites
```bash
# Python dependencies
pip install numpy scikit-learn

# ADFA-LD dataset (included in datasets/raw/ADFA-LD/)
```

### Running Core Experiments
```bash
cd evaluation/scripts
python run_real_experiments.py
```

This produces:
- ADFA-LD detection metrics
- Latency measurements (10,000 iterations)
- ML baseline comparison (RF, MLP with sklearn)

### Expected Results
| Metric | Value |
|--------|-------|
| N-gram Recall | 86% |
| N-gram Precision | 38% |
| N-gram F1 | 0.53 |
| MLP F1 | 0.87 |
| Median Latency | 33µs |
