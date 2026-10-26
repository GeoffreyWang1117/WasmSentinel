# E1 ADFA-LD (5205 normal / 746 attack), 5-fold x 3 seeds

commit d549f3cef396, wasm sha256 a389a51aaff3, 2026-10-25T17:20:32Z

| model | AUPRC | ROC-AUC | recall@5%FPR | recall@1%FPR | F1 @FPR5 op | F1 @train-F1 op |
|---|---|---|---|---|---|---|
| WasmSentinel MLP (Wasm, feature set v1) | 0.730 ± 0.056 | 0.946 ± 0.011 | 0.718 | 0.345 | 0.691 | 0.700 |
| WasmSentinel RF (Wasm, feature set v1) | 0.897 ± 0.028 | 0.982 ± 0.004 | 0.908 | 0.700 | 0.636 | 0.724 |
| STIDE 6-gram novelty (normal only) | 0.437 ± 0.043 | 0.787 ± 0.024 | 0.377 | 0.157 | 0.344 | 0.345 |
| Isolation Forest (normal only, v1 features) | 0.218 ± 0.007 | 0.745 ± 0.013 | 0.046 | 0.002 | 0.060 | 0.360 |
| Random Forest (supervised, v1 features) | 0.897 ± 0.028 | 0.982 ± 0.004 | 0.908 | 0.700 | 0.636 | 0.724 |
| LSTM on syscall sequence (supervised, early stopping) | 0.825 ± 0.061 | 0.965 ± 0.012 | 0.858 | 0.488 | 0.760 | 0.792 |

| model | AUPRC(WasmSentinel MLP) − AUPRC(model) | 95% CI | Wilcoxon p |
|---|---|---|---|
| WasmSentinel RF (Wasm, feature set v1) | -0.167 | [-0.199, -0.135] | 6.1e-05 |
| STIDE 6-gram novelty (normal only) | +0.293 | [+0.257, +0.328] | 6.1e-05 |
| Isolation Forest (normal only, v1 features) | +0.512 | [+0.480, +0.544] | 6.1e-05 |
| Random Forest (supervised, v1 features) | -0.167 | [-0.199, -0.135] | 6.1e-05 |
| LSTM on syscall sequence (supervised, early stopping) | -0.095 | [-0.126, -0.064] | 0.000183 |

| model | AUPRC(WasmSentinel RF) − AUPRC(model) | 95% CI | Wilcoxon p |
|---|---|---|---|
| WasmSentinel MLP (Wasm, feature set v1) | +0.167 | [+0.135, +0.199] | 6.1e-05 |
| STIDE 6-gram novelty (normal only) | +0.460 | [+0.430, +0.490] | 6.1e-05 |
| Isolation Forest (normal only, v1 features) | +0.679 | [+0.662, +0.696] | 6.1e-05 |
| Random Forest (supervised, v1 features) | +0.000 | [+0.000, +0.000] | 1 |
| LSTM on syscall sequence (supervised, early stopping) | +0.072 | [+0.046, +0.098] | 0.000122 |

Wasm vs reference implementation, max |score diff| over all runs: wasmsentinel_mlp 1.13e-06, wasmsentinel_rf 2.94e-08

Per-family recall at the FPR-5 % operating point (mean over runs):

| model | Adduser | Hydra_FTP | Hydra_SSH | Java_Meterpreter | Meterpreter | Web_Shell |
|---|---|---|---|---|---|---|
| wasmsentinel_mlp | 0.79 | 0.80 | 0.87 | 0.80 | 0.71 | 0.66 |
| wasmsentinel_rf | 0.96 | 0.99 | 0.99 | 0.99 | 0.97 | 0.95 |
| stide | 0.78 | 0.85 | 0.84 | 0.85 | 0.68 | 0.78 |
| iforest | 0.04 | 0.00 | 0.03 | 0.05 | 0.13 | 0.06 |
| rf | 0.96 | 0.99 | 0.99 | 0.99 | 0.97 | 0.95 |
| lstm | 0.83 | 0.91 | 0.92 | 0.91 | 0.87 | 0.76 |
