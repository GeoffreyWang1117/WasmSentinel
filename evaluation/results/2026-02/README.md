# 2026-02 ML baseline comparison (archived)

`ml_comparison_results_v2.json` was produced by `evaluation/scripts/ml_baseline_comparison.py`
(PyTorch, **not** the Wasm module) in early 2026-02 and originally sat in the repository root.
It holds only two values per model, and the working-copy diff of the script at the time had cut
training to 20 epochs (MLP) / 10 epochs (LSTM, Transformer, GNN). Treat it as a smoke run,
not as evidence; the DIMVA draft's "MLP F1 0.84" traces back here. The AsiaCCS evaluation
regenerates every number under `evaluation/results/2026-11/` (see `DEVELOPMENT_PLAN.md` §3 Phase 2).
