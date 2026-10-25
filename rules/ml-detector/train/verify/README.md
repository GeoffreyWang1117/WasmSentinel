# Formal checks for the forest exporter

`threshold_rounding_claims.yaml` states the two lemmas `forest_export.f32_floor`
relies on, as SMT-LIB floating-point problems; `threshold_rounding_report.md` is
Z3's verdict (`~/Tools/verify-router/verify run threshold_rounding_claims.yaml`,
2026-10-25, both PROVED, < 1 s each):

1. for every float32 `x` and finite float64 `t`, `x <= t` (x promoted to f64, as
   scikit-learn compares) iff `x <= RTN_f32(t)` (as the module compares in f32);
2. "round to nearest f32, then one `nextafter` toward -inf if that exceeds `t`"
   (what the Python code does) equals `RTN_f32(t)` for finite `|t| < 3e38`.

Together they say the exporter's 4-byte thresholds reproduce every split decision
of the scikit-learn forest on float32 features, which is what the empirical
checks (`train_rf.py`: 5,951 traces, max |diff| 2.5e-9; E1 `wasmsentinel_rf`
arm per fold) then confirm end to end.
