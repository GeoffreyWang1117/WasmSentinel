# E2 same model, three implementations

5951 ADFA-LD traces; max |score diff|: NumPy vs Wasm 1.91e-06, NumPy vs native 1.90e-06, native vs Wasm 5.00e-09; decisions at 0.7 agree on 5951/5951 (NumPy vs Wasm).

Random forest (same traces): max |score diff| NumPy reader vs Wasm 2.96e-08, NumPy reader vs native 3.33e-08, native vs Wasm 4.93e-09.

| implementation | median ns/call | p90 ns/call | calls/s |
|---|---|---|---|
| numpy | 165651 | 399221 | 6037 |
| native_rust | 23800 | 50799 | 42016 |
| wasm_wasmtime_py | 127370 | 190660 | 7851 |
| native_rust_rf | 19545 | 48922 | 51164 |
| wasm_rf_wasmtime_py | 132597 | 207266 | 7542 |

Go engine (`go test -bench`): BenchmarkInvokeEcho 2106 ns/op, BenchmarkRealMLDetectorJSON 10188 ns/op, BenchmarkRealMLDetectorRaw 4443 ns/op

