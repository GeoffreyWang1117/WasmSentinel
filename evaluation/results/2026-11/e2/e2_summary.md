# E2 same model, three implementations

5951 ADFA-LD traces; max |score diff|: NumPy vs Wasm 1.91e-06, NumPy vs native 1.90e-06, native vs Wasm 5.00e-09; decisions at 0.7 agree on 5951/5951 (NumPy vs Wasm).

| implementation | median ns/call | p90 ns/call | calls/s |
|---|---|---|---|
| numpy | 164603 | 413899 | 6075 |
| native_rust | 25950 | 54446 | 38535 |
| wasm_wasmtime_py | 126318 | 193161 | 7917 |

Go engine (`go test -bench`): BenchmarkInvokeEcho 2145 ns/op, BenchmarkRealMLDetectorJSON 10212 ns/op, BenchmarkRealMLDetectorRaw 4602 ns/op

