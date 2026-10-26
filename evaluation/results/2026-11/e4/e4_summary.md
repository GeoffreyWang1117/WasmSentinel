# E4 application overhead under monitoring

commit 20551595566c, 2026-10-26T09:48:23Z, reps 5, 20 s per run

| workload | arm | throughput (mean ± std) | Δ vs none | 95% CI | monitor CPU % | monitor RSS (MiB) | system CPU % |
|---|---|---|---|---|---|---|---|
| nginx | none | 170989 ± 5499 | — | — | 0.0 | 0 | 91.1 |
| nginx | wasmsentinel | 163376 ± 5542 | -4.4% | [-6.4, -2.5] | 16.8 | 153 | 90.8 |
| nginx | falco | 155239 ± 8586 | -9.2% | [-12.9, -5.6] | 80.8 | 367 | 91.4 |
| nginx | tetragon | 140880 ± 5595 | -17.5% | [-23.4, -11.6] | 277.6 | 201 | 92.2 |
| redis | none | 948485 ± 15491 | — | — | 0.0 | 0 | 21.9 |
| redis | wasmsentinel | 914511 ± 27968 | -3.6% | [-7.2, +0.0] | 9.7 | 142 | 24.7 |
| redis | falco | 900656 ± 15590 | -5.0% | [-8.1, -1.9] | 8.0 | 371 | 24.0 |
| redis | tetragon | 936621 ± 12701 | -1.2% | [-3.2, +0.8] | 7.6 | 95 | 23.3 |
| postgres | none | 25217 ± 1379 | — | — | 0.0 | 0 | 62.7 |
| postgres | wasmsentinel | 22857 ± 667 | -9.2% | [-12.5, -6.0] | 163.0 | 180 | 66.6 |
| postgres | falco | 22964 ± 646 | -8.6% | [-17.2, -0.0] | 81.5 | 366 | 65.4 |
| postgres | tetragon | 25129 ± 685 | -0.1% | [-7.8, +7.6] | 19.1 | 119 | 61.5 |
