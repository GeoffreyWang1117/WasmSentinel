# E4 application overhead under monitoring

commit ba7af70ee77e, 2026-10-25T13:22:39Z, reps 5, 20 s per run

| workload | arm | throughput (mean ± std) | Δ vs none | 95% CI | monitor CPU % | monitor RSS (MiB) | system CPU % |
|---|---|---|---|---|---|---|---|
| nginx | none | 178007 ± 2706 | — | — | 0.0 | 0 | 90.8 |
| nginx | wasmsentinel | 170071 ± 1989 | -4.4% | [-7.2, -1.7] | 18.4 | 111 | 90.5 |
| nginx | falco | 161597 ± 3918 | -9.2% | [-11.8, -6.6] | 82.0 | 368 | 91.3 |
| nginx | tetragon | 148390 ± 2112 | -16.6% | [-18.1, -15.2] | 282.1 | 195 | 91.9 |
| redis | none | 960059 ± 11272 | — | — | 0.0 | 0 | 19.8 |
| redis | wasmsentinel | 927451 ± 9860 | -3.4% | [-5.0, -1.8] | 8.1 | 97 | 21.3 |
| redis | falco | 919601 ± 19853 | -4.2% | [-7.2, -1.2] | 7.4 | 369 | 22.6 |
| redis | tetragon | 945367 ± 10336 | -1.5% | [-3.5, +0.5] | 11.9 | 96 | 21.0 |
| postgres | none | 26450 ± 1082 | — | — | 0.0 | 0 | 58.4 |
| postgres | wasmsentinel | 23799 ± 1001 | -10.0% | [-14.4, -5.5] | 149.6 | 161 | 63.3 |
| postgres | falco | 23712 ± 284 | -10.2% | [-15.3, -5.1] | 80.7 | 365 | 62.0 |
| postgres | tetragon | 25907 ± 350 | -1.9% | [-7.9, +4.1] | 14.2 | 104 | 58.7 |
