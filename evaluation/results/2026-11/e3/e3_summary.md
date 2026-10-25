# E3 end-to-end latency and throughput

commit ba7af70ee77e, 2026-10-25T12:59:09Z, reps 3, 30 s per run

| encoding | offered eps | achieved eps | e2e p50 (us) | e2e p99 | e2e p999 | detect p50 | detect p99 | RSS (MiB) |
|---|---|---|---|---|---|---|---|---|
| json | 1000 | 964 | 118 | 183 | 325 | 105 | 149 | 90 |
| binary | 1000 | 961 | 101 | 144 | 240 | 89 | 119 | 92 |
| json | 10000 | 9689 | 378 | 1853 | 4686 | 81 | 131 | 99 |
| binary | 10000 | 9688 | 304 | 1246 | 3585 | 70 | 112 | 100 |
| json | 50000 | 14996 | 334813 | 425654 | 445640 | 82 | 117 | 178 |
| binary | 50000 | 18466 | 270773 | 352795 | 366660 | 71 | 95 | 189 |
