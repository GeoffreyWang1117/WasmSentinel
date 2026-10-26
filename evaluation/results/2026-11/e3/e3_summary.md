# E3 end-to-end latency and throughput

commit 3e804a63d77c, 2026-10-25T21:38:35Z, reps 3, 30 s per run; model = ml_detector deep path (mlp: module default; rf: init config {"model":"rf"} via --rule-config)

| encoding | model | offered eps | achieved eps | e2e p50 (us) | e2e p99 | e2e p999 | detect p50 | detect p99 | RSS (MiB) |
|---|---|---|---|---|---|---|---|---|---|
| json | mlp | 1000 | 969 | 118 | 191 | 331 | 105 | 148 | 93 |
| json | rf | 1000 | 965 | 103 | 185 | 344 | 90 | 153 | 99 |
| binary | mlp | 1000 | 962 | 101 | 146 | 245 | 89 | 122 | 94 |
| binary | rf | 1000 | 968 | 86 | 153 | 284 | 73 | 116 | 97 |
| json | mlp | 10000 | 9706 | 382 | 2189 | 6280 | 81 | 130 | 101 |
| json | rf | 10000 | 9685 | 335 | 1434 | 2664 | 70 | 118 | 105 |
| binary | mlp | 10000 | 9687 | 301 | 1194 | 1834 | 70 | 110 | 103 |
| binary | rf | 10000 | 9671 | 254 | 987 | 1466 | 58 | 97 | 107 |
| json | mlp | 50000 | 15072 | 333324 | 419911 | 437699 | 82 | 115 | 189 |
| json | rf | 50000 | 17044 | 294724 | 369420 | 381873 | 69 | 100 | 190 |
| binary | mlp | 50000 | 18277 | 273616 | 364278 | 383935 | 71 | 97 | 199 |
| binary | rf | 50000 | 21430 | 233727 | 308660 | 323171 | 57 | 82 | 197 |
