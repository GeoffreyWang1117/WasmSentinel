# E5 same detections, three systems

commit 20551595566c, 2026-10-26T09:50:27Z, 20 trials per scenario

| system | scenario | detected | latency median (ms) | latency p90 | RSS max (MiB) | CPU % during trials |
|---|---|---|---|---|---|---|
| wasmsentinel | shadow | 20/20 | 2.9 | 3.1 | 104 | 6.9 |
| wasmsentinel | tmpexec | 20/20 | 0.8 | 0.9 | 104 | 6.9 |
| wasmsentinel | connect | 20/20 | 1.9 | 2.0 | 104 | 6.9 |
| falco | shadow | 20/20 | 2.9 | 3.1 | 369 | 2.5 |
| falco | tmpexec | 20/20 | 0.7 | 0.8 | 369 | 2.5 |
| falco | connect | 20/20 | 1.9 | 1.9 | 369 | 2.5 |
| tetragon | shadow | 20/20 | 2.7 | 3.0 | 86 | 0.7 |
| tetragon | tmpexec | 20/20 | 0.7 | 0.8 | 86 | 0.7 |
| tetragon | connect | 20/20 | 1.7 | 1.8 | 86 | 0.7 |
