# E5 same detections, three systems

commit ba7af70ee77e, 2026-10-25T13:24:43Z, 20 trials per scenario

| system | scenario | detected | latency median (ms) | latency p90 | RSS max (MiB) | CPU % during trials |
|---|---|---|---|---|---|---|
| wasmsentinel | shadow | 20/20 | 2.9 | 3.2 | 97 | 7.1 |
| wasmsentinel | tmpexec | 20/20 | 0.8 | 0.9 | 97 | 7.1 |
| wasmsentinel | connect | 20/20 | 2.3 | 2.7 | 97 | 7.1 |
| falco | shadow | 20/20 | 2.8 | 3.0 | 371 | 1.2 |
| falco | tmpexec | 20/20 | 0.7 | 0.7 | 371 | 1.2 |
| falco | connect | 20/20 | 1.8 | 1.9 | 371 | 1.2 |
| tetragon | shadow | 20/20 | 2.7 | 3.0 | 154 | 0.8 |
| tetragon | tmpexec | 20/20 | 0.8 | 0.8 | 154 | 0.8 |
| tetragon | connect | 20/20 | 1.7 | 1.8 | 154 | 0.8 |
