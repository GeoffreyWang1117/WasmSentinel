| module | attempt | expected | outcome | contained | time (ms) | memory after (MiB) | neighbour ok | recovers |
|---|---|---|---|---|---|---|---|---|
| `clock` | read the wall clock (permitted capability) | level==1 | level 1 | true | 0.02 | 1.1 | true | true |
| `cpu_spin` | infinite loop (fuel budget 5e7) | trap:fuel | trap fuel | true | 4.79 | 0.0 | true | true |
| `cpu_spin` | infinite loop (fuel off, 100 ms deadline) | trap:timeout | trap timeout | true | 102.65 | 0.0 | true | true |
| `env_leak` | enumerate environment variables and argv | level==0 | level 0 | true | 0.02 | 1.1 | true | true |
| `fs_read` | read /etc/passwd, list /, write /tmp via WASI | level==0 | level 0 | true | 0.03 | 1.1 | true | true |
| `mem_bomb_abort` | allocate and touch 1 GiB at once (refused before growing) | trap:memory|trap | trap trap | true | 0.09 | 0.0 | true | true |
| `mem_bomb_graceful` | grow memory 16 MiB at a time until refused | level<=64 | level 32 | true | 21.23 | 49.1 | true | true |
| `net_connect` | TCP connect to 127.0.0.1:22 via std::net | level==0 | level 0 | true | 0.00 | 1.1 | true | true |
| `proc_exit` | proc_exit(3) | trap:exit | trap exit | true | 0.04 | 0.0 | true | true |
| `stack_overflow` | unbounded recursion | trap:trap | trap trap | true | 2.15 | 0.0 | true | true |
| `stdout_flood` | write 8 MiB to stdout and stderr | level==0 | level 0 | true | 1.58 | 1.1 | true | true |

11/11 contained under limits memory=67108864 B, fuel=50000000, timeout=100ms.
