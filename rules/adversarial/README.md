# Adversarial rule modules (E6)

Each crate is a rule module that misbehaves on purpose. The engine test
`host/internal/engine/adversarial_test.go` loads every one of them under the
default limits and records what the sandbox did about it; the CI job
`isolation` builds them and publishes the resulting table. They replace the
hard-coded "5/5 blocked" table of the earlier draft with a measurement.

| module | attempt | expected containment |
|---|---|---|
| `fs_read` | read /etc/passwd, list /, write /tmp | all fail: zero-capability WASI, no preopened directories |
| `env_leak` | enumerate env and argv | both empty |
| `net_connect` | TCP connect to 127.0.0.1:22 | fails: no sockets in WASI preview 1 |
| `stdout_flood` | 8 MiB to stdout + stderr | nothing reaches the host terminal |
| `clock` | read the wall clock | permitted by design (documented capability) |
| `mem_bomb_graceful` | grow memory until refused | stops at the memory cap, reports MiB reached |
| `mem_bomb_abort` | allocate 1 GiB at once | allocator aborts, engine reports `memory`, instance replaced |
| `cpu_spin` | infinite loop | fuel budget (or epoch deadline) interrupts it |
| `proc_exit` | `proc_exit(3)` | engine reports `exit`, instance replaced |
| `stack_overflow` | unbounded recursion | trap, instance replaced |

Build: `cargo build --release --target wasm32-wasip1` in this directory.
