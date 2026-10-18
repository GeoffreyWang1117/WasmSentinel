# rules/wasm

Compiled Wasm rule modules land here. They are **build products** and are git-ignored
(`*.wasm`); run `scripts/build.sh` to produce them, or download a release tarball.

| module | source | what it does |
|---|---|---|
| `suspicious_shell.wasm` | `rules/suspicious-shell/` | keyword / port / path rules for shell, network and file events |
| `ml_detector.wasm` | `rules/ml-detector/` | STIDE n-gram fast path + embedded 128-64-32-16 MLP on syscall-number windows; provenance and parity check in `rules/ml-detector/MODEL.md` |

## Guest ABI (v2)

The host (`host/internal/engine`) talks to a rule module through these exports:

| export | signature | purpose |
|---|---|---|
| `memory` | linear memory | shared buffer space |
| `alloc` | `(size: i32) -> i32` | allocate `size` bytes; the host keeps one event buffer per instance and grows it on demand |
| `dealloc` | `(ptr: i32, size: i32)` | release a buffer from `alloc` |
| `detect` | `(ptr: i32, len: i32) -> i32` | analyse the event JSON at `ptr..ptr+len`; return a threat level 0..10 (0 = benign) |
| `init` | `(ptr: i32, len: i32) -> i32` (optional) | called once per instance with `(0, 0)` right after instantiation |
| `detect_raw` | `(ptr: i32, len: i32) -> i32` (optional) | binary path: the payload is the kernel record plus host-resolved strings (`rules/sentinel-abi`, Go `host/internal/wire`); must return the same level as `detect` would for the JSON form |

With `--event-encoding=binary` the host prefers `detect_raw` for eBPF events and falls back to `detect` per rule when the export or the binary form is missing. Writing at a fixed offset (the pre-v2 host behaviour) is gone: the host refuses to
load a module that does not export `alloc`/`dealloc`. In Rust the two allocator
exports are ten lines (see `rules/suspicious-shell/src/lib.rs`). A trap of any kind
(unreachable, fuel exhausted, deadline, failed allocation under the memory cap,
`proc_exit`) discards the instance; the next event gets a fresh one.
