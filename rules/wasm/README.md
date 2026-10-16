# rules/wasm

Compiled Wasm rule modules land here. They are **build products** and are git-ignored
(`*.wasm`); run `scripts/build.sh` to produce them, or download a release tarball.

| module | source | what it does |
|---|---|---|
| `suspicious_shell.wasm` | `rules/suspicious-shell/` | keyword / port / path rules for shell, network and file events |
| `ml_detector.wasm` | `rules/ml-detector/` | STIDE n-gram fast path + embedded MLP on syscall sequences |
