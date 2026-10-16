#!/usr/bin/env bash
# Build the host binary and both Wasm rule modules.
#   ./wasm-threat-detector            host program (Go + wasmtime)
#   rules/wasm/suspicious_shell.wasm  rule-based example module
#   rules/wasm/ml_detector.wasm       STIDE + MLP module
# Wasm modules are build products (git-ignored); fetch prebuilt ones from GitHub Releases if you
# do not have a Rust toolchain.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> checking toolchain"
command -v go    >/dev/null || { echo "Go is required (https://go.dev/dl/)"; exit 1; }
command -v cargo >/dev/null || { echo "Rust is required (https://rustup.rs)"; exit 1; }
if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-wasip1$'; then
  echo "==> installing wasm32-wasip1 target"
  rustup target add wasm32-wasip1
fi

mkdir -p rules/wasm
for crate in suspicious-shell ml-detector; do
  echo "==> building rules/$crate (wasm32-wasip1, release)"
  (cd "rules/$crate" && cargo build --release --target wasm32-wasip1 --quiet)
  cp "rules/$crate/target/wasm32-wasip1/release/"*.wasm rules/wasm/
done

echo "==> building host"
(cd host && go build -o ../wasm-threat-detector ./cmd/main.go)

echo
echo "built:"
ls -la wasm-threat-detector rules/wasm/*.wasm
echo
echo "run:  ./wasm-threat-detector --rules ./rules/wasm"
