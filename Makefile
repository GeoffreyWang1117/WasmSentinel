# WasmSentinel — build, test and reproduce.
#
#   make build       host binary + both rule modules (scripts/build.sh)
#   make test        Go (race) + Rust tests
#   make isolation   E6: adversarial modules against the engine -> $(RESULTS)/isolation/
#   make parity      P1.4: NumPy reference vs Wasm model      -> $(RESULTS)/parity/
#   make reproduce   every experiment that exists so far, into $(RESULTS)/
#
# RESULTS defaults to evaluation/results/2026-11 (the directory the AsiaCCS
# paper cites). Every artifact there is produced by a command in this file.

RESULTS ?= evaluation/results/2026-11
PY      ?= conda run -n wasmsentinel python3
ADVERSARIAL_WASM := rules/adversarial/target/wasm32-wasip1/release/fs_read.wasm

.PHONY: build test test-go test-rust adversarial isolation parity reproduce clean

build:
	./scripts/build.sh

test: test-go test-rust

test-go:
	cd host && go test -race -count=1 ./...

test-rust:
	cd rules/sentinel-abi && cargo test --release
	cd rules/suspicious-shell && cargo test --release
	cd rules/ml-detector && cargo test --release

adversarial:
	cd rules/adversarial && cargo build --release --target wasm32-wasip1

isolation: adversarial
	mkdir -p $(RESULTS)/isolation
	cd host && WASMSENTINEL_RESULTS_DIR=$(abspath $(RESULTS)/isolation) go test -count=1 -run Adversarial -v ./internal/engine/ | grep -E "adversarial_test|^(ok|FAIL)" | sed 's/^ *adversarial_test.go:[0-9]*: //'
	@echo "-> $(RESULTS)/isolation/isolation.{json,md}"

parity: build
	mkdir -p $(RESULTS)/parity
	cd rules/ml-detector && $(PY) train/verify_wasm_parity.py --wasm ../wasm/ml_detector.wasm --count 1000 --adfa-count 400 | tee ../../$(RESULTS)/parity/parity.txt

reproduce: isolation parity
	@echo "results in $(RESULTS)/"

clean:
	rm -f wasmsentinel rules/wasm/*.wasm
