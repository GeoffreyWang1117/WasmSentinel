# WasmSentinel — build, test and reproduce.
#
#   make build       host binary + both rule modules (scripts/build.sh)
#   make test        Go (race) + Rust tests
#   make isolation   E6: adversarial modules against the engine -> $(RESULTS)/isolation/
#   make parity      P1.4: NumPy reference vs Wasm model      -> $(RESULTS)/parity/
#   make e1          E1: ADFA-LD accuracy, inference in Wasm   -> $(RESULTS)/e1/
#   make e2          E2: NumPy / native / Wasm consistency + latency -> $(RESULTS)/e2/
#   make e3          E3: end-to-end latency & throughput (replay)  -> $(RESULTS)/e3/
#   make e4          E4: nginx/redis/postgres overhead under monitors -> $(RESULTS)/e4/
#   make e5          E5: same three detections in WasmSentinel/Falco/Tetragon -> $(RESULTS)/e5/
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

# E1 takes a while (15 MLP + 15 LSTM trainings; LSTM on CPU when the GPUs are busy).
e1: build
	mkdir -p $(RESULTS)/e1
	$(PY) evaluation/scripts/e1_adfa_eval.py --out $(RESULTS)/e1 --wasm rules/wasm/ml_detector.wasm
	$(PY) evaluation/scripts/plot_e1.py --results $(RESULTS)/e1

e1-quick: build
	$(PY) evaluation/scripts/e1_adfa_eval.py --quick --device cpu --out /tmp/wasmsentinel-e1-quick

# E2/E3 are timing experiments: run them on an idle machine.
e2: build
	mkdir -p $(RESULTS)/e2
	cd rules/ml-detector && cargo build --release --example native_score
	$(PY) evaluation/scripts/e2_consistency.py --out $(RESULTS)/e2

e3: build
	mkdir -p $(RESULTS)/e3
	$(PY) evaluation/scripts/e3_throughput.py --out $(RESULTS)/e3

# E4 needs docker (privileged containers for the monitors) and an idle machine.
e4: build
	mkdir -p $(RESULTS)/e4
	$(PY) evaluation/scripts/e4_overhead.py --out $(RESULTS)/e4

e5: build
	mkdir -p $(RESULTS)/e5
	$(PY) evaluation/scripts/e5_fair_comparison.py --out $(RESULTS)/e5

reproduce: isolation parity e1 e2 e3 e4 e5
	@echo "results in $(RESULTS)/"

clean:
	rm -f wasmsentinel rules/wasm/*.wasm
