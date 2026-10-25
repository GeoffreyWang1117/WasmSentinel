#!/usr/bin/env python3
"""Check that the Wasm module reproduces the NumPy reference model.

For every input sequence the script computes feature set v1 and the MLP score
twice: with the training code in this directory (train_mlp.extract_features +
SimpleMLP loaded from the JSON weights) and with the compiled module
(mlp_features / mlp_score exports, run under wasmtime). It reports the largest
absolute differences and fails when the score difference exceeds --tolerance.

Inputs: --count synthetic sequences (seeded) plus, when --adfa-dir exists, real
ADFA-LD traces. --write-golden dumps a fixture for the Rust test
tests/parity_golden.rs, computed from the NumPy reference only.

Usage:
  python3 verify_wasm_parity.py --wasm ../target/wasm32-wasip1/release/ml_detector.wasm
  python3 verify_wasm_parity.py --write-golden fixtures/features_golden.json
"""
import argparse
import json
import random
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from train_mlp import SimpleMLP, extract_features, parse_syscall_trace  # noqa: E402


def load_reference(weights_path: Path) -> SimpleMLP:
    layers = json.loads(weights_path.read_text())
    mlp = SimpleMLP(input_size=len(layers[0]["weights"][0]),
                    hidden_sizes=[len(l["weights"]) for l in layers[:-1]],
                    output_size=len(layers[-1]["weights"]))
    for i, layer in enumerate(layers):
        mlp.layers[i]["weights"] = np.asarray(layer["weights"], dtype=np.float32)
        mlp.layers[i]["biases"] = np.asarray(layer["biases"], dtype=np.float32)
    return mlp


def synthetic_sequences(count: int, seed: int = 2026):
    rng = random.Random(seed)
    lengths = [1, 2, 3, 5, 8, 10, 25, 50, 100, 300, 1000, 2000]
    out = []
    for i in range(count):
        n = lengths[i % len(lengths)]
        if i % 3 == 0:
            # bursty: a few syscalls repeated, like real traces
            alphabet = [rng.randrange(0, 341) for _ in range(rng.randrange(1, 8))]
            seq = [rng.choice(alphabet) for _ in range(n)]
        else:
            seq = [rng.randrange(0, 341) for _ in range(n)]
        out.append(seq)
    return out


def adfa_sequences(adfa_dir: Path, limit: int):
    files = sorted(adfa_dir.glob("Training_Data_Master/*.txt"))[: limit // 2]
    files += sorted(adfa_dir.glob("Attack_Data_Master/*/*.txt"))[: limit - len(files)]
    return [parse_syscall_trace(str(f)) for f in files if f.is_file()]


class WasmModel:
    def __init__(self, path: Path):
        import wasmtime

        self.engine = wasmtime.Engine()
        self.store = wasmtime.Store(self.engine)
        linker = wasmtime.Linker(self.engine)
        linker.define_wasi()
        self.store.set_wasi(wasmtime.WasiConfig())
        module = wasmtime.Module.from_file(self.engine, str(path))
        inst = linker.instantiate(self.store, module)
        ex = inst.exports(self.store)
        self.memory = ex["memory"]
        self.alloc = ex["alloc"]
        self.dealloc = ex["dealloc"]
        self.mlp_score = ex["mlp_score"]
        self.mlp_features = ex["mlp_features"]
        self.model_info = ex["model_info"]
        self.free_result = ex["free_result"]
        self.load_mlp_weights = ex["load_mlp_weights"]
        # Random-forest exports; modules built before the forest existed lack them.
        try:
            self.rf_score_fn = ex["rf_score"]
            self.load_rf_model = ex["load_rf_model"]
        except KeyError:
            self.rf_score_fn = self.load_rf_model = None

    def has_forest(self) -> bool:
        return self.rf_score_fn is not None

    def load_forest(self, blob: bytes) -> None:
        """Replace the module's random forest with a WSRF image (per-fold forests in E1)."""
        if self.load_rf_model is None:
            raise RuntimeError("module has no load_rf_model export")
        ptr = self.alloc(self.store, len(blob))
        try:
            self.memory.write(self.store, blob, ptr)
            rc = self.load_rf_model(self.store, ptr, len(blob))
            if rc != 0:
                raise RuntimeError(f"load_rf_model returned {rc}")
        finally:
            self.dealloc(self.store, ptr, len(blob))

    def score_rf(self, seq) -> float:
        """Random-forest score (features + traversal inside the module)."""
        return float(self._with_sequence(seq, lambda p, n: self.rf_score_fn(self.store, p, n)))

    def info(self) -> dict:
        lenp = self.alloc(self.store, 4)
        ptr = self.model_info(self.store, lenp)
        n = int.from_bytes(self.memory.read(self.store, lenp, lenp + 4), "little")
        data = bytes(self.memory.read(self.store, ptr, ptr + n))
        self.free_result(self.store, ptr, n)
        self.dealloc(self.store, lenp, 4)
        return json.loads(data)

    def load_weights(self, weights_json: str) -> None:
        """Replace the module's MLP with a weights JSON (per-fold models in E1)."""
        data = weights_json.encode()
        ptr = self.alloc(self.store, len(data))
        try:
            self.memory.write(self.store, data, ptr)
            rc = self.load_mlp_weights(self.store, ptr, len(data))
            if rc != 0:
                raise RuntimeError(f"load_mlp_weights returned {rc}")
        finally:
            self.dealloc(self.store, ptr, len(data))

    def _with_sequence(self, seq, fn):
        n = len(seq)
        size = max(4, 4 * n)
        ptr = self.alloc(self.store, size)
        if n:
            self.memory.write(self.store, np.asarray(seq, dtype="<u4").tobytes(), ptr)
        try:
            return fn(ptr, n)
        finally:
            self.dealloc(self.store, ptr, size)

    def score(self, seq) -> float:
        return float(self._with_sequence(seq, lambda p, n: self.mlp_score(self.store, p, n)))

    def features(self, seq) -> np.ndarray:
        out = self.alloc(self.store, 64 * 4)
        try:
            written = self._with_sequence(seq, lambda p, n: self.mlp_features(self.store, p, n, out))
            assert written == 64, written
            return np.frombuffer(bytes(self.memory.read(self.store, out, out + 256)), dtype="<f4").copy()
        finally:
            self.dealloc(self.store, out, 64 * 4)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wasm", type=Path, default=HERE.parent / "target/wasm32-wasip1/release/ml_detector.wasm")
    ap.add_argument("--weights", type=Path, default=HERE / "best_model_weights.json")
    ap.add_argument("--adfa-dir", type=Path, default=HERE.parents[2] / "evaluation/datasets/raw/ADFA-LD/ADFA-LD")
    ap.add_argument("--count", type=int, default=1000, help="synthetic sequences")
    ap.add_argument("--adfa-count", type=int, default=400, help="ADFA-LD traces, if the dataset is present")
    ap.add_argument("--tolerance", type=float, default=1e-5)
    ap.add_argument("--write-golden", type=Path, help="write a NumPy-only fixture and exit")
    args = ap.parse_args()

    ref = load_reference(args.weights)
    sequences = synthetic_sequences(args.count)
    n_adfa = 0
    if args.adfa_dir.is_dir() and args.adfa_count > 0:
        adfa = adfa_sequences(args.adfa_dir, args.adfa_count)
        n_adfa = len(adfa)
        sequences += adfa

    if args.write_golden:
        picks = sequences[:24:2] + sequences[-6:]
        cases = []
        for seq in picks:
            f = extract_features(seq)
            cases.append({"syscalls": seq, "features": [float(x) for x in f],
                          "score": float(ref.forward(f)[0])})
        args.write_golden.write_text(json.dumps({"weights": args.weights.name, "cases": cases}, indent=1))
        print(f"wrote {len(cases)} golden cases to {args.write_golden}")
        return 0

    wasm = WasmModel(args.wasm)
    info = wasm.info()
    print(f"wasm model: {info}")
    expected_hidden = [len(l["weights"]) for l in json.loads(args.weights.read_text())[:-1]]
    if info["hidden_sizes"] != expected_hidden:
        print(f"ARCHITECTURE MISMATCH: wasm {info['hidden_sizes']} vs weights {expected_hidden}")
        return 2

    max_feat = 0.0
    max_score = 0.0
    worst = None
    for i, seq in enumerate(sequences):
        f_ref = extract_features(seq)
        f_wasm = wasm.features(seq)
        d_feat = float(np.max(np.abs(f_ref - f_wasm))) if len(f_ref) else 0.0
        s_ref = float(ref.forward(f_ref)[0])
        s_wasm = wasm.score(seq)
        d_score = abs(s_ref - s_wasm)
        if d_feat > max_feat:
            max_feat = d_feat
        if d_score > max_score:
            max_score = d_score
            worst = (i, len(seq), s_ref, s_wasm)

    print(f"inputs: {len(sequences)} ({len(sequences) - n_adfa} synthetic, {n_adfa} ADFA-LD traces)")
    print(f"max |feature diff| = {max_feat:.3e}")
    print(f"max |score diff|   = {max_score:.3e}  (worst case #{worst[0]}, len {worst[1]}, ref {worst[2]:.6f} wasm {worst[3]:.6f})")
    if max_score > args.tolerance:
        print(f"FAIL: score difference exceeds {args.tolerance:g}")
        return 1

    # Random forest: the module's rf_score against the scikit-learn
    # probabilities train_rf.py stored with the fixture (no scikit-learn needed here).
    fixture = HERE / "fixtures" / "forest_golden.json"
    if wasm.has_forest() and fixture.is_file():
        golden = json.loads(fixture.read_text())
        if golden.get("sha256") != info.get("rf", {}).get("sha256"):
            print(f"FOREST MISMATCH: fixture {golden.get('sha256', '')[:12]} vs module {info.get('rf', {}).get('sha256', '')[:12]}")
            return 2
        rf_max = max(abs(wasm.score_rf(c["syscalls"]) - c["prob"]) for c in golden["cases"])
        print(f"random forest: max |score diff| = {rf_max:.3e} over {len(golden['cases'])} fixture cases (scikit-learn reference)")
        if rf_max > args.tolerance:
            print(f"FAIL: forest score difference exceeds {args.tolerance:g}")
            return 1
    print(f"PASS: within {args.tolerance:g}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
