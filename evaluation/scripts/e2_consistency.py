#!/usr/bin/env python3
"""E2: the same model, three implementations.

Consistency: for every ADFA-LD trace the embedded model's score is computed
by (1) the NumPy reference (train_mlp.extract_features + SimpleMLP forward
with the JSON weights), (2) the crate compiled natively
(rules/ml-detector/examples/native_score.rs) and (3) the Wasm module under
wasmtime (mlp_score). Reports max |diff| for each pair.

Latency: median ns per call of feature extraction + inference for each
implementation on the same traces (single thread), the Wasm number split into
in-module work (wasmtime) and host-call overhead (Go engine microbenchmark,
`go test -bench`), plus calls/s. Run --timing only on an otherwise idle
machine; --skip-timing records consistency alone.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
TRAIN_DIR = REPO / "rules" / "ml-detector" / "train"
sys.path.insert(0, str(TRAIN_DIR))
from train_mlp import extract_features, parse_syscall_trace  # noqa: E402
from verify_wasm_parity import WasmModel, load_reference  # noqa: E402


def all_traces(adfa: Path):
    files = sorted((adfa / "Training_Data_Master").glob("*.txt")) + sorted((adfa / "Validation_Data_Master").glob("*.txt"))
    files += sorted((adfa / "Attack_Data_Master").glob("*/*.txt"))
    return [f for f in files if f.is_file()]


def native_scores(files, repeat):
    exe = REPO / "rules/ml-detector/target/release/examples/native_score"
    if not exe.exists():
        subprocess.check_call(["cargo", "build", "--release", "--example", "native_score"], cwd=REPO / "rules/ml-detector")
    out = {}
    # chunk the argument list to stay under ARG_MAX
    for i in range(0, len(files), 500):
        chunk = [str(f) for f in files[i:i + 500]]
        res = subprocess.run([str(exe), "--repeat", str(repeat)] + chunk, capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            j = json.loads(line)
            out[j["path"]] = (j["score"], j["ns_per_call"], j["len"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adfa-dir", type=Path, default=REPO / "evaluation/datasets/raw/ADFA-LD/ADFA-LD")
    ap.add_argument("--wasm", type=Path, default=REPO / "rules/wasm/ml_detector.wasm")
    ap.add_argument("--weights", type=Path, default=TRAIN_DIR / "best_model_weights.json")
    ap.add_argument("--out", type=Path, default=REPO / "evaluation/results/2026-11/e2")
    ap.add_argument("--repeat", type=int, default=30, help="timed calls per trace per implementation")
    ap.add_argument("--timing-traces", type=int, default=600, help="traces used for timing (evenly sampled)")
    ap.add_argument("--skip-timing", action="store_true")
    args = ap.parse_args()

    files = all_traces(args.adfa_dir)
    seqs = [parse_syscall_trace(str(f)) for f in files]
    ref = load_reference(args.weights)
    wasm = WasmModel(args.wasm)
    t0 = time.time()

    # --- consistency on every trace
    s_np = np.array([float(ref.forward(extract_features(s))[0]) for s in seqs])
    s_wasm = np.array([wasm.score(s) for s in seqs])
    nat = native_scores(files, 1)
    s_nat = np.array([nat[str(f)][0] for f in files])
    consistency = {
        "traces": len(files),
        "max_abs_diff_numpy_vs_wasm": float(np.max(np.abs(s_np - s_wasm))),
        "max_abs_diff_numpy_vs_native": float(np.max(np.abs(s_np - s_nat))),
        "max_abs_diff_native_vs_wasm": float(np.max(np.abs(s_nat - s_wasm))),
        "decisions_agree_at_0.7": {
            "numpy_vs_wasm": int(((s_np > 0.7) == (s_wasm > 0.7)).sum()),
            "numpy_vs_native": int(((s_np > 0.7) == (s_nat > 0.7)).sum()),
        },
    }
    print("consistency:", json.dumps(consistency))

    timing = None
    if not args.skip_timing:
        step = max(1, len(files) // args.timing_traces)
        tf = files[::step]
        ts = seqs[::step]
        # NumPy
        np_ns = []
        for s in ts:
            samples = []
            for _ in range(args.repeat):
                a = time.perf_counter_ns()
                ref.forward(extract_features(s))
                samples.append(time.perf_counter_ns() - a)
            np_ns.append(statistics.median(samples))
        # Wasm (wasmtime-py, includes Python->wasmtime call overhead)
        w_ns = []
        for s in ts:
            samples = []
            for _ in range(args.repeat):
                a = time.perf_counter_ns()
                wasm.score(s)
                samples.append(time.perf_counter_ns() - a)
            w_ns.append(statistics.median(samples))
        # native
        nat_t = native_scores(tf, args.repeat)
        n_ns = [nat_t[str(f)][1] for f in tf]
        # Go engine call overhead (stub guest) and real-module invocation, from the engine benchmarks
        bench = subprocess.run(["go", "test", "-run", "^$", "-bench", "InvokeEcho|RealMLDetector", "-benchtime", "2s", "./internal/engine/"],
                               cwd=REPO / "host", capture_output=True, text=True)
        go_bench = {}
        for line in bench.stdout.splitlines():
            m = re.match(r"(Benchmark\w+)-\d+\s+\d+\s+([\d.]+) ns/op", line)
            if m:
                go_bench[m.group(1)] = float(m.group(2))
        lens = [len(s) for s in ts]
        timing = {
            "traces_timed": len(ts), "repeat": args.repeat, "trace_len_median": int(statistics.median(lens)),
            "ns_per_call_median": {"numpy": statistics.median(np_ns), "native_rust": statistics.median(n_ns), "wasm_wasmtime_py": statistics.median(w_ns)},
            "ns_per_call_p90": {"numpy": float(np.percentile(np_ns, 90)), "native_rust": float(np.percentile(n_ns, 90)), "wasm_wasmtime_py": float(np.percentile(w_ns, 90))},
            "calls_per_s_median": {k: 1e9 / v for k, v in {"numpy": statistics.median(np_ns), "native_rust": statistics.median(n_ns), "wasm_wasmtime_py": statistics.median(w_ns)}.items()},
            "go_engine_ns_per_call": go_bench,
            "note": "wasm_wasmtime_py includes the Python-side call and memory copy; go_engine_ns_per_call BenchmarkInvokeEcho is the host engine's own per-call overhead with a trivial guest, RealMLDetector* the full rule on one process event (JSON / raw payload).",
        }
        print("timing:", json.dumps(timing, indent=1))

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    cpu = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    result = {
        "experiment": "E2 same model, three implementations: consistency and single-call latency",
        "provenance": {
            "git_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip(),
            "wasm_sha256": hashlib.sha256(args.wasm.read_bytes()).hexdigest(),
            "weights_sha256": hashlib.sha256(args.weights.read_bytes()).hexdigest(),
            "kernel": platform.release(), "cpu": cpu, "numpy": np.__version__,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "args": {k: str(v) for k, v in vars(args).items()},
        },
        "consistency": consistency, "timing": timing, "elapsed_seconds": round(time.time() - t0, 1),
    }
    (out / "e2_results.json").write_text(json.dumps(result, indent=1))
    md = ["# E2 same model, three implementations", "",
          f"{consistency['traces']} ADFA-LD traces; max |score diff|: NumPy vs Wasm {consistency['max_abs_diff_numpy_vs_wasm']:.2e}, "
          f"NumPy vs native {consistency['max_abs_diff_numpy_vs_native']:.2e}, native vs Wasm {consistency['max_abs_diff_native_vs_wasm']:.2e}; "
          f"decisions at 0.7 agree on {consistency['decisions_agree_at_0.7']['numpy_vs_wasm']}/{consistency['traces']} (NumPy vs Wasm).", ""]
    if timing:
        md += ["| implementation | median ns/call | p90 ns/call | calls/s |", "|---|---|---|---|"]
        for k in ("numpy", "native_rust", "wasm_wasmtime_py"):
            md.append(f"| {k} | {timing['ns_per_call_median'][k]:.0f} | {timing['ns_per_call_p90'][k]:.0f} | {timing['calls_per_s_median'][k]:.0f} |")
        md += ["", "Go engine (`go test -bench`): " + ", ".join(f"{k} {v:.0f} ns/op" for k, v in timing["go_engine_ns_per_call"].items()), ""]
    (out / "e2_summary.md").write_text("\n".join(md) + "\n")
    print(f"wrote {out}/e2_results.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
