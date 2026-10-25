#!/usr/bin/env python3
"""E3: end-to-end latency and throughput of the host pipeline.

Drives the real binary in replay mode (recorded ADFA-LD syscall traces, one
event per syscall, STIDE trained on Training_Data_Master so the ml_detector
takes its normal fast/deep path mix) at fixed offered rates with both event
encodings, and reads the Pipeline statistics the process prints on exit:
achieved events/s, end-to-end latency percentiles (event creation -> alert
handled: queue wait + detection + output), detection-only percentiles, max
RSS. Each cell is repeated --reps times. Per-alert console logging is off
(--alert-log=false): the output handlers still run, only the terminal write
of every alert is skipped.

The replay collector stands in for the eBPF collector: it produces the same
event objects (same conversion code, binary payload included), so the
measurement covers everything from the collector boundary to the output
handlers. Kernel-side costs are measured separately (E4).

Run on an otherwise idle machine.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def run_once(args, encoding, eps, max_events):
    cmd = [str(args.binary), "--collector=replay", "--replay-file", str(args.replay_dir), "--replay-loop",
           "--replay-eps", str(eps), "--replay-max-events", str(max_events), "--event-encoding", encoding,
           "--rules", str(args.rules), "--metrics-port", "0", "--log-level", "info", "--alert-log=false"]
    if args.train_dir:
        cmd += ["--rule-train-dir", str(args.train_dir)]
    t0 = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, timeout=args.timeout)
    stats, rules = None, {}
    for line in res.stdout.splitlines() + res.stderr.splitlines():
        if '"msg":"Pipeline statistics"' in line:
            stats = json.loads(line)
        elif '"msg":"Rule statistics"' in line:
            j = json.loads(line)
            rules[j["rule"]] = {k: j[k] for k in ("calls", "calls_raw", "threats", "errors", "fuel_total", "latency_max", "memory_bytes") if k in j}
    if stats is None:
        raise RuntimeError(f"no Pipeline statistics in output (rc {res.returncode}):\n{res.stderr[-2000:]}")
    return {
        "encoding": encoding, "offered_eps": eps, "max_events": max_events,
        "events": stats["events"], "alerts": stats["alerts"], "elapsed_s": stats["elapsed_s"],
        "achieved_eps": float(stats["events_per_s"]), "max_rss_kb": stats["max_rss_kb"],
        "e2e_us": stats["e2e_us"], "detect_us": stats["detect_us"], "rules": rules, "wall_s": round(time.time() - t0, 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", type=Path, default=REPO / "wasmsentinel")
    ap.add_argument("--rules", type=Path, default=REPO / "rules/wasm")
    ap.add_argument("--replay-dir", type=Path, default=REPO / "evaluation/datasets/raw/ADFA-LD/ADFA-LD/Attack_Data_Master")
    ap.add_argument("--train-dir", type=Path, default=REPO / "evaluation/datasets/raw/ADFA-LD/ADFA-LD/Training_Data_Master")
    ap.add_argument("--rates", default="1000,10000,50000")
    ap.add_argument("--encodings", default="json,binary")
    ap.add_argument("--seconds", type=float, default=30.0, help="target duration per run (events = rate x seconds)")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--out", type=Path, default=REPO / "evaluation/results/2026-11/e3")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.quick:
        args.rates, args.reps, args.seconds = "1000,10000", 1, 3.0
    rates = [int(r) for r in args.rates.split(",")]
    encodings = args.encodings.split(",")

    runs = []
    for rep in range(args.reps):
        for eps in rates:
            for enc in encodings:
                r = run_once(args, enc, eps, int(eps * args.seconds))
                r["rep"] = rep
                runs.append(r)
                print(f"rep {rep} {enc:6s} offered {eps:6d} achieved {r['achieved_eps']:8.0f} e2e p50 {r['e2e_us']['p50']:6d} p99 {r['e2e_us']['p99']:7d} p999 {r['e2e_us']['p999']:7d} us "
                      f"detect p50 {r['detect_us']['p50']:5d} rss {r['max_rss_kb'] // 1024} MiB ({r['wall_s']} s)", flush=True)

    summary = {}
    for eps in rates:
        for enc in encodings:
            rs = [r for r in runs if r["offered_eps"] == eps and r["encoding"] == enc]
            cell = {"n": len(rs)}
            for key in ("achieved_eps", "max_rss_kb"):
                v = [r[key] for r in rs]
                cell[key] = {"mean": statistics.mean(v), "min": min(v), "max": max(v)}
            for dist in ("e2e_us", "detect_us"):
                cell[dist] = {q: {"mean": statistics.mean(r[dist][q] for r in rs), "max": max(r[dist][q] for r in rs)} for q in ("p50", "p90", "p99", "p999", "max")}
            summary[f"{enc}@{eps}"] = cell

    cpu = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    result = {
        "experiment": "E3 end-to-end latency and throughput (replay collector -> rules -> output)",
        "provenance": {"git_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip(),
                       "kernel": platform.release(), "cpu": cpu, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "args": {k: str(v) for k, v in vars(args).items()}},
        "rules_loaded": sorted({name for r in runs for name in r["rules"]}),
        "summary": summary, "runs": runs,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "e3_results.json").write_text(json.dumps(result, indent=1))
    md = ["# E3 end-to-end latency and throughput", "", f"commit {result['provenance']['git_commit'][:12]}, {result['provenance']['timestamp']}, reps {args.reps}, {args.seconds:.0f} s per run", "",
          "| encoding | offered eps | achieved eps | e2e p50 (us) | e2e p99 | e2e p999 | detect p50 | detect p99 | RSS (MiB) |", "|---|---|---|---|---|---|---|---|---|"]
    for eps in rates:
        for enc in encodings:
            c = summary[f"{enc}@{eps}"]
            md.append(f"| {enc} | {eps} | {c['achieved_eps']['mean']:.0f} | {c['e2e_us']['p50']['mean']:.0f} | {c['e2e_us']['p99']['mean']:.0f} | {c['e2e_us']['p999']['mean']:.0f} | "
                      f"{c['detect_us']['p50']['mean']:.0f} | {c['detect_us']['p99']['mean']:.0f} | {c['max_rss_kb']['mean'] / 1024:.0f} |")
    (args.out / "e3_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main())
