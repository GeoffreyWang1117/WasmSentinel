#!/usr/bin/env python3
"""Generate LaTeX macros for every number the paper cites, straight from the
result JSONs under evaluation/results/2026-11. Missing experiments produce
macros that render as \\textbf{??} so a stale draft is visible, never wrong.

  python3 evaluation/scripts/paper_numbers.py --out paper-asiaccs/tables/numbers.tex
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


class Macros:
    def __init__(self):
        self.lines = []

    def add(self, name, value, fmt="{}"):
        if value is None:
            body = r"\textbf{??}"
        else:
            body = fmt.format(value)
        # macro names may only contain letters
        assert name.isalpha(), name
        self.lines.append(f"\\newcommand{{\\{name}}}{{{body}}}")

    def text(self, header):
        return header + "\n".join(self.lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=REPO / "evaluation/results/2026-11")
    ap.add_argument("--out", type=Path, default=REPO / "paper-asiaccs/tables/numbers.tex")
    args = ap.parse_args()
    R = args.results
    m = Macros()
    commits = {}

    # ---- E6 isolation
    iso = load(R / "isolation/isolation.json")
    m.add("isoContained", iso and iso["contained"])
    m.add("isoTotal", iso and iso["total"])
    m.add("isoModules", iso and len({c["module"] for c in iso["cases"]}))
    m.add("isoMemoryCapMiB", iso and iso["limits"]["memory_bytes"] // (1 << 20))
    m.add("isoFuel", iso and iso["limits"]["fuel"], "{:,}")
    m.add("isoTimeout", iso and iso["limits"]["timeout"])

    # ---- parity (P1.4)
    par = (R / "parity/parity.txt")
    ptxt = par.read_text() if par.exists() else ""
    import re
    mm = re.search(r"inputs: (\d+)", ptxt)
    m.add("parityInputs", int(mm.group(1)) if mm else None, "{:,}")
    mm = re.search(r"max \|score diff\|\s*=\s*([\d.e+-]+)", ptxt)
    m.add("parityMaxScoreDiff", float(mm.group(1)) if mm else None, "{:.1e}")

    # ---- E1
    e1 = load(R / "e1/e1_results.json")
    if e1:
        commits["e1"] = e1["provenance"]["git_commit"][:12]
        m.add("eOneNormal", e1["dataset"]["normal"], "{:,}")
        m.add("eOneAttack", e1["dataset"]["attack"])
        m.add("eOneFolds", e1["provenance"]["args"]["folds"])
        m.add("eOneSeeds", e1["provenance"]["args"]["seeds"])
        names = {"wasmsentinel_mlp": "Mlp", "stide": "Stide", "iforest": "IForest", "rf": "Rf", "lstm": "Lstm"}
        for key, suf in names.items():
            s = e1["summary"].get(key)
            m.add(f"eOneAuprc{suf}", s and s["auprc"]["mean"], "{:.3f}")
            m.add(f"eOneAuprcStd{suf}", s and s["auprc"]["std"], "{:.3f}")
            m.add(f"eOneAuroc{suf}", s and s["roc_auc"]["mean"], "{:.3f}")
            m.add(f"eOneRecallFprFive{suf}", s and s["recall_at_fpr5"]["mean"], "{:.3f}")
            m.add(f"eOneRecallFprOne{suf}", s and s["recall_at_fpr1"]["mean"], "{:.3f}")
            m.add(f"eOneFOneOpFive{suf}", s and s["op_fpr5_f1"]["mean"], "{:.3f}")
        for key, suf in names.items():
            if key == "wasmsentinel_mlp":
                continue
            pz = e1["paired_vs_wasmsentinel_auprc"].get(key)
            m.add(f"eOneDiff{suf}", pz and pz["auprc_diff_mean"], "{:+.3f}")
            m.add(f"eOneDiffCiLo{suf}", pz and pz["ci95"][0], "{:+.3f}")
            m.add(f"eOneDiffCiHi{suf}", pz and pz["ci95"][1], "{:+.3f}")
        diffs = [max(r["info"].get("wasm_vs_numpy_max_abs_diff", 0) for r in e1["runs"] if r["model"] == "wasmsentinel_mlp")] if e1["runs"] else [None]
        m.add("eOneWasmNumpyMaxDiff", diffs[0], "{:.1e}")
    else:
        for name in ("eOneNormal", "eOneAttack", "eOneAuprcMlp", "eOneAuprcRf", "eOneAuprcLstm", "eOneAuprcStide", "eOneAuprcIForest"):
            m.add(name, None)

    # ---- E2
    e2 = load(R / "e2/e2_results.json")
    if e2:
        commits["e2"] = e2["provenance"]["git_commit"][:12]
        c = e2["consistency"]
        m.add("eTwoTraces", c["traces"], "{:,}")
        m.add("eTwoMaxDiffNumpyWasm", c["max_abs_diff_numpy_vs_wasm"], "{:.1e}")
        m.add("eTwoMaxDiffNativeWasm", c["max_abs_diff_native_vs_wasm"], "{:.1e}")
        t = e2.get("timing")
        for k, suf in (("numpy", "Numpy"), ("native_rust", "Native"), ("wasm_wasmtime_py", "Wasm")):
            m.add(f"eTwoUsPerCall{suf}", t and t["ns_per_call_median"][k] / 1000, "{:.1f}")
        gb = (t or {}).get("go_engine_ns_per_call", {})
        m.add("eTwoEngineOverheadUs", gb.get("BenchmarkInvokeEcho") and gb["BenchmarkInvokeEcho"] / 1000, "{:.1f}")
        m.add("eTwoMlJsonUs", gb.get("BenchmarkRealMLDetectorJSON") and gb["BenchmarkRealMLDetectorJSON"] / 1000, "{:.1f}")
        m.add("eTwoMlRawUs", gb.get("BenchmarkRealMLDetectorRaw") and gb["BenchmarkRealMLDetectorRaw"] / 1000, "{:.1f}")
    else:
        for name in ("eTwoTraces", "eTwoMaxDiffNumpyWasm", "eTwoUsPerCallWasm", "eTwoEngineOverheadUs"):
            m.add(name, None)

    # ---- E3
    e3 = load(R / "e3/e3_results.json")
    if e3:
        commits["e3"] = e3["provenance"]["git_commit"][:12]
        for cell, v in e3["summary"].items():
            enc, eps = cell.split("@")
            suf = {"json": "Json", "binary": "Bin"}[enc] + {1000: "OneK", 10000: "TenK", 50000: "FiftyK"}.get(int(eps), "X")
            m.add(f"eThreeAchieved{suf}", v["achieved_eps"]["mean"], "{:,.0f}")
            m.add(f"eThreePFifty{suf}", v["e2e_us"]["p50"]["mean"], "{:,.0f}")
            m.add(f"eThreePNinetyNine{suf}", v["e2e_us"]["p99"]["mean"], "{:,.0f}")
            m.add(f"eThreePNineNineNine{suf}", v["e2e_us"]["p999"]["mean"], "{:,.0f}")
            m.add(f"eThreeRssMiB{suf}", v["max_rss_kb"]["mean"] / 1024, "{:.0f}")
    else:
        m.add("eThreeAchievedBinTenK", None)

    # ---- E4
    e4 = load(R / "e4/e4_results.json")
    if e4:
        commits["e4"] = e4["provenance"]["git_commit"][:12]
        wl_suf = {"nginx": "Nginx", "redis": "Redis", "postgres": "Pg"}
        arm_suf = {"none": "None", "wasmsentinel": "Ws", "falco": "Falco", "tetragon": "Tetragon"}
        for wl, arms in e4["summary"].items():
            for arm, c in arms.items():
                suf = wl_suf.get(wl, wl.title()) + arm_suf.get(arm, arm.title())
                m.add(f"eFourTput{suf}", c["throughput_mean"], "{:,.0f}")
                m.add(f"eFourDelta{suf}", c.get("throughput_delta_pct_mean"), "{:+.1f}")
                m.add(f"eFourCpu{suf}", c["monitor_cpu_pct_mean"], "{:.1f}")
                m.add(f"eFourRss{suf}", c["monitor_rss_mib_max"], "{:.0f}")
    else:
        m.add("eFourDeltaNginxWs", None)

    # ---- E5
    e5 = load(R / "e5/e5_results.json")
    if e5:
        commits["e5"] = e5["provenance"]["git_commit"][:12]
        sys_suf = {"wasmsentinel": "Ws", "falco": "Falco", "tetragon": "Tetragon"}
        sc_suf = {"shadow": "Shadow", "tmpexec": "TmpExec", "connect": "Connect"}
        m.add("eFiveTrials", e5["provenance"]["args"]["trials"])
        for system, r in e5["results"].items():
            for sc, p in r["scenarios"].items():
                suf = sys_suf[system] + sc_suf[sc]
                m.add(f"eFiveDetected{suf}", p["detected"])
                m.add(f"eFiveLatency{suf}", p["latency_ms"] and p["latency_ms"]["median"], "{:.1f}")
            m.add(f"eFiveRss{sys_suf[system]}", r["resources"].get("rss_kb_max", 0) / 1024, "{:.0f}")
            m.add(f"eFiveCpu{sys_suf[system]}", r["resources"].get("cpu_pct_mean"), "{:.1f}")
    else:
        m.add("eFiveDetectedWsShadow", None)

    header = "% Generated by evaluation/scripts/paper_numbers.py from " + str(R.relative_to(REPO)) + "\n% commits: " + ", ".join(f"{k}={v}" for k, v in sorted(commits.items())) + "\n% Do not edit; run `make numbers` in paper-asiaccs/.\n"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(m.text(header))
    missing = sum(1 for l in m.lines if "??" in l)
    print(f"wrote {args.out}: {len(m.lines)} macros, {missing} still missing")


if __name__ == "__main__":
    main()
