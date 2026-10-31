#!/usr/bin/env python3
"""Plot E3: end-to-end latency percentiles and achieved throughput per offered
rate, JSON vs binary, from e3_results.json, for one deep path of ml_detector
(--model rf, the module's default since 2026-10-26, or mlp).

  python3 evaluation/scripts/plot_e3.py --results evaluation/results/2026-11/e3
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(__file__).resolve().parents[2]
STYLE = {"json": dict(color="0.45", ls="--", marker="s"), "binary": dict(color="black", ls="-", marker="o")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=REPO / "evaluation/results/2026-11/e3")
    ap.add_argument("--model", choices=("rf", "mlp"), default="rf",
                    help="ml_detector deep path to plot: rf (the default forest) or mlp; the other is in the table only")
    args = ap.parse_args()
    d = json.loads((args.results / "e3_results.json").read_text())
    cells = {}
    for key, v in d["summary"].items():
        enc, eps, model = (key.split("@") + ["mlp"])[:3]  # "enc@eps" is the MLP, "enc@eps@rf" the forest
        if model != args.model:
            continue
        cells.setdefault(enc, {})[int(eps)] = v
    rates = sorted({eps for c in cells.values() for eps in c})

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.2, 2.7), gridspec_kw={"width_ratios": [3, 2]})
    for enc, by_rate in cells.items():
        xs = [r for r in rates if r in by_rate]
        for pct, alpha in (("p50", 1.0), ("p99", 0.55)):
            ys = [by_rate[r]["e2e_us"][pct]["mean"] / 1000 for r in xs]
            ax1.plot(xs, ys, alpha=alpha, label=f"{enc} {pct}", **STYLE[enc])
    ax1.set_xscale("log"); ax1.set_yscale("log")
    ax1.set_xlabel("offered events/s"); ax1.set_ylabel("end-to-end latency (ms)")
    ax1.set_xticks(rates); ax1.set_xticklabels([f"{r//1000}K" for r in rates])
    ax1.grid(True, which="both", alpha=0.3); ax1.legend(fontsize=7, ncol=2)

    width = 0.38
    for i, (enc, by_rate) in enumerate(sorted(cells.items())):
        xs = [k for k, r in enumerate(rates) if r in by_rate]
        ys = [by_rate[r]["achieved_eps"]["mean"] / 1000 for r in rates if r in by_rate]
        ax2.bar([x + (i - 0.5) * width for x in xs], ys, width, label=enc,
                color="black" if enc == "binary" else "0.6")
    ax2.plot(range(len(rates)), [r / 1000 for r in rates], "k:", lw=1, label="offered")
    ax2.set_xticks(range(len(rates))); ax2.set_xticklabels([f"{r//1000}K" for r in rates])
    ax2.set_xlabel("offered events/s"); ax2.set_ylabel("achieved K events/s")
    ax2.legend(fontsize=7); ax2.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    for ext in ("png", "pdf"):
        out = args.results / f"e3_latency_throughput.{ext}"
        fig.savefig(out, dpi=200)
        print("wrote", out.relative_to(REPO) if out.is_relative_to(REPO) else out)


if __name__ == "__main__":
    main()
