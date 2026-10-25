#!/usr/bin/env python3
"""Plot the E1 mean precision-recall curves from e1_pr_curves.json."""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=REPO / "evaluation/results/2026-11/e1")
    args = ap.parse_args()
    curves = json.loads((args.results / "e1_pr_curves.json").read_text())
    summary = json.loads((args.results / "e1_results.json").read_text())["summary"]

    fig, ax = plt.subplots(figsize=(4.2, 3.4))
    styles = {"wasmsentinel_rf": ("k", "-"), "wasmsentinel_mlp": ("k", "--"), "rf": ("0.35", "--"), "lstm": ("0.35", "-."),
              "stide": ("0.6", ":"), "iforest": ("0.75", "--")}
    labels = {"wasmsentinel_rf": "WasmSentinel RF (Wasm)", "wasmsentinel_mlp": "WasmSentinel MLP (Wasm)", "rf": "Random Forest (scikit-learn)",
              "lstm": "LSTM", "stide": "STIDE 6-gram", "iforest": "Isolation Forest"}
    for name, c in curves.items():
        if name == "rf" and "wasmsentinel_rf" in curves:
            continue  # the same forest scored by scikit-learn; the curves coincide
        color, ls = styles.get(name, ("0.5", "-"))
        r = c["recall"]
        p = c["precision_mean"]
        s = c["precision_std"]
        ax.plot(r, p, color=color, ls=ls, lw=1.6 if name.startswith("wasmsentinel_") else 1.1,
                label=f"{labels.get(name, name.replace('_', ' '))} (AUPRC {summary[name]['auprc']['mean']:.2f})")
        ax.fill_between(r, [max(0, a - b) for a, b in zip(p, s)], [min(1, a + b) for a, b in zip(p, s)], color=color, alpha=0.08, lw=0)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.grid(alpha=0.3, lw=0.5)
    ax.legend(fontsize=7, frameon=False, loc="lower left")
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(args.results / f"e1_pr_curves.{ext}", dpi=200)
    print("wrote", args.results / "e1_pr_curves.pdf")


if __name__ == "__main__":
    main()
