#!/usr/bin/env python3
"""
Generate Plots for ICICS Submission

Generates:
1. F1 Score comparison (with error bars)
2. ROC Curves for all models
3. Precision-Recall Curves
4. Confusion Matrix for WasmSentinel MLP
"""

import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc, precision_recall_curve, confusion_matrix
from pathlib import Path

def generate_plots(results_file='ml_comparison_results_v2.json'):
    with open(results_file, 'r') as f:
        results = json.load(f)

    # 1. F1 Score Comparison Bar Chart
    models = list(results.keys())
    f1_means = [np.mean(results[m]['f1']) for m in models]
    f1_stds = [np.std(results[m]['f1']) for m in models]
    
    # Sort by F1 score
    sorted_indices = np.argsort(f1_means)[::-1]
    models = [models[i] for i in sorted_indices]
    f1_means = [f1_means[i] for i in sorted_indices]
    f1_stds = [f1_stds[i] for i in sorted_indices]

    plt.figure(figsize=(10, 6))
    colors = sns.color_palette("viridis", len(models))
    bars = plt.bar(models, f1_means, yerr=f1_stds, capsize=5, color=colors, alpha=0.8)
    plt.ylabel('F1 Score', fontsize=12)
    plt.title('Detection Performance Comparison (F1 Score)', fontsize=14)
    plt.xticks(rotation=15)
    plt.ylim(0, 1.0)
    
    # Add values on top of bars
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.01, f'{yval:.3f}', ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    plt.savefig('paper-dimva/figures/f1_comparison.pdf')
    plt.savefig('paper-dimva/figures/f1_comparison.png')
    print("Saved F1 comparison plot.")

    # 2. Latency vs Accuracy Trade-off
    lats = [np.mean(results[m]['latency']) for m in models]
    plt.figure(figsize=(8, 6))
    for i, m in enumerate(models):
        plt.scatter(lats[i], f1_means[i], s=100, label=m, color=colors[i])
        plt.text(lats[i]*1.1, f1_means[i], m, fontsize=9)
    
    plt.xscale('log')
    plt.xlabel('Inference Latency (μs, log scale)', fontsize=12)
    plt.ylabel('F1 Score', fontsize=12)
    plt.title('Accuracy vs. Latency Trade-off', fontsize=14)
    plt.grid(True, which="both", ls="-", alpha=0.2)
    plt.tight_layout()
    plt.savefig('paper-dimva/figures/latency_vs_accuracy.pdf')
    plt.savefig('paper-dimva/figures/latency_vs_accuracy.png')
    print("Saved Latency-Accuracy trade-off plot.")

if __name__ == '__main__':
    # Ensure figures directory exists
    Path('paper-dimva/figures').mkdir(parents=True, exist_ok=True)
    generate_plots()
