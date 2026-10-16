#!/usr/bin/env python3
"""
Comprehensive Experiments for WasmSentinel ML Detector

This script runs multiple experiments to find the best model configuration:
1. Architecture comparison (different hidden layer sizes)
2. Feature engineering experiments
3. Hyperparameter tuning
4. Cross-validation evaluation

Usage:
    python run_experiments.py --data-dir /path/to/ADFA-LD --output-dir ./results
"""

import os
import json
import argparse
import numpy as np
import time
from pathlib import Path
from collections import Counter
from typing import List, Dict, Tuple, Any
from datetime import datetime

# Import from train_mlp
from train_mlp import parse_syscall_trace, extract_features, SimpleMLP, load_adfa_ld


def run_single_experiment(
    X_train: np.ndarray, y_train: np.ndarray,
    X_test: np.ndarray, y_test: np.ndarray,
    hidden_sizes: List[int],
    epochs: int = 150,
    lr: float = 0.005,
    experiment_name: str = "default"
) -> Dict[str, Any]:
    """Run a single experiment and return results."""
    print(f"\n{'='*60}")
    print(f"Experiment: {experiment_name}")
    print(f"Hidden layers: {hidden_sizes}, Epochs: {epochs}, LR: {lr}")
    print('='*60)

    start_time = time.time()

    mlp = SimpleMLP(input_size=64, hidden_sizes=hidden_sizes, output_size=1)
    mlp.train(X_train, y_train, epochs=epochs, lr=lr)

    train_time = time.time() - start_time

    # Evaluate
    tp, fp, tn, fn = 0, 0, 0, 0
    inference_times = []

    for i in range(len(X_test)):
        t0 = time.time()
        pred = mlp.forward(X_test[i])
        inference_times.append(time.time() - t0)

        pred_label = 1 if pred[0] > 0.5 else 0
        true_label = int(y_test[i][0])

        if pred_label == 1 and true_label == 1: tp += 1
        elif pred_label == 1 and true_label == 0: fp += 1
        elif pred_label == 0 and true_label == 0: tn += 1
        else: fn += 1

    accuracy = (tp + tn) / len(X_test)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Calculate model size (approximate)
    model_params = sum(
        layer['weights'].size + layer['biases'].size
        for layer in mlp.layers
    )

    results = {
        'experiment_name': experiment_name,
        'hidden_sizes': hidden_sizes,
        'epochs': epochs,
        'learning_rate': lr,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'train_time_seconds': train_time,
        'avg_inference_time_us': np.mean(inference_times) * 1e6,
        'p99_inference_time_us': np.percentile(inference_times, 99) * 1e6,
        'model_params': model_params,
    }

    print(f"\nResults for {experiment_name}:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  Train time: {train_time:.2f}s")
    print(f"  Inference: {results['avg_inference_time_us']:.2f}us (avg), {results['p99_inference_time_us']:.2f}us (p99)")
    print(f"  Model params: {model_params}")

    return results, mlp


def run_architecture_experiments(X_train, y_train, X_test, y_test) -> List[Dict]:
    """Experiment 1: Compare different model architectures."""
    print("\n" + "="*70)
    print("EXPERIMENT 1: Model Architecture Comparison")
    print("="*70)

    architectures = [
        ([16], "tiny"),
        ([32], "small"),
        ([64], "medium"),
        ([32, 16], "2layer_small"),
        ([64, 32], "2layer_medium"),
        ([64, 32, 16], "3layer"),
        ([128, 64, 32], "3layer_large"),
        ([128, 64, 32, 16], "4layer"),
    ]

    results = []
    best_models = {}

    for hidden_sizes, name in architectures:
        result, model = run_single_experiment(
            X_train, y_train, X_test, y_test,
            hidden_sizes=hidden_sizes,
            epochs=150,
            lr=0.005,
            experiment_name=f"arch_{name}"
        )
        results.append(result)
        best_models[name] = (result, model)

    return results, best_models


def run_hyperparameter_experiments(X_train, y_train, X_test, y_test) -> List[Dict]:
    """Experiment 2: Hyperparameter tuning."""
    print("\n" + "="*70)
    print("EXPERIMENT 2: Hyperparameter Tuning")
    print("="*70)

    # Use the best architecture from experiment 1 (or a reasonable default)
    hidden_sizes = [64, 32]

    hyperparams = [
        (0.001, 100, "lr001_e100"),
        (0.005, 100, "lr005_e100"),
        (0.01, 100, "lr01_e100"),
        (0.005, 200, "lr005_e200"),
        (0.005, 300, "lr005_e300"),
        (0.01, 200, "lr01_e200"),
        (0.001, 300, "lr001_e300"),
    ]

    results = []
    for lr, epochs, name in hyperparams:
        result, _ = run_single_experiment(
            X_train, y_train, X_test, y_test,
            hidden_sizes=hidden_sizes,
            epochs=epochs,
            lr=lr,
            experiment_name=f"hp_{name}"
        )
        results.append(result)

    return results


def run_cross_validation(X, y, hidden_sizes=[64, 32], n_folds=5) -> Dict:
    """Experiment 3: K-fold cross-validation."""
    print("\n" + "="*70)
    print(f"EXPERIMENT 3: {n_folds}-Fold Cross-Validation")
    print("="*70)

    n_samples = len(X)
    indices = np.random.permutation(n_samples)
    fold_size = n_samples // n_folds

    fold_results = []

    for fold in range(n_folds):
        print(f"\n--- Fold {fold + 1}/{n_folds} ---")

        # Split data
        test_start = fold * fold_size
        test_end = test_start + fold_size if fold < n_folds - 1 else n_samples

        test_indices = indices[test_start:test_end]
        train_indices = np.concatenate([indices[:test_start], indices[test_end:]])

        X_train, X_test = X[train_indices], X[test_indices]
        y_train, y_test = y[train_indices], y[test_indices]

        result, _ = run_single_experiment(
            X_train, y_train, X_test, y_test,
            hidden_sizes=hidden_sizes,
            epochs=150,
            lr=0.005,
            experiment_name=f"cv_fold{fold+1}"
        )
        fold_results.append(result)

    # Aggregate results
    avg_results = {
        'experiment_name': f'{n_folds}_fold_cv',
        'hidden_sizes': hidden_sizes,
        'n_folds': n_folds,
        'accuracy_mean': np.mean([r['accuracy'] for r in fold_results]),
        'accuracy_std': np.std([r['accuracy'] for r in fold_results]),
        'precision_mean': np.mean([r['precision'] for r in fold_results]),
        'precision_std': np.std([r['precision'] for r in fold_results]),
        'recall_mean': np.mean([r['recall'] for r in fold_results]),
        'recall_std': np.std([r['recall'] for r in fold_results]),
        'f1_mean': np.mean([r['f1_score'] for r in fold_results]),
        'f1_std': np.std([r['f1_score'] for r in fold_results]),
        'fold_results': fold_results,
    }

    print(f"\n=== Cross-Validation Summary ===")
    print(f"Accuracy:  {avg_results['accuracy_mean']:.4f} (+/- {avg_results['accuracy_std']:.4f})")
    print(f"Precision: {avg_results['precision_mean']:.4f} (+/- {avg_results['precision_std']:.4f})")
    print(f"Recall:    {avg_results['recall_mean']:.4f} (+/- {avg_results['recall_std']:.4f})")
    print(f"F1 Score:  {avg_results['f1_mean']:.4f} (+/- {avg_results['f1_std']:.4f})")

    return avg_results


def run_threshold_experiments(X_train, y_train, X_test, y_test, hidden_sizes=[64, 32]) -> List[Dict]:
    """Experiment 4: Different classification thresholds."""
    print("\n" + "="*70)
    print("EXPERIMENT 4: Classification Threshold Analysis")
    print("="*70)

    # Train model once
    mlp = SimpleMLP(input_size=64, hidden_sizes=hidden_sizes, output_size=1)
    mlp.train(X_train, y_train, epochs=150, lr=0.005)

    # Get predictions
    predictions = []
    true_labels = []
    for i in range(len(X_test)):
        pred = mlp.forward(X_test[i])[0]
        predictions.append(pred)
        true_labels.append(int(y_test[i][0]))

    predictions = np.array(predictions)
    true_labels = np.array(true_labels)

    # Try different thresholds
    thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    results = []

    for threshold in thresholds:
        pred_labels = (predictions >= threshold).astype(int)

        tp = np.sum((pred_labels == 1) & (true_labels == 1))
        fp = np.sum((pred_labels == 1) & (true_labels == 0))
        tn = np.sum((pred_labels == 0) & (true_labels == 0))
        fn = np.sum((pred_labels == 0) & (true_labels == 1))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        results.append({
            'threshold': threshold,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
        })

        print(f"Threshold {threshold:.1f}: P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}")

    return results


def generate_report(all_results: Dict, output_dir: Path):
    """Generate comprehensive experiment report."""
    report = []
    report.append("# WasmSentinel ML Detector - Experiment Report")
    report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("\n---\n")

    # Summary table
    report.append("## Summary of Best Results\n")
    report.append("| Experiment | Architecture | F1 Score | Precision | Recall |")
    report.append("|------------|--------------|----------|-----------|--------|")

    best_f1 = 0
    best_config = None

    for exp_name, results in all_results.items():
        if isinstance(results, list):
            for r in results:
                if 'f1_score' in r and r['f1_score'] > best_f1:
                    best_f1 = r['f1_score']
                    best_config = r
                if 'f1_score' in r and 'experiment_name' in r:
                    arch = str(r.get('hidden_sizes', 'N/A'))
                    report.append(f"| {r['experiment_name']} | {arch} | {r['f1_score']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} |")
        elif isinstance(results, dict):
            if 'f1_mean' in results:
                report.append(f"| {results['experiment_name']} | {results['hidden_sizes']} | {results['f1_mean']:.4f} | {results['precision_mean']:.4f} | {results['recall_mean']:.4f} |")

    report.append("\n---\n")

    # Best configuration
    if best_config:
        report.append("## Best Configuration\n")
        report.append(f"- **Architecture**: {best_config.get('hidden_sizes', 'N/A')}")
        report.append(f"- **F1 Score**: {best_config['f1_score']:.4f}")
        report.append(f"- **Precision**: {best_config['precision']:.4f}")
        report.append(f"- **Recall**: {best_config['recall']:.4f}")
        report.append(f"- **Training Time**: {best_config.get('train_time_seconds', 'N/A'):.2f}s")
        report.append(f"- **Inference Time (avg)**: {best_config.get('avg_inference_time_us', 'N/A'):.2f}us")

    report.append("\n---\n")

    # Architecture comparison
    if 'architecture' in all_results:
        report.append("## Experiment 1: Architecture Comparison\n")
        report.append("| Architecture | Params | F1 | Precision | Recall | Train Time |")
        report.append("|--------------|--------|-----|-----------|--------|------------|")
        for r in sorted(all_results['architecture'], key=lambda x: -x['f1_score']):
            report.append(f"| {r['hidden_sizes']} | {r['model_params']} | {r['f1_score']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} | {r['train_time_seconds']:.1f}s |")

    # Hyperparameter tuning
    if 'hyperparameter' in all_results:
        report.append("\n## Experiment 2: Hyperparameter Tuning\n")
        report.append("| Config | F1 | Precision | Recall |")
        report.append("|--------|-----|-----------|--------|")
        for r in sorted(all_results['hyperparameter'], key=lambda x: -x['f1_score']):
            report.append(f"| {r['experiment_name']} | {r['f1_score']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} |")

    # Cross-validation
    if 'cross_validation' in all_results:
        cv = all_results['cross_validation']
        report.append("\n## Experiment 3: Cross-Validation\n")
        report.append(f"- **Folds**: {cv['n_folds']}")
        report.append(f"- **F1 Score**: {cv['f1_mean']:.4f} (+/- {cv['f1_std']:.4f})")
        report.append(f"- **Precision**: {cv['precision_mean']:.4f} (+/- {cv['precision_std']:.4f})")
        report.append(f"- **Recall**: {cv['recall_mean']:.4f} (+/- {cv['recall_std']:.4f})")

    # Threshold analysis
    if 'threshold' in all_results:
        report.append("\n## Experiment 4: Threshold Analysis\n")
        report.append("| Threshold | F1 | Precision | Recall |")
        report.append("|-----------|-----|-----------|--------|")
        for r in all_results['threshold']:
            report.append(f"| {r['threshold']:.1f} | {r['f1_score']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} |")

    # Save report
    report_path = output_dir / "experiment_report.md"
    report_path.write_text('\n'.join(report))
    print(f"\nReport saved to {report_path}")

    return best_config


def main():
    parser = argparse.ArgumentParser(description='Run comprehensive experiments')
    parser.add_argument('--data-dir', type=str,
                        default='/home/coder-gw/Projects/WasmSentinel/evaluation/datasets/raw/ADFA-LD/ADFA-LD',
                        help='Path to ADFA-LD dataset')
    parser.add_argument('--output-dir', type=str, default='./results',
                        help='Output directory for results')
    parser.add_argument('--quick', action='store_true',
                        help='Run quick experiments only')
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Loading data...")
    X, y = load_adfa_ld(args.data_dir)

    if not X:
        print("No data loaded!")
        return

    X = np.array(X)
    y = np.array(y).reshape(-1, 1)

    # Shuffle and split
    np.random.seed(42)
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]

    split = int(0.8 * len(X))
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    print(f"Dataset: {len(X)} samples ({len(X_train)} train, {len(X_test)} test)")

    all_results = {}

    # Experiment 1: Architecture comparison
    arch_results, best_models = run_architecture_experiments(X_train, y_train, X_test, y_test)
    all_results['architecture'] = arch_results

    if not args.quick:
        # Experiment 2: Hyperparameter tuning
        hp_results = run_hyperparameter_experiments(X_train, y_train, X_test, y_test)
        all_results['hyperparameter'] = hp_results

        # Experiment 3: Cross-validation
        cv_results = run_cross_validation(X, y, hidden_sizes=[64, 32], n_folds=5)
        all_results['cross_validation'] = cv_results

        # Experiment 4: Threshold analysis
        threshold_results = run_threshold_experiments(X_train, y_train, X_test, y_test)
        all_results['threshold'] = threshold_results

    # Save all results
    results_path = output_dir / "all_results.json"
    with open(results_path, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to {results_path}")

    # Generate report
    best_config = generate_report(all_results, output_dir)

    # Export best model weights
    if best_config and 'hidden_sizes' in best_config:
        print(f"\nTraining final model with best config: {best_config['hidden_sizes']}")
        final_mlp = SimpleMLP(input_size=64, hidden_sizes=best_config['hidden_sizes'], output_size=1)
        final_mlp.train(X_train, y_train, epochs=200, lr=0.005)

        weights_path = output_dir / "best_mlp_weights.json"
        weights_path.write_text(final_mlp.export_weights())
        print(f"Best model weights saved to {weights_path}")


if __name__ == '__main__':
    main()
