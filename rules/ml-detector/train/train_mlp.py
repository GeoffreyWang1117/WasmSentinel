#!/usr/bin/env python3
"""
MLP Model Training for WasmSentinel

This script trains a lightweight MLP model on ADFA-LD dataset
and exports weights in JSON format for the Rust Wasm module.

Usage:
    python train_mlp.py --data-dir /path/to/ADFA-LD --output weights.json
"""

import os
import json
import argparse
import numpy as np
from pathlib import Path
from collections import Counter
from typing import List, Dict, Tuple

# Syscall categories for feature extraction
SYSCALL_CATEGORIES = {
    'io': ['read', 'write', 'pread', 'pwrite', 'readv', 'writev'],
    'file': ['open', 'openat', 'close', 'creat', 'stat', 'fstat', 'lstat'],
    'memory': ['mmap', 'mprotect', 'munmap', 'brk', 'mremap'],
    'network': ['socket', 'connect', 'bind', 'listen', 'accept', 'sendto', 'recvfrom'],
    'process': ['fork', 'clone', 'execve', 'exit', 'wait4', 'kill'],
    'directory': ['mkdir', 'rmdir', 'unlink', 'rename', 'link', 'symlink'],
    'permission': ['chmod', 'chown', 'fchmod', 'fchown', 'setuid', 'setgid'],
    'control': ['ioctl', 'fcntl', 'select', 'poll', 'epoll'],
}

DANGEROUS_SYSCALLS = [
    'ptrace', 'setuid', 'setgid', 'chroot', 'mount', 'umount',
    'init_module', 'delete_module', 'kexec_load', 'reboot',
]

def parse_syscall_trace(filepath: str) -> List[int]:
    """Parse a syscall trace file and return list of syscall numbers."""
    syscalls = []
    try:
        with open(filepath, 'r') as f:
            content = f.read().strip()
            # ADFA-LD format: space-separated syscall numbers
            parts = content.split()
            for part in parts:
                try:
                    syscall_nr = int(part)
                    syscalls.append(syscall_nr)
                except ValueError:
                    continue
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
    return syscalls


def extract_features(syscalls: List[int], max_features: int = 64) -> np.ndarray:
    """Extract features from syscall number sequence."""
    features = np.zeros(max_features, dtype=np.float32)

    if not syscalls:
        return features

    total = len(syscalls)
    counter = Counter(syscalls)

    # Syscall number categories (based on ADFA-LD syscall list)
    # These are approximate groupings for common syscall numbers
    io_syscalls = {0, 1, 63, 64, 65, 66, 67}  # read, write, etc.
    file_syscalls = {56, 57, 80, 81, 82, 83}  # open, close, stat, etc.
    memory_syscalls = {222, 226, 215, 214}  # mmap, mprotect, etc.
    network_syscalls = {198, 200, 201, 202, 203, 204, 205, 206}  # socket, connect, etc.
    process_syscalls = {220, 221, 93, 94, 129}  # clone, execve, exit, etc.
    dangerous_syscalls = {117, 105, 106, 142, 143, 40, 41, 165, 166}  # ptrace, setuid, setgid, etc.

    # Features 0-5: Category frequencies
    features[0] = sum(counter.get(s, 0) for s in io_syscalls) / total
    features[1] = sum(counter.get(s, 0) for s in file_syscalls) / total
    features[2] = sum(counter.get(s, 0) for s in memory_syscalls) / total
    features[3] = sum(counter.get(s, 0) for s in network_syscalls) / total
    features[4] = sum(counter.get(s, 0) for s in process_syscalls) / total
    features[5] = sum(counter.get(s, 0) for s in dangerous_syscalls) / total

    # Features 6-15: Top 10 most common syscall frequencies (normalized)
    most_common = counter.most_common(10)
    for i, (syscall, count) in enumerate(most_common):
        if i + 6 >= 16:
            break
        features[i + 6] = count / total

    # Features 16-25: Syscall distribution histogram (binned by syscall number)
    for i, syscall_nr in enumerate(syscalls[:min(10, len(syscalls))]):
        if i + 16 >= 26:
            break
        features[i + 16] = syscall_nr / 300.0  # Normalize by max syscall number

    # Features 26-35: Transition features (bigram patterns)
    if len(syscalls) >= 2:
        transitions = Counter(zip(syscalls[:-1], syscalls[1:]))
        most_common_trans = transitions.most_common(10)
        for i, ((s1, s2), count) in enumerate(most_common_trans):
            if i + 26 >= 36:
                break
            features[i + 26] = count / (total - 1)

    # Features 36-45: Statistical features
    features[36] = min(1.0, total / 1000.0)  # Normalized length
    features[37] = len(counter) / max(1, total)  # Unique ratio

    # Entropy
    probs = np.array([c / total for c in counter.values()])
    features[38] = -np.sum(probs * np.log2(probs + 1e-10)) / np.log2(max(2, len(counter)))

    # Burstiness (max / mean)
    if counter:
        counts = list(counter.values())
        features[39] = max(counts) / (sum(counts) / len(counts)) / 10.0

    # Dangerous syscall presence
    features[40] = 1.0 if any(s in dangerous_syscalls for s in syscalls) else 0.0

    # Consecutive same syscall ratio
    consecutive_same = sum(1 for i in range(len(syscalls) - 1) if syscalls[i] == syscalls[i + 1])
    features[41] = consecutive_same / max(1, total - 1)

    # Network after file access pattern (potential exfiltration)
    network_after_file = 0
    for i in range(len(syscalls) - 1):
        if syscalls[i] in file_syscalls and syscalls[i + 1] in network_syscalls:
            network_after_file += 1
    features[42] = network_after_file / max(1, total - 1)

    # Memory operations after process operations (potential injection)
    mem_after_proc = 0
    for i in range(len(syscalls) - 1):
        if syscalls[i] in process_syscalls and syscalls[i + 1] in memory_syscalls:
            mem_after_proc += 1
    features[43] = mem_after_proc / max(1, total - 1)

    # Mean syscall number (normalized)
    features[44] = np.mean(syscalls) / 300.0

    # Std of syscall numbers
    features[45] = np.std(syscalls) / 100.0 if len(syscalls) > 1 else 0.0

    return features


class SimpleMLP:
    """Simple MLP implementation matching the Rust version."""

    def __init__(self, input_size: int = 64, hidden_sizes: List[int] = [32, 16], output_size: int = 1):
        self.input_size = input_size
        self.hidden_sizes = hidden_sizes
        self.output_size = output_size

        # Initialize weights
        self.layers = []
        prev_size = input_size

        for hidden_size in hidden_sizes:
            W = np.random.randn(hidden_size, prev_size).astype(np.float32) * np.sqrt(2.0 / (prev_size + hidden_size))
            b = np.zeros(hidden_size, dtype=np.float32)
            self.layers.append({'weights': W, 'biases': b})
            prev_size = hidden_size

        # Output layer
        W = np.random.randn(output_size, prev_size).astype(np.float32) * np.sqrt(2.0 / (prev_size + output_size))
        b = np.zeros(output_size, dtype=np.float32)
        self.layers.append({'weights': W, 'biases': b})

    def relu(self, x):
        return np.maximum(0, x)

    def sigmoid(self, x):
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

    def forward(self, x: np.ndarray) -> np.ndarray:
        current = x
        for i, layer in enumerate(self.layers):
            current = np.dot(layer['weights'], current) + layer['biases']
            if i < len(self.layers) - 1:
                current = self.relu(current)
            else:
                current = self.sigmoid(current)
        return current

    def train(self, X: np.ndarray, y: np.ndarray, epochs: int = 100, lr: float = 0.001, batch_size: int = 32):
        """Mini-batch gradient descent training with class balancing."""
        n_samples = X.shape[0]

        # Calculate class weights for imbalanced data
        n_positive = np.sum(y)
        n_negative = n_samples - n_positive
        pos_weight = n_samples / (2 * n_positive) if n_positive > 0 else 1.0
        neg_weight = n_samples / (2 * n_negative) if n_negative > 0 else 1.0
        print(f"Class weights: positive={pos_weight:.2f}, negative={neg_weight:.2f}")

        best_f1 = 0
        best_weights = None

        for epoch in range(epochs):
            total_loss = 0

            # Shuffle data
            indices = np.random.permutation(n_samples)
            X_shuffled = X[indices]
            y_shuffled = y[indices]

            for batch_start in range(0, n_samples, batch_size):
                batch_end = min(batch_start + batch_size, n_samples)
                X_batch = X_shuffled[batch_start:batch_end]
                y_batch = y_shuffled[batch_start:batch_end]

                # Accumulate gradients over batch
                grad_w_accum = [np.zeros_like(layer['weights']) for layer in self.layers]
                grad_b_accum = [np.zeros_like(layer['biases']) for layer in self.layers]
                batch_loss = 0

                for i in range(len(X_batch)):
                    x = X_batch[i]
                    target = y_batch[i]

                    # Class weight
                    sample_weight = pos_weight if target[0] == 1 else neg_weight

                    # Forward pass with caching
                    activations = [x]
                    pre_activations = []
                    current = x
                    for j, layer in enumerate(self.layers):
                        z = np.dot(layer['weights'], current) + layer['biases']
                        pre_activations.append(z)
                        if j < len(self.layers) - 1:
                            current = self.relu(z)
                        else:
                            current = self.sigmoid(z)
                        activations.append(current)

                    output = np.clip(current, 1e-7, 1 - 1e-7)
                    loss = -target * np.log(output) - (1 - target) * np.log(1 - output)
                    batch_loss += loss.mean() * sample_weight

                    # Backward pass with class weight
                    delta = (output - target) * sample_weight
                    for j in range(len(self.layers) - 1, -1, -1):
                        prev_activation = activations[j]

                        # Gradient for weights and biases
                        grad_w = np.outer(delta, prev_activation)
                        grad_b = delta.flatten() if delta.ndim > 1 else delta

                        # Accumulate gradients
                        grad_w_accum[j] += grad_w
                        grad_b_accum[j] += grad_b

                        if j > 0:
                            delta = np.dot(self.layers[j]['weights'].T, delta)
                            delta = delta * (pre_activations[j-1] > 0).astype(float)

                # Update weights
                actual_batch_size = len(X_batch)
                for j in range(len(self.layers)):
                    grad_w = np.clip(grad_w_accum[j] / actual_batch_size, -1.0, 1.0)
                    grad_b = np.clip(grad_b_accum[j] / actual_batch_size, -1.0, 1.0)
                    self.layers[j]['weights'] -= lr * grad_w
                    self.layers[j]['biases'] -= lr * grad_b

                total_loss += batch_loss

            # Evaluate on training data periodically
            if epoch % 10 == 0:
                avg_loss = total_loss / n_samples
                tp, fp, tn, fn = 0, 0, 0, 0
                for i in range(min(1000, n_samples)):  # Quick eval on subset
                    pred = self.forward(X[i])[0]
                    pred_label = 1 if pred > 0.5 else 0
                    true_label = int(y[i][0])
                    if pred_label == 1 and true_label == 1: tp += 1
                    elif pred_label == 1 and true_label == 0: fp += 1
                    elif pred_label == 0 and true_label == 0: tn += 1
                    else: fn += 1

                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

                print(f"Epoch {epoch}: Loss={avg_loss:.4f}, P={precision:.3f}, R={recall:.3f}, F1={f1:.3f}")

                if f1 > best_f1:
                    best_f1 = f1
                    best_weights = [(l['weights'].copy(), l['biases'].copy()) for l in self.layers]

        # Restore best weights
        if best_weights:
            for j, (w, b) in enumerate(best_weights):
                self.layers[j]['weights'] = w
                self.layers[j]['biases'] = b
            print(f"Restored best model with F1={best_f1:.3f}")

    def export_weights(self) -> str:
        """Export weights to JSON format for Rust Wasm module."""
        layers_json = []
        for layer in self.layers:
            layers_json.append({
                'weights': layer['weights'].tolist(),
                'biases': layer['biases'].tolist()
            })
        return json.dumps(layers_json, indent=2)


def load_adfa_ld(data_dir: str) -> Tuple[List[np.ndarray], List[int]]:
    """Load ADFA-LD dataset."""
    X = []
    y = []

    data_path = Path(data_dir)

    # Load normal data (Training_Data_Master and Validation_Data_Master)
    normal_dirs = ['Training_Data_Master', 'Validation_Data_Master']
    for dir_name in normal_dirs:
        dir_path = data_path / dir_name
        if dir_path.exists():
            for trace_file in dir_path.glob('*'):
                if trace_file.is_file():
                    syscalls = parse_syscall_trace(str(trace_file))
                    if syscalls:
                        features = extract_features(syscalls)
                        X.append(features)
                        y.append(0)  # Normal

    print(f"Loaded {len(X)} normal traces")

    # Load attack data (Attack_Data_Master)
    attack_dir = data_path / 'Attack_Data_Master'
    if attack_dir.exists():
        for attack_type in attack_dir.iterdir():
            if attack_type.is_dir():
                for trace_file in attack_type.glob('*'):
                    if trace_file.is_file():
                        syscalls = parse_syscall_trace(str(trace_file))
                        if syscalls:
                            features = extract_features(syscalls)
                            X.append(features)
                            y.append(1)  # Attack

    attack_count = sum(y)
    print(f"Loaded {attack_count} attack traces")

    return X, y


def main():
    parser = argparse.ArgumentParser(description='Train MLP model for WasmSentinel')
    parser.add_argument('--data-dir', type=str,
                        default='/home/coder-gw/Projects/WasmSentinel/evaluation/datasets/raw/ADFA-LD',
                        help='Path to ADFA-LD dataset')
    parser.add_argument('--output', type=str, default='mlp_weights.json',
                        help='Output path for weights JSON')
    parser.add_argument('--epochs', type=int, default=100,
                        help='Number of training epochs')
    parser.add_argument('--lr', type=float, default=0.01,
                        help='Learning rate')
    parser.add_argument('--hidden', type=str, default='32,16',
                        help='Hidden layer sizes (comma-separated)')
    args = parser.parse_args()

    hidden_sizes = [int(x) for x in args.hidden.split(',')]

    print(f"Loading data from {args.data_dir}...")
    X, y = load_adfa_ld(args.data_dir)

    if not X:
        print("No data loaded! Check data directory path.")
        return

    X = np.array(X)
    y = np.array(y).reshape(-1, 1)

    print(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"Class distribution: {np.sum(y == 0)} normal, {np.sum(y == 1)} attack")

    # Shuffle and split
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]

    split = int(0.8 * len(X))
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    print(f"\nTraining MLP with hidden layers: {hidden_sizes}")
    mlp = SimpleMLP(input_size=64, hidden_sizes=hidden_sizes, output_size=1)
    mlp.train(X_train, y_train, epochs=args.epochs, lr=args.lr)

    # Evaluate
    correct = 0
    tp, fp, tn, fn = 0, 0, 0, 0

    for i in range(len(X_test)):
        pred = mlp.forward(X_test[i])
        pred_label = 1 if pred[0] > 0.5 else 0
        true_label = int(y_test[i][0])

        if pred_label == true_label:
            correct += 1

        if pred_label == 1 and true_label == 1:
            tp += 1
        elif pred_label == 1 and true_label == 0:
            fp += 1
        elif pred_label == 0 and true_label == 0:
            tn += 1
        else:
            fn += 1

    accuracy = correct / len(X_test)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n=== Evaluation Results ===")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")

    # Export weights
    weights_json = mlp.export_weights()
    output_path = Path(args.output)
    output_path.write_text(weights_json)
    print(f"\nWeights exported to {args.output}")
    print(f"File size: {output_path.stat().st_size} bytes")


if __name__ == '__main__':
    main()
