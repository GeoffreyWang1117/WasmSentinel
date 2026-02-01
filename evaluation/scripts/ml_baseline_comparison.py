#!/usr/bin/env python3
"""
ML Baseline Comparison for WasmSentinel DIMVA Paper

Compare WasmSentinel's MLP with other ML approaches:
1. Random Forest (traditional ML)
2. LSTM (deep learning)
3. Autoencoder (unsupervised)
4. WasmSentinel MLP (our approach)

Usage:
    python ml_baseline_comparison.py --data-dir /path/to/ADFA-LD
"""

import argparse
import json
import os
import sys
import time
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')

# Check for required packages
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report
    )
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("Warning: scikit-learn not installed, some baselines unavailable")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    print("Warning: PyTorch not installed, neural network baselines unavailable")


# ============================================================
# Feature Extraction (same as WasmSentinel)
# ============================================================

def load_adfa_ld(data_dir: str) -> Tuple[List[List[int]], List[int]]:
    """Load ADFA-LD dataset"""
    data_path = Path(data_dir)
    sequences = []
    labels = []

    # Normal training data
    normal_dirs = [
        data_path / "Training_Data_Master",
        data_path / "Validation_Data_Master"
    ]

    for normal_dir in normal_dirs:
        if normal_dir.exists():
            for f in normal_dir.glob("*.txt"):
                try:
                    with open(f, 'r') as fp:
                        syscalls = [int(x) for x in fp.read().split()]
                        if len(syscalls) >= 10:
                            sequences.append(syscalls)
                            labels.append(0)  # Normal
                except:
                    pass

    # Attack data
    attack_dir = data_path / "Attack_Data_Master"
    if attack_dir.exists():
        for attack_type in attack_dir.iterdir():
            if attack_type.is_dir():
                for f in attack_type.glob("*.txt"):
                    try:
                        with open(f, 'r') as fp:
                            syscalls = [int(x) for x in fp.read().split()]
                            if len(syscalls) >= 10:
                                sequences.append(syscalls)
                                labels.append(1)  # Attack
                    except:
                        pass

    print(f"Loaded {len(sequences)} sequences ({sum(1 for l in labels if l == 0)} normal, {sum(1 for l in labels if l == 1)} attack)")
    return sequences, labels


def extract_features(sequences: List[List[int]],
                     feature_dim: int = 340,
                     ngram_size: int = 3) -> np.ndarray:
    """Extract features from syscall sequences (same as WasmSentinel)"""

    features = []

    for seq in sequences:
        feat = np.zeros(feature_dim, dtype=np.float32)

        # 1. Syscall frequency histogram (0-255 mapped to 0-99)
        counter = Counter(seq)
        total = len(seq)
        for syscall, count in counter.items():
            idx = min(syscall % 100, 99)
            feat[idx] += count / total

        # 2. N-gram features (100-199)
        if len(seq) >= ngram_size:
            ngrams = []
            for i in range(len(seq) - ngram_size + 1):
                ngram = tuple(seq[i:i+ngram_size])
                ngrams.append(ngram)
            ngram_counter = Counter(ngrams)
            for ngram, count in ngram_counter.most_common(50):
                idx = 100 + (hash(ngram) % 100)
                feat[idx] += count / len(ngrams)

        # 3. Statistical features (200-239)
        if len(seq) > 0:
            feat[200] = len(seq) / 10000  # Normalized length
            feat[201] = len(set(seq)) / 256  # Unique syscalls ratio
            feat[202] = np.mean(seq) / 256  # Mean syscall number
            feat[203] = np.std(seq) / 256 if len(seq) > 1 else 0  # Std dev
            feat[204] = np.median(seq) / 256  # Median

            # Transition entropy
            if len(seq) > 1:
                transitions = [(seq[i], seq[i+1]) for i in range(len(seq)-1)]
                trans_counter = Counter(transitions)
                probs = [c/len(transitions) for c in trans_counter.values()]
                entropy = -sum(p * np.log2(p + 1e-10) for p in probs)
                feat[205] = entropy / 16  # Normalized entropy

        # 4. Sequence patterns (240-339)
        # Burst detection
        if len(seq) > 10:
            for i in range(0, len(seq) - 10, 10):
                window = seq[i:i+10]
                if len(set(window)) <= 2:  # Burst pattern
                    feat[240 + (i // 10) % 50] += 1

        features.append(feat)

    return np.array(features, dtype=np.float32)


# ============================================================
# ML Models
# ============================================================

class SimpleMLP(nn.Module):
    """Simple MLP (same architecture as WasmSentinel)"""

    def __init__(self, input_dim: int = 340, hidden_dims: List[int] = [128, 64, 32, 16]):
        super().__init__()
        layers = []
        prev_dim = input_dim

        for dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, dim))
            layers.append(nn.ReLU())
            layers.append(nn.Dropout(0.3))
            prev_dim = dim

        layers.append(nn.Linear(prev_dim, 1))
        layers.append(nn.Sigmoid())

        self.network = nn.Sequential(*layers)

    def forward(self, x):
        return self.network(x)


class SimpleLSTM(nn.Module):
    """LSTM for sequence classification"""

    def __init__(self, vocab_size: int = 512, embed_dim: int = 32,
                 hidden_dim: int = 64, num_layers: int = 2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers,
                           batch_first=True, dropout=0.3, bidirectional=True)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 32),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        x = self.embedding(x)
        _, (h_n, _) = self.lstm(x)
        h_n = torch.cat([h_n[-2], h_n[-1]], dim=1)
        return self.fc(h_n)


class SimpleAutoencoder(nn.Module):
    """Autoencoder for anomaly detection"""

    def __init__(self, input_dim: int = 340, latent_dim: int = 32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, latent_dim),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)


# ============================================================
# Training Functions
# ============================================================

def train_mlp(X_train, y_train, X_test, y_test,
              hidden_dims=[128, 64, 32, 16], epochs=100, lr=0.01):
    """Train MLP classifier"""

    if not HAS_TORCH:
        return None

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # Prepare data
    X_train_t = torch.FloatTensor(X_train).to(device)
    y_train_t = torch.FloatTensor(y_train).unsqueeze(1).to(device)
    X_test_t = torch.FloatTensor(X_test).to(device)

    train_dataset = TensorDataset(X_train_t, y_train_t)
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)

    # Model
    model = SimpleMLP(input_dim=X_train.shape[1], hidden_dims=hidden_dims).to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    # Train
    start_time = time.time()
    model.train()
    for epoch in range(epochs):
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

    training_time = time.time() - start_time

    # Inference
    model.eval()
    with torch.no_grad():
        start_time = time.time()
        for _ in range(10):  # 10 iterations for stable measurement
            outputs = model(X_test_t)
        inference_time = (time.time() - start_time) / 10 / len(X_test) * 1000000  # μs per sample

        y_pred = (outputs.cpu().numpy() > 0.5).astype(int).flatten()

    return y_pred, training_time, inference_time


def train_lstm(sequences, labels, test_sequences, test_labels,
               max_len=500, epochs=50, lr=0.001):
    """Train LSTM classifier"""

    if not HAS_TORCH:
        return None

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # Pad sequences
    def pad_sequences(seqs, max_len):
        result = []
        for seq in seqs:
            if len(seq) > max_len:
                seq = seq[:max_len]
            else:
                seq = seq + [0] * (max_len - len(seq))
            # Clip to vocab size
            seq = [min(s, 511) for s in seq]
            result.append(seq)
        return np.array(result)

    X_train = pad_sequences(sequences, max_len)
    X_test = pad_sequences(test_sequences, max_len)

    X_train_t = torch.LongTensor(X_train).to(device)
    y_train_t = torch.FloatTensor(labels).unsqueeze(1).to(device)
    X_test_t = torch.LongTensor(X_test).to(device)

    train_dataset = TensorDataset(X_train_t, y_train_t)
    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)

    # Model
    model = SimpleLSTM().to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    # Train
    start_time = time.time()
    model.train()
    for epoch in range(epochs):
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

    training_time = time.time() - start_time

    # Inference
    model.eval()
    with torch.no_grad():
        start_time = time.time()
        for _ in range(5):
            outputs = model(X_test_t)
        inference_time = (time.time() - start_time) / 5 / len(X_test) * 1000000  # μs

        y_pred = (outputs.cpu().numpy() > 0.5).astype(int).flatten()

    return y_pred, training_time, inference_time


def train_autoencoder(X_train_normal, X_test, y_test, epochs=100, lr=0.001):
    """Train Autoencoder for anomaly detection"""

    if not HAS_TORCH:
        return None

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    X_train_t = torch.FloatTensor(X_train_normal).to(device)
    X_test_t = torch.FloatTensor(X_test).to(device)

    train_dataset = TensorDataset(X_train_t, X_train_t)
    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)

    model = SimpleAutoencoder(input_dim=X_train_normal.shape[1]).to(device)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    # Train on normal data only
    start_time = time.time()
    model.train()
    for epoch in range(epochs):
        for batch_x, _ in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_x)
            loss.backward()
            optimizer.step()

    training_time = time.time() - start_time

    # Inference - use reconstruction error as anomaly score
    model.eval()
    with torch.no_grad():
        start_time = time.time()
        for _ in range(10):
            reconstructed = model(X_test_t)
        inference_time = (time.time() - start_time) / 10 / len(X_test) * 1000000

        # Compute reconstruction error
        errors = torch.mean((X_test_t - reconstructed) ** 2, dim=1).cpu().numpy()

        # Use threshold (e.g., 95th percentile of normal data errors)
        train_reconstructed = model(X_train_t)
        train_errors = torch.mean((X_train_t - train_reconstructed) ** 2, dim=1).cpu().numpy()
        threshold = np.percentile(train_errors, 95)

        y_pred = (errors > threshold).astype(int)

    return y_pred, training_time, inference_time


def train_random_forest(X_train, y_train, X_test):
    """Train Random Forest classifier"""

    if not HAS_SKLEARN:
        return None

    model = RandomForestClassifier(n_estimators=100, max_depth=10,
                                   random_state=42, n_jobs=-1)

    start_time = time.time()
    model.fit(X_train, y_train)
    training_time = time.time() - start_time

    start_time = time.time()
    for _ in range(10):
        y_pred = model.predict(X_test)
    inference_time = (time.time() - start_time) / 10 / len(X_test) * 1000000

    return y_pred, training_time, inference_time


# ============================================================
# Main Evaluation
# ============================================================

def evaluate_predictions(y_true, y_pred):
    """Compute evaluation metrics"""
    return {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, zero_division=0)),
        'f1': float(f1_score(y_true, y_pred, zero_division=0)),
        'confusion_matrix': confusion_matrix(y_true, y_pred).tolist()
    }


def main():
    parser = argparse.ArgumentParser(description='ML Baseline Comparison')
    parser.add_argument('--data-dir', type=str, required=True,
                        help='Path to ADFA-LD dataset')
    parser.add_argument('--output', '-o', type=str,
                        default='ml_comparison_results.json',
                        help='Output file')

    args = parser.parse_args()

    print("=" * 60)
    print("WasmSentinel ML Baseline Comparison")
    print("=" * 60)

    # Load data
    print("\n[1/6] Loading ADFA-LD dataset...")
    sequences, labels = load_adfa_ld(args.data_dir)

    if len(sequences) == 0:
        print("ERROR: No data loaded")
        return 1

    # Extract features
    print("\n[2/6] Extracting features...")
    X = extract_features(sequences)
    y = np.array(labels)

    # Normalize
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Train/test split (stratified)
    np.random.seed(42)
    indices = np.random.permutation(len(X))
    split = int(0.8 * len(X))
    train_idx, test_idx = indices[:split], indices[split:]

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    # Get normal training data for autoencoder
    normal_train_mask = y_train == 0
    X_train_normal = X_train[normal_train_mask]

    # Get raw sequences for LSTM
    train_sequences = [sequences[i] for i in train_idx]
    test_sequences = [sequences[i] for i in test_idx]

    print(f"Training: {len(X_train)} samples ({sum(y_train)} attacks)")
    print(f"Testing: {len(X_test)} samples ({sum(y_test)} attacks)")

    results = {
        'timestamp': datetime.now().isoformat(),
        'dataset': 'ADFA-LD',
        'train_samples': len(X_train),
        'test_samples': len(X_test),
        'models': {}
    }

    # ============================================================
    # 1. Random Forest
    # ============================================================
    print("\n[3/6] Training Random Forest...")
    if HAS_SKLEARN:
        y_pred_rf, train_time_rf, infer_time_rf = train_random_forest(X_train, y_train, X_test)
        metrics_rf = evaluate_predictions(y_test, y_pred_rf)
        results['models']['random_forest'] = {
            **metrics_rf,
            'training_time_sec': train_time_rf,
            'inference_time_us': infer_time_rf,
            'model_type': 'Traditional ML'
        }
        print(f"  F1: {metrics_rf['f1']:.4f}, Inference: {infer_time_rf:.1f} μs/sample")
    else:
        print("  Skipped (sklearn not available)")

    # ============================================================
    # 2. MLP (WasmSentinel approach)
    # ============================================================
    print("\n[4/6] Training MLP (WasmSentinel)...")
    if HAS_TORCH:
        y_pred_mlp, train_time_mlp, infer_time_mlp = train_mlp(
            X_train, y_train, X_test, y_test,
            hidden_dims=[128, 64, 32, 16], epochs=100, lr=0.01
        )
        metrics_mlp = evaluate_predictions(y_test, y_pred_mlp)
        results['models']['mlp_wasmsentinel'] = {
            **metrics_mlp,
            'training_time_sec': train_time_mlp,
            'inference_time_us': infer_time_mlp,
            'model_type': 'Lightweight Neural Network',
            'architecture': '[128, 64, 32, 16]'
        }
        print(f"  F1: {metrics_mlp['f1']:.4f}, Inference: {infer_time_mlp:.1f} μs/sample")
    else:
        print("  Skipped (PyTorch not available)")

    # ============================================================
    # 3. LSTM
    # ============================================================
    print("\n[5/6] Training LSTM...")
    if HAS_TORCH:
        y_pred_lstm, train_time_lstm, infer_time_lstm = train_lstm(
            train_sequences, y_train.tolist(),
            test_sequences, y_test.tolist(),
            epochs=30
        )
        metrics_lstm = evaluate_predictions(y_test, y_pred_lstm)
        results['models']['lstm'] = {
            **metrics_lstm,
            'training_time_sec': train_time_lstm,
            'inference_time_us': infer_time_lstm,
            'model_type': 'Deep Learning (Sequential)'
        }
        print(f"  F1: {metrics_lstm['f1']:.4f}, Inference: {infer_time_lstm:.1f} μs/sample")
    else:
        print("  Skipped (PyTorch not available)")

    # ============================================================
    # 4. Autoencoder
    # ============================================================
    print("\n[6/6] Training Autoencoder...")
    if HAS_TORCH:
        y_pred_ae, train_time_ae, infer_time_ae = train_autoencoder(
            X_train_normal, X_test, y_test, epochs=50
        )
        metrics_ae = evaluate_predictions(y_test, y_pred_ae)
        results['models']['autoencoder'] = {
            **metrics_ae,
            'training_time_sec': train_time_ae,
            'inference_time_us': infer_time_ae,
            'model_type': 'Unsupervised (Reconstruction)'
        }
        print(f"  F1: {metrics_ae['f1']:.4f}, Inference: {infer_time_ae:.1f} μs/sample")
    else:
        print("  Skipped (PyTorch not available)")

    # Save results
    output_path = Path(args.output)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 60)
    print("COMPARISON COMPLETE")
    print("=" * 60)
    print(f"Results saved to: {output_path}")

    # Summary table
    print("\nModel Comparison Summary:")
    print("-" * 70)
    print(f"{'Model':<20} {'F1':>8} {'Precision':>10} {'Recall':>8} {'Latency':>12}")
    print("-" * 70)

    for name, data in results['models'].items():
        print(f"{name:<20} {data['f1']:>8.4f} {data['precision']:>10.4f} "
              f"{data['recall']:>8.4f} {data['inference_time_us']:>10.1f} μs")

    return 0


if __name__ == '__main__':
    sys.exit(main())
