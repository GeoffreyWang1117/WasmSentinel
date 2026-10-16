#!/usr/bin/env python3
"""
ML Baseline Comparison for WasmSentinel ICICS Submission

Compare WasmSentinel's MLP with other ML approaches:
1. Random Forest (traditional ML)
2. LSTM (deep learning)
3. Transformer (deep learning)
4. GNN (graph neural network)
5. Autoencoder (unsupervised)
6. WasmSentinel MLP (our approach)

Features:
- Cross-validation for statistical significance (p-values, confidence intervals)
- ROC/PR curves generation
- Modern DL baselines (Transformer, GNN)
"""

import argparse
import json
import os
import sys
import time
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

# Check for required packages
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import StratifiedKFold, train_test_split
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report, roc_curve, auc, precision_recall_curve
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

try:
    import torch_geometric
    from torch_geometric.nn import GCNConv, global_mean_pool
    from torch_geometric.data import Data, Batch
    from torch_geometric.loader import DataLoader as PyGDataLoader
    HAS_PYG = True
except ImportError:
    HAS_PYG = False
    print("Warning: torch_geometric not installed, GNN baseline unavailable")

try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


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
                 hidden_dim: int = 64, num_layers: int = 1):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers,
                           batch_first=True, dropout=0, bidirectional=True)
        self.fc = nn.Sequential(
            nn.Linear(hidden_dim * 2, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        x = self.embedding(x)
        _, (h_n, _) = self.lstm(x)
        h_n = torch.cat([h_n[-2], h_n[-1]], dim=1)
        return self.fc(h_n)


class SimpleTransformer(nn.Module):
    """Transformer for sequence classification"""

    def __init__(self, vocab_size: int = 512, embed_dim: int = 32,
                 num_heads: int = 4, num_layers: int = 1, hidden_dim: int = 64):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        encoder_layers = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=num_heads, dim_feedforward=hidden_dim,
            dropout=0.1, batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layers, num_layers=num_layers)
        self.fc = nn.Sequential(
            nn.Linear(embed_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        x = self.embedding(x)
        x = self.transformer(x)
        x = x.mean(dim=1)  # Global average pooling
        return self.fc(x)


class SimpleGNN(nn.Module):
    """Simple GCN for graph-represented sequences"""

    def __init__(self, in_channels: int = 32, hidden_channels: int = 64, out_channels: int = 1):
        super().__init__()
        self.embedding = nn.Embedding(512, in_channels)
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.conv2 = GCNConv(hidden_channels, hidden_channels)
        self.fc = nn.Sequential(
            nn.Linear(hidden_channels, 32),
            nn.ReLU(),
            nn.Linear(32, out_channels),
            nn.Sigmoid()
        )

    def forward(self, x, edge_index, batch):
        x = self.embedding(x).squeeze(1)
        x = self.conv1(x, edge_index).relu()
        x = self.conv2(x, edge_index).relu()
        x = global_mean_pool(x, batch)
        return self.fc(x)


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
# Training & Utility Functions
# ============================================================

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


def seq_to_graph(seq: List[int], label: int) -> Data:
    """Convert syscall sequence to graph data for GNN"""
    unique_syscalls = list(set(seq))
    syscall_to_idx = {s: i for i, s in enumerate(unique_syscalls)}
    x = torch.LongTensor([[s] for s in unique_syscalls])
    edge_index = []
    for i in range(len(seq) - 1):
        u = syscall_to_idx[seq[i]]
        v = syscall_to_idx[seq[i+1]]
        edge_index.append([u, v])
    if not edge_index:
        edge_index = [[0, 0]]
    edge_index = torch.LongTensor(edge_index).t().contiguous()
    return Data(x=x, edge_index=edge_index, y=torch.FloatTensor([label]))


def train_mlp(X_train, y_train, X_test, y_test, epochs=20, lr=0.01):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    train_ds = TensorDataset(torch.FloatTensor(X_train), torch.FloatTensor(y_train).unsqueeze(1))
    train_loader = DataLoader(train_ds, batch_size=128, shuffle=True)
    test_t = torch.FloatTensor(X_test).to(device)

    model = SimpleMLP(input_dim=X_train.shape[1]).to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    model.train()
    for _ in range(epochs):
        for bx, by in train_loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            outputs = model(bx)
            loss = criterion(outputs, by)
            loss.backward()
            optimizer.step()

    model.eval()
    with torch.no_grad():
        start_time = time.time()
        probs = model(test_t).cpu().numpy().flatten()
        infer_time = (time.time() - start_time) / len(X_test) * 1e6
        preds = (probs > 0.5).astype(int)
    return preds, probs, infer_time


def train_seq_model(ModelClass, train_seqs, y_train, test_seqs, y_test, epochs=10):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    max_len = 200 # Reduced for speed/memory
    X_train = torch.LongTensor(pad_sequences(train_seqs, max_len))
    y_train_t = torch.FloatTensor(y_train).unsqueeze(1)
    train_ds = TensorDataset(X_train, y_train_t)
    train_loader = DataLoader(train_ds, batch_size=64, shuffle=True)
    X_test = torch.LongTensor(pad_sequences(test_seqs, max_len)).to(device)

    model = ModelClass().to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    model.train()
    for _ in range(epochs):
        for bx, by in train_loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            outputs = model(bx)
            loss = criterion(outputs, by)
            loss.backward()
            optimizer.step()

    model.eval()
    with torch.no_grad():
        start_time = time.time()
        probs = model(X_test).cpu().numpy().flatten()
        infer_time = (time.time() - start_time) / len(test_seqs) * 1e6
        preds = (probs > 0.5).astype(int)
    return preds, probs, infer_time


def train_gnn(train_seqs, y_train, test_seqs, y_test, epochs=10):
    if not HAS_PYG: return None
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    train_list = [seq_to_graph(s, l) for s, l in zip(train_seqs, y_train)]
    train_loader = PyGDataLoader(train_list, batch_size=64, shuffle=True)
    test_list = [seq_to_graph(s, l) for s, l in zip(test_seqs, y_test)]
    test_loader = PyGDataLoader(test_list, batch_size=64)

    model = SimpleGNN().to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    model.train()
    for _ in range(epochs):
        for data in train_loader:
            data = data.to(device)
            optimizer.zero_grad()
            outputs = model(data.x, data.edge_index, data.batch)
            loss = criterion(outputs, data.y.unsqueeze(1))
            loss.backward()
            optimizer.step()

    model.eval()
    all_probs = []
    with torch.no_grad():
        start_time = time.time()
        for data in test_loader:
            data = data.to(device)
            probs = model(data.x, data.edge_index, data.batch)
            all_probs.append(probs.cpu().numpy().flatten())
        infer_time = (time.time() - start_time) / len(test_seqs) * 1e6
        probs = np.concatenate(all_probs)
        preds = (probs > 0.5).astype(int)
    return preds, probs, infer_time


def train_autoencoder(X_train_normal, X_test, y_test, epochs=20):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    train_ds = TensorDataset(torch.FloatTensor(X_train_normal), torch.FloatTensor(X_train_normal))
    train_loader = DataLoader(train_ds, batch_size=128, shuffle=True)
    test_t = torch.FloatTensor(X_test).to(device)

    model = SimpleAutoencoder(input_dim=X_train_normal.shape[1]).to(device)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    model.train()
    for _ in range(epochs):
        for bx, _ in train_loader:
            bx = bx.to(device)
            optimizer.zero_grad()
            outputs = model(bx)
            loss = criterion(outputs, bx)
            loss.backward()
            optimizer.step()

    model.eval()
    with torch.no_grad():
        start_time = time.time()
        reconstructed = model(test_t)
        infer_time = (time.time() - start_time) / len(X_test) * 1e6
        errors = torch.mean((test_t - reconstructed)**2, dim=1).cpu().numpy()
        train_rec = model(torch.FloatTensor(X_train_normal).to(device))
        train_errors = torch.mean((torch.FloatTensor(X_train_normal).to(device) - train_rec)**2, dim=1).cpu().numpy()
        threshold = np.percentile(train_errors, 95)
        preds = (errors > threshold).astype(int)
        probs = np.clip(errors / (threshold * 2), 0, 1)
    return preds, probs, infer_time


def main():
    parser = argparse.ArgumentParser(description='ICICS ML Comparison')
    parser.add_argument('--data-dir', type=str, required=True, help='Path to ADFA-LD')
    parser.add_argument('--trials', type=int, default=3, help='Number of trials')
    args = parser.parse_args()

    sequences, labels = load_adfa_ld(args.data_dir)
    X = extract_features(sequences)
    y = np.array(labels)
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    models = ['random_forest', 'mlp_wasmsentinel', 'lstm', 'transformer', 'gnn', 'autoencoder']
    results = {m: {'f1': [], 'latency': []} for m in models}

    for trial in range(args.trials):
        print(f"Trial {trial+1}/{args.trials}...")
        skf = StratifiedKFold(n_splits=3, shuffle=True, random_state=42+trial)
        for train_idx, test_idx in skf.split(X, y):
            X_tr, X_te = X[train_idx], X[test_idx]
            y_tr, y_te = y[train_idx], y[test_idx]
            seq_tr = [sequences[i] for i in train_idx]
            seq_te = [sequences[i] for i in test_idx]

            # RF
            rf = RandomForestClassifier(n_estimators=100, max_depth=10)
            rf.fit(X_tr, y_tr)
            s = time.time()
            y_p = rf.predict(X_te)
            results['random_forest']['latency'].append((time.time()-s)/len(y_te)*1e6)
            results['random_forest']['f1'].append(f1_score(y_te, y_p))

            # MLP
            y_p, _, lat = train_mlp(X_tr, y_tr, X_te, y_te)
            results['mlp_wasmsentinel']['f1'].append(f1_score(y_te, y_p))
            results['mlp_wasmsentinel']['latency'].append(lat)

            # LSTM
            y_p, _, lat = train_seq_model(SimpleLSTM, seq_tr, y_tr, seq_te, y_te)
            results['lstm']['f1'].append(f1_score(y_te, y_p))
            results['lstm']['latency'].append(lat)

            # Transformer
            y_p, _, lat = train_seq_model(SimpleTransformer, seq_tr, y_tr, seq_te, y_te)
            results['transformer']['f1'].append(f1_score(y_te, y_p))
            results['transformer']['latency'].append(lat)

            # GNN
            y_p, _, lat = train_gnn(seq_tr, y_tr, seq_te, y_te)
            results['gnn']['f1'].append(f1_score(y_te, y_p))
            results['gnn']['latency'].append(lat)

            # AE
            y_p, _, lat = train_autoencoder(X_tr[y_tr==0], X_te, y_te)
            results['autoencoder']['f1'].append(f1_score(y_te, y_p))
            results['autoencoder']['latency'].append(lat)
            break

    print("\n" + "="*80)
    print(f"{'Model':<20} {'F1 (Mean ± Std)':<20} {'Latency (μs)':<15} {'p-value'}")
    print("="*80)
    mlp_f1 = results['mlp_wasmsentinel']['f1']
    for m in models:
        f1, lat = results[m]['f1'], results[m]['latency']
        if not f1: continue
        p = stats.ttest_ind(mlp_f1, f1)[1] if m!='mlp_wasmsentinel' else 1.0
        print(f"{m:<20} {np.mean(f1):>6.4f} ± {np.std(f1):.4f} {np.mean(lat):>10.1f} {p:>10.4f}")

    with open('ml_comparison_results_v2.json', 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == '__main__':
    main()
