#!/usr/bin/env python3
"""E1: detection accuracy on ADFA-LD with inference inside the Wasm module.

Protocol
  * traces: ADFA-LD normal (Training + Validation, 5,205) and attack (746, six
    families); stratified K-fold over all traces, repeated with several seeds
  * WasmSentinel MLP: feature set v1 (64 dims) -> 64-128-64-32-16-1 MLP trained
    per fold in NumPy (vectorized re-implementation of train_mlp.SimpleMLP,
    early stopping on a 10 % inner validation split), weights loaded into the
    compiled module with load_mlp_weights, every test score produced by the
    module's mlp_score export (features + inference inside Wasm)
  * WasmSentinel RF: the Random Forest baseline's model (scikit-learn, 300
    trees, balanced class weights) serialized with forest_export.py, loaded
    into the module with load_rf_model, every test score produced by the
    module's rf_score export (features + tree traversal inside Wasm)
  * baselines: STIDE 6-gram novelty rate (normal-only), Isolation Forest
    (normal-only, v1 features), Random Forest (supervised, v1 features; the
    scikit-learn reference of the WasmSentinel RF arm), LSTM on the raw
    syscall sequence (supervised, early stopping)
  * metrics per (seed, fold): AUPRC, ROC-AUC, recall at FPR <= 5 % and 1 %,
    precision/recall/F1 at two operating points fixed on the training fold
    (FPR-5 % threshold from training normals; train-optimal-F1 threshold),
    per-family recall at the FPR-5 % point
  * paired comparison of AUPRC against each WasmSentinel arm over the (seed,
    fold) runs: mean difference, 95 % t-CI, Wilcoxon signed-rank p

Outputs (in --out): e1_results.json (everything, with provenance),
e1_summary.md, e1_pr_curves.json (mean PR curves for plotting).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
TRAIN_DIR = REPO / "rules" / "ml-detector" / "train"
sys.path.insert(0, str(TRAIN_DIR))
from forest_export import forest_stats, forest_to_bytes  # noqa: E402
from train_mlp import extract_features, parse_syscall_trace  # noqa: E402
from verify_wasm_parity import WasmModel  # noqa: E402

FAMILIES = ["Adduser", "Hydra_FTP", "Hydra_SSH", "Java_Meterpreter", "Meterpreter", "Web_Shell"]


# ----------------------------------------------------------------------------- data

def load_adfa(adfa_dir: Path):
    traces = []
    for sub in ("Training_Data_Master", "Validation_Data_Master"):
        for f in sorted((adfa_dir / sub).glob("*.txt")):
            seq = parse_syscall_trace(str(f))
            if seq:
                traces.append({"seq": np.asarray(seq, dtype=np.uint32), "label": 0, "family": "normal", "path": str(f.relative_to(adfa_dir))})
    for d in sorted((adfa_dir / "Attack_Data_Master").iterdir()):
        if not d.is_dir():
            continue
        family = d.name.rsplit("_", 1)[0]
        for f in sorted(d.glob("*.txt")):
            seq = parse_syscall_trace(str(f))
            if seq:
                traces.append({"seq": np.asarray(seq, dtype=np.uint32), "label": 1, "family": family, "path": str(f.relative_to(adfa_dir))})
    return traces


# ----------------------------------------------------------------------------- metrics

def recall_at_fpr(y, s, max_fpr):
    from sklearn.metrics import roc_curve
    fpr, tpr, _ = roc_curve(y, s)
    ok = fpr <= max_fpr
    return float(tpr[ok].max()) if ok.any() else 0.0


def prf(y, pred):
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": p, "recall": r, "f1": f, "tp": tp, "fp": fp, "fn": fn}


def train_optimal_threshold(y, s):
    from sklearn.metrics import precision_recall_curve
    p, r, t = precision_recall_curve(y, s)
    f = 2 * p[:-1] * r[:-1] / np.maximum(p[:-1] + r[:-1], 1e-12)
    return float(t[int(np.argmax(f))])


def evaluate(y_train, s_train, y_test, s_test, families_test):
    from sklearn.metrics import average_precision_score, roc_auc_score, precision_recall_curve
    y_train, s_train, y_test, s_test = map(np.asarray, (y_train, s_train, y_test, s_test))
    thr_fpr5 = float(np.quantile(s_train[y_train == 0], 0.95))
    thr_f1 = train_optimal_threshold(y_train, s_train)
    pred5 = (s_test > thr_fpr5).astype(int)
    predf = (s_test > thr_f1).astype(int)
    fam = {}
    families_test = np.asarray(families_test)
    for name in FAMILIES:
        m = families_test == name
        if m.any():
            fam[name] = float(pred5[m].mean())
    fpr5_observed = float(pred5[y_test == 0].mean()) if (y_test == 0).any() else 0.0
    p, r, _ = precision_recall_curve(y_test, s_test)
    grid = np.linspace(0, 1, 101)
    # precision as a function of recall (step interpolation, max precision at >= recall)
    pr_interp = [float(p[r >= g].max()) if (r >= g).any() else 0.0 for g in grid]
    return {
        "auprc": float(average_precision_score(y_test, s_test)),
        "roc_auc": float(roc_auc_score(y_test, s_test)),
        "recall_at_fpr5": recall_at_fpr(y_test, s_test, 0.05),
        "recall_at_fpr1": recall_at_fpr(y_test, s_test, 0.01),
        "op_fpr5": {"threshold": thr_fpr5, "observed_fpr": fpr5_observed, **prf(y_test, pred5), "per_family_recall": fam},
        "op_train_f1": {"threshold": thr_f1, **prf(y_test, predf)},
        "pr_curve": pr_interp,
    }


# ----------------------------------------------------------------------------- WasmSentinel MLP

class NumpyMLP:
    """Vectorized re-implementation of train_mlp.SimpleMLP: same layers,
    activations, class weighting, gradient clipping; batched instead of
    per-sample loops, early stopping on an inner validation split."""

    def __init__(self, sizes, rng):
        self.layers = []
        for i, o in zip(sizes[:-1], sizes[1:]):
            w = (rng.standard_normal((o, i)) * np.sqrt(2.0 / (i + o))).astype(np.float32)
            self.layers.append([w, np.zeros(o, dtype=np.float32)])

    @staticmethod
    def _sigmoid(z):
        return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))

    def forward(self, X):
        acts, pre = [X], []
        cur = X
        n = len(self.layers)
        for j, (w, b) in enumerate(self.layers):
            z = cur @ w.T + b
            pre.append(z)
            cur = np.maximum(z, 0) if j < n - 1 else self._sigmoid(z)
            acts.append(cur)
        return acts, pre

    def predict(self, X):
        return self.forward(X.astype(np.float32))[0][-1][:, 0]

    def train(self, X, y, Xv, yv, epochs, lr, batch, patience, rng, log=None):
        from sklearn.metrics import average_precision_score
        X = X.astype(np.float32)
        y = y.astype(np.float32)
        n = len(X)
        n_pos = y.sum()
        pos_w = n / (2 * n_pos) if n_pos else 1.0
        neg_w = n / (2 * (n - n_pos)) if n - n_pos else 1.0
        sw_all = np.where(y == 1, pos_w, neg_w).astype(np.float32)
        best, best_ep, best_state, bad = -1.0, -1, None, 0
        for ep in range(epochs):
            idx = rng.permutation(n)
            for s in range(0, n, batch):
                bi = idx[s:s + batch]
                xb, yb, sw = X[bi], y[bi], sw_all[bi]
                acts, pre = self.forward(xb)
                out = np.clip(acts[-1][:, 0], 1e-7, 1 - 1e-7)
                delta = ((out - yb) * sw / len(bi))[:, None]  # mean of weighted per-sample grads
                for j in range(len(self.layers) - 1, -1, -1):
                    gw = np.clip(delta.T @ acts[j], -1.0, 1.0)
                    gb = np.clip(delta.sum(0), -1.0, 1.0)
                    if j > 0:
                        delta = (delta @ self.layers[j][0]) * (pre[j - 1] > 0)
                    self.layers[j][0] -= lr * gw.astype(np.float32)
                    self.layers[j][1] -= lr * gb.astype(np.float32)
            ap = average_precision_score(yv, self.predict(Xv))
            if ap > best:
                best, best_ep, bad = ap, ep, 0
                best_state = [(w.copy(), b.copy()) for w, b in self.layers]
            else:
                bad += 1
                if bad >= patience:
                    break
        if best_state:
            self.layers = [[w, b] for w, b in best_state]
        return {"best_val_auprc": float(best), "best_epoch": best_ep, "epochs_run": ep + 1}

    def export_json(self):
        return json.dumps([{"weights": w.tolist(), "biases": b.tolist()} for w, b in self.layers])


def run_wasm_mlp(ctx, tr, te, seed, fold):
    rng = np.random.default_rng(seed * 1000 + fold)
    from sklearn.model_selection import train_test_split
    Xtr, ytr = ctx.X[tr], ctx.y[tr]
    Xa, Xv, ya, yv = train_test_split(Xtr, ytr, test_size=0.1, stratify=ytr, random_state=seed * 1000 + fold)
    mlp = NumpyMLP([64, 128, 64, 32, 16, 1], rng)
    info = mlp.train(Xa, ya, Xv, yv, epochs=ctx.args.mlp_epochs, lr=0.01, batch=32, patience=ctx.args.mlp_patience, rng=rng)
    weights = mlp.export_json()
    ctx.wasm.load_weights(weights)
    s_test = np.array([ctx.wasm.score(ctx.traces[i]["seq"]) for i in te], dtype=np.float64)
    s_train = np.array([ctx.wasm.score(ctx.traces[i]["seq"]) for i in tr], dtype=np.float64)
    ref = mlp.predict(ctx.X[te]).astype(np.float64)
    info["wasm_vs_numpy_max_abs_diff"] = float(np.max(np.abs(ref - s_test)))
    info["weights_sha256"] = hashlib.sha256(weights.encode()).hexdigest()[:16]
    return s_train, s_test, info


# ----------------------------------------------------------------------------- WasmSentinel RF

def fit_rf(ctx, tr, seed, fold):
    """The Random Forest of the 'rf' baseline; the same seed gives the same
    model for the 'rf' and 'wasmsentinel_rf' arms."""
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed * 1000 + fold, n_jobs=-1).fit(ctx.X[tr], ctx.y[tr])


def run_wasm_rf(ctx, tr, te, seed, fold):
    """Forest serialized (forest_export.py), loaded into the module with
    load_rf_model, every score from the module's rf_score export."""
    if not ctx.wasm.has_forest():
        raise RuntimeError("the Wasm module has no rf_score / load_rf_model exports; rebuild it")
    m = fit_rf(ctx, tr, seed, fold)
    blob = forest_to_bytes(m)
    ctx.wasm.load_forest(blob)
    s_test = np.array([ctx.wasm.score_rf(ctx.traces[i]["seq"]) for i in te], dtype=np.float64)
    s_train = np.array([ctx.wasm.score_rf(ctx.traces[i]["seq"]) for i in tr], dtype=np.float64)
    ref = m.predict_proba(ctx.X[te])[:, 1].astype(np.float64)
    info = forest_stats(m, blob)
    info["sha256"] = info["sha256"][:16]
    info["wasm_vs_sklearn_max_abs_diff"] = float(np.max(np.abs(ref - s_test)))
    return s_train, s_test, info


# ----------------------------------------------------------------------------- baselines

def run_stide(ctx, tr, te, seed, fold, n=6):
    normal = set()
    for i in tr:
        if ctx.y[i] == 0:
            seq = ctx.traces[i]["seq"]
            for k in range(len(seq) - n + 1):
                normal.add(seq[k:k + n].tobytes())
    def novelty(seq):
        grams = [seq[k:k + n].tobytes() for k in range(len(seq) - n + 1)]
        if not grams:
            return 0.0
        return sum(1 for g in grams if g not in normal) / len(grams)
    s_train = np.array([novelty(ctx.traces[i]["seq"]) for i in tr])
    s_test = np.array([novelty(ctx.traces[i]["seq"]) for i in te])
    return s_train, s_test, {"ngram": n, "normal_ngrams": len(normal)}


def run_iforest(ctx, tr, te, seed, fold):
    from sklearn.ensemble import IsolationForest
    Xn = ctx.X[tr][ctx.y[tr] == 0]
    m = IsolationForest(n_estimators=300, random_state=seed * 1000 + fold, n_jobs=-1).fit(Xn)
    return -m.score_samples(ctx.X[tr]), -m.score_samples(ctx.X[te]), {"n_estimators": 300, "trained_on": "normal only"}


def run_rf(ctx, tr, te, seed, fold):
    m = fit_rf(ctx, tr, seed, fold)
    return m.predict_proba(ctx.X[tr])[:, 1], m.predict_proba(ctx.X[te])[:, 1], {"n_estimators": 300}


def pick_device(requested):
    """A GPU with >= 1.5 GiB free, else CPU. Shared GPUs may be so full that even
    querying them fails; any CUDA error means CPU."""
    import torch
    if requested != "auto":
        return torch.device(requested)
    try:
        if torch.cuda.is_available():
            best, best_free = None, 0
            for i in range(torch.cuda.device_count()):
                free, _ = torch.cuda.mem_get_info(i)
                if free > best_free:
                    best, best_free = i, free
            if best is not None and best_free >= 1.5 * 2**30:
                return torch.device(f"cuda:{best}")
    except Exception as e:  # noqa: BLE001
        print(f"CUDA unavailable ({str(e).splitlines()[0]}); using CPU", flush=True)
    return torch.device("cpu")


def run_lstm(ctx, tr, te, seed, fold):
    import torch
    import torch.nn as nn
    from sklearn.metrics import average_precision_score
    from sklearn.model_selection import train_test_split
    torch.manual_seed(seed * 1000 + fold)
    dev = pick_device(ctx.args.device)
    max_len = ctx.args.lstm_max_len
    vocab = int(max(int(t["seq"].max()) for t in ctx.traces)) + 2

    def batchify(idx):
        seqs = [ctx.traces[i]["seq"][:max_len].astype(np.int64) + 1 for i in idx]
        lens = torch.tensor([len(s) for s in seqs])
        x = torch.zeros(len(seqs), int(lens.max()), dtype=torch.long)
        for k, s in enumerate(seqs):
            x[k, :len(s)] = torch.from_numpy(s)
        return x, lens

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.emb = nn.Embedding(vocab, 32, padding_idx=0)
            self.lstm = nn.LSTM(32, 64, batch_first=True)
            self.fc = nn.Linear(64, 1)

        def forward(self, x, lens):
            e = self.emb(x)
            packed = nn.utils.rnn.pack_padded_sequence(e, lens.cpu(), batch_first=True, enforce_sorted=False)
            _, (h, _) = self.lstm(packed)
            return self.fc(h[-1])[:, 0]

    def scores(net, idx):
        net.eval()
        out = []
        with torch.no_grad():
            for s in range(0, len(idx), 128):
                x, lens = batchify(idx[s:s + 128])
                out.append(torch.sigmoid(net(x.to(dev), lens)).cpu().numpy())
        return np.concatenate(out)

    tr = np.asarray(tr)
    ia, iv = train_test_split(tr, test_size=0.1, stratify=ctx.y[tr], random_state=seed * 1000 + fold)
    net = Net().to(dev)
    pos = ctx.y[ia].sum()
    pos_weight = torch.tensor([(len(ia) - pos) / max(pos, 1)], dtype=torch.float32, device=dev)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.Adam(net.parameters(), lr=1e-3)
    best, best_state, bad, best_ep = -1.0, None, 0, -1
    rng = np.random.default_rng(seed * 1000 + fold)
    t0 = time.time()
    for ep in range(ctx.args.lstm_epochs):
        net.train()
        perm = rng.permutation(len(ia))
        for s in range(0, len(ia), 64):
            bi = ia[perm[s:s + 64]]
            x, lens = batchify(bi)
            yb = torch.tensor(ctx.y[bi], dtype=torch.float32, device=dev)
            opt.zero_grad()
            loss = loss_fn(net(x.to(dev), lens), yb)
            loss.backward()
            nn.utils.clip_grad_norm_(net.parameters(), 1.0)
            opt.step()
        ap = average_precision_score(ctx.y[iv], scores(net, iv))
        if ap > best:
            best, best_ep, bad = ap, ep, 0
            best_state = {k: v.detach().clone() for k, v in net.state_dict().items()}
        else:
            bad += 1
            if bad >= ctx.args.lstm_patience:
                break
    if best_state:
        net.load_state_dict(best_state)
    return scores(net, tr), scores(net, te), {
        "device": str(dev), "max_len": max_len, "best_val_auprc": float(best), "best_epoch": best_ep,
        "epochs_run": ep + 1, "train_seconds": round(time.time() - t0, 1), "params": sum(p.numel() for p in net.parameters()),
    }


MODELS = {
    "wasmsentinel_mlp": ("WasmSentinel MLP (Wasm, feature set v1)", run_wasm_mlp),
    "wasmsentinel_rf": ("WasmSentinel RF (Wasm, feature set v1)", run_wasm_rf),
    "stide": ("STIDE 6-gram novelty (normal only)", run_stide),
    "iforest": ("Isolation Forest (normal only, v1 features)", run_iforest),
    "rf": ("Random Forest (supervised, v1 features)", run_rf),
    "lstm": ("LSTM on syscall sequence (supervised, early stopping)", run_lstm),
}


# ----------------------------------------------------------------------------- driver

class Ctx:
    pass


def provenance(args, wasm_path):
    def sh(cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, cwd=REPO).strip()
        except Exception:
            return ""
    cpu = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    import sklearn
    prov = {
        "git_commit": sh("git rev-parse HEAD"), "git_dirty": bool(sh("git status --porcelain --untracked-files=no")),
        "kernel": platform.release(), "cpu": cpu, "python": platform.python_version(),
        "numpy": np.__version__, "sklearn": sklearn.__version__,
        "wasm_sha256": hashlib.sha256(Path(wasm_path).read_bytes()).hexdigest(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "args": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
    }
    try:
        import torch, wasmtime
        prov["torch"] = torch.__version__
        prov["wasmtime_py"] = getattr(wasmtime, "__version__", "")
    except Exception:
        pass
    return prov


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adfa-dir", type=Path, default=REPO / "evaluation/datasets/raw/ADFA-LD/ADFA-LD")
    ap.add_argument("--wasm", type=Path, default=REPO / "rules/wasm/ml_detector.wasm")
    ap.add_argument("--out", type=Path, default=REPO / "evaluation/results/2026-11/e1")
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--models", default=",".join(MODELS))
    ap.add_argument("--mlp-epochs", type=int, default=200)
    ap.add_argument("--mlp-patience", type=int, default=25)
    ap.add_argument("--lstm-epochs", type=int, default=40)
    ap.add_argument("--lstm-patience", type=int, default=5)
    ap.add_argument("--lstm-max-len", type=int, default=1000)
    ap.add_argument("--device", default="auto")
    ap.add_argument("--quick", action="store_true", help="1 seed, 2 folds, few epochs (smoke test)")
    args = ap.parse_args()
    if args.quick:
        args.seeds, args.folds, args.mlp_epochs, args.lstm_epochs = 1, 2, 20, 3

    from sklearn.model_selection import StratifiedKFold
    t_start = time.time()
    # Provenance is taken at the start: the commit and module hash the run was
    # started from, not whatever HEAD is hours later when it finishes.
    prov = provenance(args, args.wasm)
    traces = load_adfa(args.adfa_dir)
    ctx = Ctx()
    ctx.args, ctx.traces = args, traces
    ctx.y = np.array([t["label"] for t in traces])
    ctx.fam = np.array([t["family"] for t in traces])
    ctx.X = np.stack([extract_features(list(map(int, t["seq"]))) for t in traces]).astype(np.float32)
    ctx.wasm = WasmModel(args.wasm)
    print(f"traces: {len(traces)} ({int((ctx.y == 0).sum())} normal, {int(ctx.y.sum())} attack); wasm model {ctx.wasm.info()['hidden_sizes']}")

    models = [m for m in args.models.split(",") if m]
    runs = []
    for seed in range(args.seeds):
        skf = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=seed)
        for fold, (tr, te) in enumerate(skf.split(ctx.X, ctx.y)):
            for name in models:
                label, fn = MODELS[name]
                t0 = time.time()
                s_tr, s_te, info = fn(ctx, tr, te, seed, fold)
                m = evaluate(ctx.y[tr], s_tr, ctx.y[te], s_te, ctx.fam[te])
                m.update({"model": name, "seed": seed, "fold": fold, "n_train": int(len(tr)), "n_test": int(len(te)),
                          "seconds": round(time.time() - t0, 1), "info": info})
                runs.append(m)
                print(f"seed {seed} fold {fold} {name:17s} AUPRC {m['auprc']:.3f} AUROC {m['roc_auc']:.3f} "
                      f"R@5%FPR {m['recall_at_fpr5']:.3f} F1@fpr5 {m['op_fpr5']['f1']:.3f} ({m['seconds']}s)", flush=True)

    # aggregate
    from scipy import stats
    summary = {}
    for name in models:
        rs = [r for r in runs if r["model"] == name]
        agg = {}
        for key in ("auprc", "roc_auc", "recall_at_fpr5", "recall_at_fpr1"):
            v = np.array([r[key] for r in rs])
            agg[key] = {"mean": float(v.mean()), "std": float(v.std(ddof=1)) if len(v) > 1 else 0.0}
        for op in ("op_fpr5", "op_train_f1"):
            for key in ("precision", "recall", "f1"):
                v = np.array([r[op][key] for r in rs])
                agg[f"{op}_{key}"] = {"mean": float(v.mean()), "std": float(v.std(ddof=1)) if len(v) > 1 else 0.0}
        fam = {}
        for f in FAMILIES:
            v = [r["op_fpr5"]["per_family_recall"][f] for r in rs if f in r["op_fpr5"]["per_family_recall"]]
            if v:
                fam[f] = float(np.mean(v))
        agg["per_family_recall_at_fpr5"] = fam
        agg["pr_curve_mean"] = np.mean([r["pr_curve"] for r in rs], axis=0).tolist()
        agg["pr_curve_std"] = np.std([r["pr_curve"] for r in rs], axis=0).tolist()
        agg["runs"] = len(rs)
        summary[name] = agg
    def paired_vs(reference):
        """AUPRC(reference) - AUPRC(other) over the (seed, fold) runs."""
        out = {}
        base = {(r["seed"], r["fold"]): r["auprc"] for r in runs if r["model"] == reference}
        for name in models:
            if name == reference:
                continue
            diffs = np.array([base[(r["seed"], r["fold"])] - r["auprc"] for r in runs if r["model"] == name])
            if len(diffs) > 1 and not np.any(diffs != 0):
                ci, p = (0.0, 0.0), 1.0  # identical scores (e.g. the forest scored by scikit-learn and by the module)
            elif len(diffs) > 1:
                ci = stats.t.interval(0.95, len(diffs) - 1, loc=diffs.mean(), scale=stats.sem(diffs))
                try:
                    p = float(stats.wilcoxon(diffs).pvalue)
                except ValueError:
                    p = float("nan")
            else:
                ci, p = (float("nan"), float("nan")), float("nan")
            out[name] = {"auprc_diff_mean": float(diffs.mean()), "ci95": [float(ci[0]), float(ci[1])], "wilcoxon_p": p, "n": int(len(diffs))}
        return out

    paired = paired_vs("wasmsentinel_mlp") if "wasmsentinel_mlp" in models else {}
    paired_rf = paired_vs("wasmsentinel_rf") if "wasmsentinel_rf" in models else {}

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    prov["timestamp_end"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    result = {
        "experiment": "E1 ADFA-LD detection accuracy, inference inside the Wasm module",
        "provenance": prov,
        "dataset": {"normal": int((ctx.y == 0).sum()), "attack": int(ctx.y.sum()), "families": FAMILIES,
                    "protocol": f"StratifiedKFold({args.folds}, shuffle) x {args.seeds} seeds; operating points fixed on the training fold"},
        "models": {k: MODELS[k][0] for k in models},
        "summary": summary, "paired_vs_wasmsentinel_auprc": paired, "paired_vs_wasmsentinel_rf_auprc": paired_rf,
        "notes": [
            "The (seed, fold) runs share data across seeds; the paired CI treats them as 15 draws and is optimistic.",
            "WasmSentinel MLP scores come from the compiled module (mlp_score) after load_mlp_weights; wasm_vs_numpy_max_abs_diff in each run records the parity.",
            "WasmSentinel RF scores come from the compiled module (rf_score) after load_rf_model with the 'rf' baseline's forest serialized by forest_export.py; wasm_vs_sklearn_max_abs_diff in each run records the parity against scikit-learn's predict_proba.",
            "paired_vs_wasmsentinel_auprc is AUPRC(WasmSentinel MLP) - AUPRC(model); paired_vs_wasmsentinel_rf_auprc is AUPRC(WasmSentinel RF) - AUPRC(model).",
            "Operating points: op_fpr5 uses the 95th percentile of the training fold's normal scores; op_train_f1 the F1-optimal threshold on the training fold.",
        ],
        "runs": runs, "elapsed_seconds": round(time.time() - t_start, 1),
    }
    (out / "e1_results.json").write_text(json.dumps(result, indent=1, default=str))
    (out / "e1_pr_curves.json").write_text(json.dumps({k: {"recall": np.linspace(0, 1, 101).tolist(), "precision_mean": v["pr_curve_mean"], "precision_std": v["pr_curve_std"], "label": MODELS[k][0]} for k, v in summary.items()}, indent=1))

    lines = [f"# E1 ADFA-LD ({result['dataset']['normal']} normal / {result['dataset']['attack']} attack), {args.folds}-fold x {args.seeds} seeds",
             "", f"commit {result['provenance']['git_commit'][:12]}, wasm sha256 {result['provenance']['wasm_sha256'][:12]}, {result['provenance']['timestamp']}", "",
             "| model | AUPRC | ROC-AUC | recall@5%FPR | recall@1%FPR | F1 @FPR5 op | F1 @train-F1 op |", "|---|---|---|---|---|---|---|"]
    for name in models:
        a = summary[name]
        lines.append(f"| {MODELS[name][0]} | {a['auprc']['mean']:.3f} ± {a['auprc']['std']:.3f} | {a['roc_auc']['mean']:.3f} ± {a['roc_auc']['std']:.3f} | "
                     f"{a['recall_at_fpr5']['mean']:.3f} | {a['recall_at_fpr1']['mean']:.3f} | {a['op_fpr5_f1']['mean']:.3f} | {a['op_train_f1_f1']['mean']:.3f} |")
    for ref_name, pz_all in (("WasmSentinel MLP", paired), ("WasmSentinel RF", paired_rf)):
        if pz_all:
            lines += ["", f"| model | AUPRC({ref_name}) − AUPRC(model) | 95% CI | Wilcoxon p |", "|---|---|---|---|"]
            for name, pz in pz_all.items():
                lines.append(f"| {MODELS[name][0]} | {pz['auprc_diff_mean']:+.3f} | [{pz['ci95'][0]:+.3f}, {pz['ci95'][1]:+.3f}] | {pz['wilcoxon_p']:.3g} |")
    parity = [(r["model"], r["info"].get("wasm_vs_numpy_max_abs_diff", r["info"].get("wasm_vs_sklearn_max_abs_diff"))) for r in runs if r["model"].startswith("wasmsentinel_")]
    if parity:
        lines += ["", "Wasm vs reference implementation, max |score diff| over all runs: " + ", ".join(
            f"{m} {max(d for mm, d in parity if mm == m):.2e}" for m in dict.fromkeys(m for m, _ in parity))]
    lines += ["", "Per-family recall at the FPR-5 % operating point (mean over runs):", "", "| model | " + " | ".join(FAMILIES) + " |", "|---|" + "---|" * len(FAMILIES)]
    for name in models:
        fam = summary[name]["per_family_recall_at_fpr5"]
        lines.append(f"| {name} | " + " | ".join(f"{fam.get(f, float('nan')):.2f}" for f in FAMILIES) + " |")
    (out / "e1_summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nwrote {out}/e1_results.json ({result['elapsed_seconds']} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
