#!/usr/bin/env python3
"""Serialize a scikit-learn RandomForestClassifier into the byte image the
ml-detector module decodes (src/forest.rs, format "WSRF" v1).

Layout (little-endian):

    0   magic       u32  0x46525357 ("WSRF")
    4   version     u32  1
    8   n_features  u32
    12  n_trees     u32
    16  n_nodes     u32  over all trees
    20  flags       u32  0
    24  roots       n_trees x u32   node index of each tree's root
    ..  nodes       n_nodes x 12 B  feature i32 | value f32 | right u32

Nodes are written depth-first with the left subtree immediately after its
parent, so a split's left child is the next node and only the right child is
stored. A leaf has feature -1 and carries the tree's class-1 probability in
`value`. A split carries its threshold rounded *down* to float32: scikit-learn
compares the float32-cast feature with a float64 threshold, and for every
float32 x, `x <= t` is equivalent to `x <= floor_f32(t)`, so the module's f32
comparison reproduces scikit-learn's decision exactly. The forest score is the
mean leaf probability over trees (scikit-learn's predict_proba[:, 1]).
"""
from __future__ import annotations

import hashlib
import struct
import sys

import numpy as np

MAGIC = 0x46525357
VERSION = 1
NODE_BYTES = 12
HEADER_BYTES = 24


def f32_floor(t: float) -> float:
    """Largest float32 that is <= t."""
    t32 = np.float32(t)
    if float(t32) > t:
        t32 = np.nextafter(t32, np.float32(-np.inf))
    return float(t32)


def forest_to_bytes(model) -> bytes:
    """Byte image of a fitted binary RandomForestClassifier."""
    classes = list(model.classes_)
    if len(classes) != 2:
        raise ValueError(f"binary forests only, got classes {classes}")
    pos = classes.index(1) if 1 in classes else 1
    n_features = int(model.n_features_in_)
    feats: list[int] = []
    vals: list[float] = []
    rights: list[int] = []
    roots: list[int] = []
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))
    for est in model.estimators_:
        t = est.tree_
        cl, cr, fe, th, va = t.children_left, t.children_right, t.feature, t.threshold, t.value

        def emit(n: int) -> None:
            idx = len(feats)
            if cl[n] == -1:
                v = va[n, 0]
                s = float(v.sum())
                feats.append(-1)
                vals.append(float(v[pos]) / s if s > 0 else 0.0)
                rights.append(0)
                return
            feats.append(int(fe[n]))
            vals.append(f32_floor(float(th[n])))
            rights.append(0)
            emit(int(cl[n]))
            rights[idx] = len(feats)
            emit(int(cr[n]))

        roots.append(len(feats))
        emit(0)
    nodes = np.zeros(len(feats), dtype=[("f", "<i4"), ("v", "<f4"), ("r", "<u4")])
    nodes["f"] = feats
    nodes["v"] = vals
    nodes["r"] = rights
    header = struct.pack("<6I", MAGIC, VERSION, n_features, len(roots), len(feats), 0)
    return header + np.asarray(roots, dtype="<u4").tobytes() + nodes.tobytes()


def forest_stats(model, blob: bytes | None = None) -> dict:
    """Size facts recorded next to a forest (results JSON, generated Rust)."""
    trees = model.estimators_
    out = {
        "n_trees": len(trees),
        "n_nodes": int(sum(e.tree_.node_count for e in trees)),
        "n_leaves": int(sum(e.tree_.n_leaves for e in trees)),
        "max_depth": int(max(e.tree_.max_depth for e in trees)),
        "mean_depth": float(np.mean([e.tree_.max_depth for e in trees])),
        "n_features": int(model.n_features_in_),
    }
    if blob is not None:
        out["bytes"] = len(blob)
        out["sha256"] = hashlib.sha256(blob).hexdigest()
    return out


def forest_predict(blob: bytes, X: np.ndarray) -> np.ndarray:
    """Pure-NumPy reader of the byte image (a second implementation of the
    traversal, used to check the exporter against scikit-learn)."""
    magic, version, n_features, n_trees, n_nodes, _ = struct.unpack_from("<6I", blob, 0)
    assert magic == MAGIC and version == VERSION, (magic, version)
    roots = np.frombuffer(blob, dtype="<u4", count=n_trees, offset=HEADER_BYTES)
    nodes = np.frombuffer(blob, dtype=[("f", "<i4"), ("v", "<f4"), ("r", "<u4")], count=n_nodes,
                          offset=HEADER_BYTES + 4 * n_trees)
    X = np.asarray(X, dtype=np.float32)
    out = np.zeros(len(X), dtype=np.float64)
    for row, x in enumerate(X):
        acc = 0.0
        for r in roots:
            i = int(r)
            while True:
                f, v, right = int(nodes["f"][i]), nodes["v"][i], int(nodes["r"][i])
                if f < 0:
                    acc += float(v)
                    break
                i = i + 1 if x[f] <= v else right
        out[row] = acc / n_trees
    return out
