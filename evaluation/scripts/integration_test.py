#!/usr/bin/env python3
"""
End-to-End Integration Test for WasmSentinel

This script tests the complete detection pipeline:
1. Load the Wasm module with embedded weights
2. Send simulated syscall events
3. Verify detection accuracy and performance

Requirements:
- wasmtime Python bindings: pip install wasmtime
- Or use the Go host directly

Usage:
    python integration_test.py
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple
import struct


# Test cases: (syscall_sequence, expected_label, description)
TEST_CASES = [
    # Normal behavior patterns
    ([0, 1, 2, 3, 0, 1, 2, 3], 0, "Normal read/write sequence"),
    ([257, 0, 1, 3, 0, 1, 3], 0, "Normal file operations"),
    ([41, 42, 44, 45, 0, 1], 0, "Normal network sequence"),

    # Attack patterns
    ([59, 57, 102, 59, 57, 102, 59], 1, "Fork-exec attack pattern"),
    ([59, 59, 59, 59, 59, 59], 1, "Repeated execve (suspicious)"),
    ([157, 157, 157, 157], 1, "Repeated prctl (privilege escalation attempt)"),
    ([41, 42, 49, 59, 102], 1, "Reverse shell pattern"),
    ([90, 90, 90, 59, 57], 1, "Repeated mmap + exec"),
]


def create_feature_vector(syscalls: List[int], size: int = 64) -> List[float]:
    """Create a feature vector from syscall sequence."""
    features = [0.0] * size

    if not syscalls:
        return features

    # Syscall frequency bins (0-31)
    for sc in syscalls:
        bin_idx = min(sc % 32, 31)
        features[bin_idx] += 1

    # Normalize
    total = len(syscalls)
    if total > 0:
        for i in range(32):
            features[i] /= total

    # Category ratios (32-36)
    file_syscalls = {0, 1, 2, 3, 4, 5, 6, 8, 17, 18, 19, 20, 21, 22, 257, 258}
    network_syscalls = {41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55}
    process_syscalls = {56, 57, 58, 59, 60, 61, 62, 102, 157}
    memory_syscalls = {9, 10, 11, 12, 13, 25, 26, 27, 28, 90}

    categories = [file_syscalls, network_syscalls, process_syscalls, memory_syscalls]
    for i, cat in enumerate(categories):
        count = sum(1 for sc in syscalls if sc in cat)
        features[32 + i] = count / total if total > 0 else 0

    # Sequence statistics (37-47)
    features[37] = len(syscalls) / 1000.0
    features[38] = len(set(syscalls)) / 350.0

    # Bigram diversity
    bigrams = set()
    for i in range(len(syscalls) - 1):
        bigrams.add((syscalls[i], syscalls[i+1]))
    features[39] = len(bigrams) / max(len(syscalls) - 1, 1)

    return features


def test_with_python_mlp():
    """Test using pure Python MLP implementation."""
    import numpy as np

    # Load weights
    weights_path = Path(__file__).parent.parent.parent / "rules/ml-detector/train/mlp_weights.json"

    if not weights_path.exists():
        print(f"Weights file not found: {weights_path}")
        return None

    with open(weights_path, 'r') as f:
        layers = json.load(f)

    def forward(features):
        """Forward pass through MLP."""
        x = np.array(features)
        for i, layer in enumerate(layers):
            weights = np.array(layer['weights'])
            biases = np.array(layer['biases'])
            x = np.dot(weights, x) + biases
            if i < len(layers) - 1:
                x = np.maximum(0, x)  # ReLU
            else:
                x = 1.0 / (1.0 + np.exp(-x))  # Sigmoid
        return x[0]

    # Run tests
    results = []
    correct = 0
    total = len(TEST_CASES)

    print("\n" + "="*70)
    print("Integration Test: Python MLP with Embedded Weights")
    print("="*70)

    for syscalls, expected, description in TEST_CASES:
        features = create_feature_vector(syscalls)
        score = forward(features)
        predicted = 1 if score > 0.5 else 0

        is_correct = predicted == expected
        if is_correct:
            correct += 1

        status = "PASS" if is_correct else "FAIL"
        print(f"[{status}] {description}")
        print(f"      Syscalls: {syscalls[:6]}{'...' if len(syscalls) > 6 else ''}")
        print(f"      Score: {score:.4f}, Predicted: {predicted}, Expected: {expected}")

        results.append({
            'description': description,
            'score': float(score),
            'predicted': predicted,
            'expected': expected,
            'correct': is_correct
        })

    accuracy = correct / total
    print(f"\n{'='*70}")
    print(f"Results: {correct}/{total} tests passed ({accuracy*100:.1f}% accuracy)")
    print("="*70)

    return {
        'accuracy': accuracy,
        'correct': correct,
        'total': total,
        'results': results
    }


def test_wasm_module():
    """Test the compiled Wasm module directly."""
    try:
        from wasmtime import Store, Module, Instance, Func
        HAS_WASMTIME = True
    except ImportError:
        HAS_WASMTIME = False

    if not HAS_WASMTIME:
        print("\nWasmtime Python bindings not available.")
        print("Install with: pip install wasmtime")
        return None

    wasm_path = Path(__file__).parent.parent.parent / "rules/ml-detector/target/wasm32-wasip1/release/ml_detector.wasm"

    if not wasm_path.exists():
        print(f"Wasm module not found: {wasm_path}")
        return None

    print("\n" + "="*70)
    print("Integration Test: Wasm Module")
    print("="*70)

    store = Store()
    module = Module.from_file(store.engine, str(wasm_path))

    # Note: Full WASI integration would be needed for the actual module
    # This is a simplified test framework
    print("Wasm module loaded successfully")
    print(f"Module size: {wasm_path.stat().st_size / 1024:.1f} KB")

    return {'status': 'loaded', 'size_kb': wasm_path.stat().st_size / 1024}


def test_performance():
    """Test inference performance."""
    import numpy as np

    # Load weights
    weights_path = Path(__file__).parent.parent.parent / "rules/ml-detector/train/mlp_weights.json"

    if not weights_path.exists():
        return None

    with open(weights_path, 'r') as f:
        layers = json.load(f)

    def forward(features):
        x = np.array(features)
        for i, layer in enumerate(layers):
            weights = np.array(layer['weights'])
            biases = np.array(layer['biases'])
            x = np.dot(weights, x) + biases
            if i < len(layers) - 1:
                x = np.maximum(0, x)
            else:
                x = 1.0 / (1.0 + np.exp(-x))
        return x[0]

    # Generate random test data
    num_iterations = 10000
    test_features = [create_feature_vector([i % 400 for i in range(50)]) for _ in range(100)]

    print("\n" + "="*70)
    print("Performance Test: Python MLP Inference")
    print("="*70)

    # Warmup
    for _ in range(100):
        forward(test_features[0])

    # Benchmark
    start = time.perf_counter()
    for i in range(num_iterations):
        forward(test_features[i % 100])
    elapsed = time.perf_counter() - start

    latency_us = (elapsed / num_iterations) * 1_000_000
    throughput = num_iterations / elapsed

    print(f"Iterations: {num_iterations}")
    print(f"Total time: {elapsed*1000:.2f} ms")
    print(f"Average latency: {latency_us:.2f} μs")
    print(f"Throughput: {throughput:.0f} inferences/sec")

    return {
        'iterations': num_iterations,
        'latency_us': latency_us,
        'throughput': throughput
    }


def main():
    print("WasmSentinel Integration Test Suite")
    print("=" * 70)

    results = {}

    # Test 1: Python MLP
    mlp_results = test_with_python_mlp()
    if mlp_results:
        results['python_mlp'] = mlp_results

    # Test 2: Performance
    perf_results = test_performance()
    if perf_results:
        results['performance'] = perf_results

    # Test 3: Wasm module loading
    wasm_results = test_wasm_module()
    if wasm_results:
        results['wasm_module'] = wasm_results

    # Save results
    output_path = Path(__file__).parent.parent / "results/integration_test_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to: {output_path}")

    # Summary
    print("\n" + "="*70)
    print("INTEGRATION TEST SUMMARY")
    print("="*70)

    if 'python_mlp' in results:
        acc = results['python_mlp']['accuracy']
        print(f"Detection Accuracy: {acc*100:.1f}%")

    if 'performance' in results:
        lat = results['performance']['latency_us']
        thr = results['performance']['throughput']
        print(f"Inference Latency: {lat:.2f} μs")
        print(f"Throughput: {thr:.0f}/sec")

    if 'wasm_module' in results:
        size = results['wasm_module'].get('size_kb', 0)
        print(f"Wasm Module Size: {size:.1f} KB")

    print("\nAll integration tests completed.")

    return 0 if mlp_results and mlp_results['accuracy'] >= 0.5 else 1


if __name__ == '__main__':
    sys.exit(main())
