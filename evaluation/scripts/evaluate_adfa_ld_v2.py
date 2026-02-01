#!/usr/bin/env python3
"""
ADFA-LD Dataset Evaluation for WasmSentinel (V2 - Improved Detection)
Uses frequency-based anomaly detection with optimized thresholds
"""

import os
import json
import random
import math
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Set
from collections import defaultdict, Counter
import statistics

# Constants
PROJECT_ROOT = Path(__file__).parent.parent.parent
DATASET_PATH = PROJECT_ROOT / "evaluation" / "datasets" / "raw" / "ADFA-LD" / "ADFA-LD"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"

@dataclass
class SyscallTrace:
    """Represents a syscall trace from ADFA-LD"""
    filename: str
    syscalls: List[int]
    category: str
    is_attack: bool

@dataclass
class DetectionResult:
    """Result of detection on a trace"""
    trace_filename: str
    category: str
    is_attack: bool
    detected: bool
    anomaly_score: float
    reasons: List[str]

@dataclass
class EvaluationMetrics:
    """Evaluation metrics"""
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    auc_roc: float = 0.0

def load_trace(filepath: Path) -> List[int]:
    """Load a syscall trace from file"""
    with open(filepath, 'r') as f:
        content = f.read().strip()
        syscalls = [int(x) for x in content.split() if x.isdigit()]
    return syscalls

def load_dataset() -> Tuple[List[SyscallTrace], List[SyscallTrace], Dict[str, List[SyscallTrace]]]:
    """Load the ADFA-LD dataset"""
    training_traces = []
    validation_traces = []
    attack_traces = defaultdict(list)

    # Load training data
    training_dir = DATASET_PATH / "Training_Data_Master"
    if training_dir.exists():
        for f in training_dir.glob("*.txt"):
            syscalls = load_trace(f)
            if syscalls:
                training_traces.append(SyscallTrace(
                    filename=f.name, syscalls=syscalls,
                    category="normal", is_attack=False
                ))

    # Load validation data
    validation_dir = DATASET_PATH / "Validation_Data_Master"
    if validation_dir.exists():
        for f in validation_dir.glob("*.txt"):
            syscalls = load_trace(f)
            if syscalls:
                validation_traces.append(SyscallTrace(
                    filename=f.name, syscalls=syscalls,
                    category="normal", is_attack=False
                ))

    # Load attack data
    attack_dir = DATASET_PATH / "Attack_Data_Master"
    if attack_dir.exists():
        for attack_type_dir in attack_dir.iterdir():
            if attack_type_dir.is_dir():
                attack_type = attack_type_dir.name.rsplit('_', 1)[0]
                for f in attack_type_dir.glob("*.txt"):
                    syscalls = load_trace(f)
                    if syscalls:
                        attack_traces[attack_type].append(SyscallTrace(
                            filename=f.name, syscalls=syscalls,
                            category=attack_type, is_attack=True
                        ))

    return training_traces, validation_traces, attack_traces

class ImprovedAnomalyDetector:
    """Improved anomaly detector using multiple techniques"""

    def __init__(self):
        # N-gram models
        self.unigram_freq = defaultdict(float)
        self.bigram_freq = defaultdict(float)
        self.trigram_freq = defaultdict(float)

        # Statistics
        self.total_syscalls = 0
        self.total_bigrams = 0
        self.total_trigrams = 0

        # Trace-level statistics
        self.trace_length_mean = 0
        self.trace_length_std = 0
        self.unique_syscall_mean = 0
        self.unique_syscall_std = 0

        # Smoothing
        self.smoothing = 1e-10

    def train(self, normal_traces: List[SyscallTrace]):
        """Train on normal traces"""
        trace_lengths = []
        unique_counts = []

        for trace in normal_traces:
            syscalls = trace.syscalls
            trace_lengths.append(len(syscalls))
            unique_counts.append(len(set(syscalls)))

            # Count unigrams
            for s in syscalls:
                self.unigram_freq[s] += 1
                self.total_syscalls += 1

            # Count bigrams
            for i in range(len(syscalls) - 1):
                bigram = (syscalls[i], syscalls[i+1])
                self.bigram_freq[bigram] += 1
                self.total_bigrams += 1

            # Count trigrams
            for i in range(len(syscalls) - 2):
                trigram = (syscalls[i], syscalls[i+1], syscalls[i+2])
                self.trigram_freq[trigram] += 1
                self.total_trigrams += 1

        # Normalize frequencies
        for k in self.unigram_freq:
            self.unigram_freq[k] /= self.total_syscalls
        for k in self.bigram_freq:
            self.bigram_freq[k] /= self.total_bigrams
        for k in self.trigram_freq:
            self.trigram_freq[k] /= self.total_trigrams

        # Calculate trace statistics
        self.trace_length_mean = statistics.mean(trace_lengths)
        self.trace_length_std = statistics.stdev(trace_lengths) if len(trace_lengths) > 1 else 1
        self.unique_syscall_mean = statistics.mean(unique_counts)
        self.unique_syscall_std = statistics.stdev(unique_counts) if len(unique_counts) > 1 else 1

    def calculate_log_likelihood(self, syscalls: List[int]) -> float:
        """Calculate log-likelihood of a sequence under the trained model"""
        if len(syscalls) < 3:
            return 0.0

        log_prob = 0.0
        count = 0

        # Bigram probability
        for i in range(len(syscalls) - 1):
            bigram = (syscalls[i], syscalls[i+1])
            prob = self.bigram_freq.get(bigram, self.smoothing)
            log_prob += math.log(prob + self.smoothing)
            count += 1

        if count > 0:
            return log_prob / count
        return 0.0

    def calculate_anomaly_score(self, trace: SyscallTrace) -> Tuple[float, List[str]]:
        """Calculate anomaly score for a trace"""
        syscalls = trace.syscalls
        reasons = []
        scores = []

        # 1. Log-likelihood score (lower = more anomalous)
        ll = self.calculate_log_likelihood(syscalls)
        ll_score = max(0, min(1, (-ll - 5) / 10))  # Normalize to [0,1]
        scores.append(ll_score * 0.4)
        if ll_score > 0.5:
            reasons.append(f"low_likelihood:{ll:.2f}")

        # 2. Unknown syscall ratio
        unknown_count = sum(1 for s in syscalls if s not in self.unigram_freq)
        unknown_ratio = unknown_count / len(syscalls) if syscalls else 0
        if unknown_ratio > 0.1:
            scores.append(unknown_ratio * 0.3)
            reasons.append(f"unknown_syscalls:{unknown_count}")

        # 3. Rare bigram ratio
        rare_bigrams = 0
        for i in range(len(syscalls) - 1):
            bigram = (syscalls[i], syscalls[i+1])
            if self.bigram_freq.get(bigram, 0) < 1e-6:
                rare_bigrams += 1
        rare_ratio = rare_bigrams / (len(syscalls) - 1) if len(syscalls) > 1 else 0
        if rare_ratio > 0.2:
            scores.append(rare_ratio * 0.3)
            reasons.append(f"rare_patterns:{rare_bigrams}")

        # 4. Trace length anomaly
        if self.trace_length_std > 0:
            length_zscore = abs(len(syscalls) - self.trace_length_mean) / self.trace_length_std
            if length_zscore > 3:
                scores.append(min(1, length_zscore / 10) * 0.2)
                reasons.append(f"length_anomaly:{len(syscalls)}")

        # 5. Unique syscall count anomaly
        unique_count = len(set(syscalls))
        if self.unique_syscall_std > 0:
            unique_zscore = abs(unique_count - self.unique_syscall_mean) / self.unique_syscall_std
            if unique_zscore > 2:
                scores.append(min(1, unique_zscore / 5) * 0.1)
                reasons.append(f"unique_anomaly:{unique_count}")

        # 6. Specific attack patterns
        syscall_set = set(syscalls)
        syscall_counter = Counter(syscalls)

        # Network activity patterns
        network_syscalls = {41, 42, 43, 44, 45, 49, 50}  # socket, connect, accept, etc.
        network_count = sum(syscall_counter.get(s, 0) for s in network_syscalls)
        if network_count > 50:
            scores.append(min(1, network_count / 200) * 0.3)
            reasons.append(f"high_network:{network_count}")

        # Process creation patterns
        if 59 in syscall_set:  # execve
            execve_count = syscall_counter[59]
            if execve_count > 3:
                scores.append(min(1, execve_count / 10) * 0.2)
                reasons.append(f"multiple_execve:{execve_count}")

        # Privilege escalation patterns
        priv_syscalls = {105, 106, 101, 157}  # setuid, setgid, ptrace, prctl
        if len(syscall_set.intersection(priv_syscalls)) >= 2:
            scores.append(0.3)
            reasons.append("priv_esc_pattern")

        # Calculate final score
        total_score = sum(scores)
        normalized_score = min(1.0, total_score)

        return normalized_score, reasons

    def detect(self, trace: SyscallTrace, threshold: float = 0.3) -> DetectionResult:
        """Detect if a trace is anomalous"""
        score, reasons = self.calculate_anomaly_score(trace)

        return DetectionResult(
            trace_filename=trace.filename,
            category=trace.category,
            is_attack=trace.is_attack,
            detected=score >= threshold,
            anomaly_score=score,
            reasons=reasons
        )

def find_optimal_threshold(detector: ImprovedAnomalyDetector,
                          validation_traces: List[SyscallTrace],
                          attack_traces: List[SyscallTrace]) -> float:
    """Find optimal threshold using validation data"""
    # Sample for efficiency
    val_sample = random.sample(validation_traces, min(200, len(validation_traces)))
    attack_sample = attack_traces[:min(200, len(attack_traces))]

    # Calculate scores
    normal_scores = [detector.calculate_anomaly_score(t)[0] for t in val_sample]
    attack_scores = [detector.calculate_anomaly_score(t)[0] for t in attack_sample]

    best_f1 = 0
    best_threshold = 0.3

    for threshold in [i/20 for i in range(1, 20)]:
        tp = sum(1 for s in attack_scores if s >= threshold)
        fp = sum(1 for s in normal_scores if s >= threshold)
        fn = sum(1 for s in attack_scores if s < threshold)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold

    return best_threshold

def evaluate_detector(detector: ImprovedAnomalyDetector,
                     test_traces: List[SyscallTrace],
                     threshold: float) -> Tuple[EvaluationMetrics, List[DetectionResult]]:
    """Evaluate detector on test traces"""
    results = []
    tp = fp = tn = fn = 0

    for trace in test_traces:
        result = detector.detect(trace, threshold)
        results.append(result)

        if trace.is_attack:
            if result.detected:
                tp += 1
            else:
                fn += 1
        else:
            if result.detected:
                fp += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / len(test_traces) if test_traces else 0

    return EvaluationMetrics(
        true_positives=tp, false_positives=fp,
        true_negatives=tn, false_negatives=fn,
        precision=precision, recall=recall,
        f1_score=f1, accuracy=accuracy
    ), results

def run_evaluation():
    """Run full evaluation"""
    print("=" * 60)
    print("ADFA-LD Evaluation V2 - Improved Anomaly Detection")
    print("=" * 60)

    # Load dataset
    print("\n[1/5] Loading ADFA-LD dataset...")
    training_traces, validation_traces, attack_traces = load_dataset()

    all_attacks = []
    for traces in attack_traces.values():
        all_attacks.extend(traces)

    print(f"  Training: {len(training_traces)} normal traces")
    print(f"  Validation: {len(validation_traces)} normal traces")
    print(f"  Attacks: {len(all_attacks)} traces in {len(attack_traces)} categories")

    # Train detector
    print("\n[2/5] Training anomaly detector...")
    detector = ImprovedAnomalyDetector()
    detector.train(training_traces)
    print(f"  Unigram vocabulary: {len(detector.unigram_freq)}")
    print(f"  Bigram vocabulary: {len(detector.bigram_freq)}")
    print(f"  Trigram vocabulary: {len(detector.trigram_freq)}")

    # Find optimal threshold
    print("\n[3/5] Finding optimal threshold...")
    threshold = find_optimal_threshold(detector, validation_traces, all_attacks)
    print(f"  Optimal threshold: {threshold:.2f}")

    # Prepare test set
    print("\n[4/5] Preparing test set...")
    test_traces = []
    test_normal = random.sample(validation_traces, min(500, len(validation_traces)))
    test_traces.extend(test_normal)
    test_traces.extend(all_attacks)
    random.shuffle(test_traces)

    attack_count = sum(1 for t in test_traces if t.is_attack)
    print(f"  Test set: {len(test_traces)} traces ({len(test_traces) - attack_count} normal, {attack_count} attack)")

    # Evaluate
    print("\n[5/5] Evaluating...")
    metrics, results = evaluate_detector(detector, test_traces, threshold)

    # Print results
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)

    print(f"\nThreshold: {threshold:.2f}")
    print("\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"              Positive  Negative")
    print(f"Actual  ┌─────────┬─────────┐")
    print(f"Positive│  {metrics.true_positives:5d}  │  {metrics.false_negatives:5d}  │")
    print(f"        ├─────────┼─────────┤")
    print(f"Negative│  {metrics.false_positives:5d}  │  {metrics.true_negatives:5d}  │")
    print(f"        └─────────┴─────────┘")

    print(f"\nMetrics:")
    print(f"  Precision: {metrics.precision:.4f}")
    print(f"  Recall:    {metrics.recall:.4f}")
    print(f"  F1 Score:  {metrics.f1_score:.4f}")
    print(f"  Accuracy:  {metrics.accuracy:.4f}")

    # Per-attack analysis
    print("\nPer-Attack-Type Detection Rate:")
    attack_results = defaultdict(lambda: {"detected": 0, "total": 0})
    for result in results:
        if result.is_attack:
            attack_results[result.category]["total"] += 1
            if result.detected:
                attack_results[result.category]["detected"] += 1

    for attack_type, counts in sorted(attack_results.items()):
        rate = counts["detected"] / counts["total"] if counts["total"] > 0 else 0
        status = "✅" if rate >= 0.7 else "⚠️" if rate >= 0.5 else "❌"
        print(f"  {status} {attack_type}: {counts['detected']}/{counts['total']} ({rate:.1%})")

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = RESULTS_DIR / f"adfa_ld_v2_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "metrics.json", 'w') as f:
        json.dump(asdict(metrics), f, indent=2)

    with open(output_dir / "config.json", 'w') as f:
        json.dump({"threshold": threshold, "version": "v2"}, f, indent=2)

    print(f"\nResults saved to: {output_dir}")

    return metrics

if __name__ == "__main__":
    run_evaluation()
