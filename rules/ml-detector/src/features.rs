//! Feature Extraction Module
//!
//! Provides utilities for extracting features from various event types
//! for use with ML-based detection.

use std::collections::HashMap;

/// N-gram feature extractor for syscall sequences
pub struct NgramExtractor {
    ngram_size: usize,
    vocab: HashMap<String, usize>,
    next_id: usize,
}

impl NgramExtractor {
    pub fn new(ngram_size: usize) -> Self {
        Self {
            ngram_size,
            vocab: HashMap::new(),
            next_id: 0,
        }
    }

    /// Build vocabulary from training data
    pub fn fit(&mut self, sequences: &[Vec<String>]) {
        for sequence in sequences {
            for window in sequence.windows(self.ngram_size) {
                let ngram = window.join(":");
                if !self.vocab.contains_key(&ngram) {
                    self.vocab.insert(ngram, self.next_id);
                    self.next_id += 1;
                }
            }
        }
    }

    /// Transform sequence to n-gram features (bag-of-ngrams)
    pub fn transform(&self, sequence: &[String], max_features: usize) -> Vec<f32> {
        let mut features = vec![0.0; max_features];

        for window in sequence.windows(self.ngram_size) {
            let ngram = window.join(":");
            if let Some(&id) = self.vocab.get(&ngram) {
                if id < max_features {
                    features[id] += 1.0;
                }
            }
        }

        // Normalize
        let sum: f32 = features.iter().sum();
        if sum > 0.0 {
            for f in &mut features {
                *f /= sum;
            }
        }

        features
    }

    /// Get vocabulary size
    pub fn vocab_size(&self) -> usize {
        self.vocab.len()
    }
}

/// Syscall frequency analyzer
pub struct SyscallFrequency {
    /// Syscall counts
    counts: HashMap<String, u64>,
    /// Total count
    total: u64,
}

impl SyscallFrequency {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            total: 0,
        }
    }

    pub fn add(&mut self, syscall: &str) {
        *self.counts.entry(syscall.to_string()).or_insert(0) += 1;
        self.total += 1;
    }

    pub fn get_frequency(&self, syscall: &str) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        self.counts.get(syscall).copied().unwrap_or(0) as f32 / self.total as f32
    }

    pub fn to_feature_vector(&self, syscall_order: &[&str]) -> Vec<f32> {
        syscall_order
            .iter()
            .map(|s| self.get_frequency(s))
            .collect()
    }
}

impl Default for SyscallFrequency {
    fn default() -> Self {
        Self::new()
    }
}

/// Behavior pattern detector
pub struct PatternDetector {
    /// Known malicious patterns (sequence -> score)
    malicious_patterns: Vec<(Vec<&'static str>, f32)>,
}

impl PatternDetector {
    pub fn new() -> Self {
        Self {
            malicious_patterns: vec![
                // Reverse shell patterns
                (vec!["socket", "connect", "dup2", "execve"], 0.9),
                (vec!["socket", "connect", "execve"], 0.8),
                // Privilege escalation
                (vec!["setuid", "setgid", "execve"], 0.85),
                (vec!["ptrace", "mmap", "mprotect"], 0.8),
                // Code injection
                (vec!["mmap", "mprotect", "munmap"], 0.6),
                (vec!["execve", "mmap", "mprotect", "write"], 0.75),
                // Data exfiltration
                (vec!["open", "read", "socket", "sendto"], 0.7),
                (vec!["openat", "read", "connect", "write"], 0.7),
                // Persistence
                (vec!["open", "write", "chmod"], 0.5),
                (vec!["openat", "write", "fchmod"], 0.5),
                // Process injection
                (vec!["ptrace", "process_vm_writev"], 0.9),
                (vec!["ptrace", "mmap", "write"], 0.85),
            ],
        }
    }

    /// Check for malicious patterns in syscall sequence
    pub fn detect(&self, sequence: &[&str]) -> (f32, Option<String>) {
        let mut max_score = 0.0;
        let mut matched_pattern = None;

        for (pattern, score) in &self.malicious_patterns {
            if self.contains_pattern(sequence, pattern) {
                if *score > max_score {
                    max_score = *score;
                    matched_pattern = Some(pattern.join(" -> "));
                }
            }
        }

        (max_score, matched_pattern)
    }

    /// Check if sequence contains pattern (subsequence matching)
    fn contains_pattern(&self, sequence: &[&str], pattern: &[&str]) -> bool {
        if pattern.is_empty() || sequence.len() < pattern.len() {
            return false;
        }

        let mut pattern_idx = 0;
        for syscall in sequence {
            if *syscall == pattern[pattern_idx] {
                pattern_idx += 1;
                if pattern_idx == pattern.len() {
                    return true;
                }
            }
        }

        false
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistical features from syscall sequences
pub struct StatisticalFeatures;

impl StatisticalFeatures {
    /// Calculate entropy of syscall distribution
    pub fn entropy(counts: &HashMap<String, u64>, total: u64) -> f32 {
        if total == 0 {
            return 0.0;
        }

        let mut entropy = 0.0;
        for &count in counts.values() {
            if count > 0 {
                let p = count as f32 / total as f32;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Calculate burstiness (ratio of max to mean)
    pub fn burstiness(counts: &HashMap<String, u64>) -> f32 {
        if counts.is_empty() {
            return 0.0;
        }

        let values: Vec<u64> = counts.values().copied().collect();
        let max = *values.iter().max().unwrap_or(&0) as f32;
        let mean = values.iter().sum::<u64>() as f32 / values.len() as f32;

        if mean > 0.0 {
            max / mean
        } else {
            0.0
        }
    }

    /// Calculate unique syscall ratio
    pub fn uniqueness_ratio(sequence: &[&str]) -> f32 {
        if sequence.is_empty() {
            return 0.0;
        }

        let unique: std::collections::HashSet<_> = sequence.iter().collect();
        unique.len() as f32 / sequence.len() as f32
    }

    /// Detect sudden changes in syscall patterns
    pub fn detect_anomaly_burst(sequence: &[&str], window_size: usize) -> Vec<f32> {
        if sequence.len() < window_size * 2 {
            return vec![0.0];
        }

        let mut anomaly_scores = Vec::new();

        for i in window_size..sequence.len() - window_size {
            let prev_window = &sequence[i - window_size..i];
            let next_window = &sequence[i..i + window_size];

            let prev_unique: std::collections::HashSet<_> = prev_window.iter().collect();
            let next_unique: std::collections::HashSet<_> = next_window.iter().collect();

            // Jaccard distance
            let intersection = prev_unique.intersection(&next_unique).count();
            let union = prev_unique.union(&next_unique).count();

            let similarity = if union > 0 {
                intersection as f32 / union as f32
            } else {
                1.0
            };

            anomaly_scores.push(1.0 - similarity);
        }

        anomaly_scores
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ngram_extractor() {
        let mut extractor = NgramExtractor::new(3);

        let sequences = vec![
            vec!["read".to_string(), "write".to_string(), "close".to_string()],
            vec!["open".to_string(), "read".to_string(), "close".to_string()],
        ];

        extractor.fit(&sequences);
        assert!(extractor.vocab_size() > 0);

        let features = extractor.transform(&sequences[0], 10);
        assert_eq!(features.len(), 10);
    }

    #[test]
    fn test_pattern_detector() {
        let detector = PatternDetector::new();

        // Test reverse shell pattern
        let sequence = vec!["fork", "socket", "connect", "dup2", "execve", "read"];
        let (score, pattern) = detector.detect(&sequence);
        assert!(score > 0.8);
        assert!(pattern.is_some());

        // Test normal sequence
        let normal = vec!["open", "read", "read", "read", "close"];
        let (score, _) = detector.detect(&normal);
        assert!(score < 0.5);
    }

    #[test]
    fn test_statistical_features() {
        let mut counts = HashMap::new();
        counts.insert("read".to_string(), 50);
        counts.insert("write".to_string(), 30);
        counts.insert("close".to_string(), 20);

        let entropy = StatisticalFeatures::entropy(&counts, 100);
        assert!(entropy > 0.0);

        let burstiness = StatisticalFeatures::burstiness(&counts);
        assert!(burstiness >= 1.0);
    }
}

// ---------------------------------------------------------------------------
// Feature set v1 (ADFA-LD): exact port of `extract_features` in
// train/train_mlp.py. The model embedded in weights.rs was trained on these 64
// values (46 populated) computed from syscall *numbers*. Everything is computed
// in f64 like the NumPy reference and cast to f32 at the end, so the Wasm
// module and the training script agree to within f32 rounding
// (train/verify_wasm_parity.py checks this against the module).
//
// The category sets mix ABI numberings (0/1 are x86_64 read/write, 56/57 are
// aarch64 openat/close, ...) while ADFA-LD itself uses i386 numbers. They are
// kept verbatim because the trained weights depend on them; a semantically
// clean feature set is an evaluation question (E1), not a porting one.
// ---------------------------------------------------------------------------

/// Length of the v1 feature vector.
pub const ADFA_FEATURE_DIM: usize = 64;

const IO_SYSCALLS: &[u32] = &[0, 1, 63, 64, 65, 66, 67];
const FILE_SYSCALLS: &[u32] = &[56, 57, 80, 81, 82, 83];
const MEMORY_SYSCALLS: &[u32] = &[222, 226, 215, 214];
const NETWORK_SYSCALLS: &[u32] = &[198, 200, 201, 202, 203, 204, 205, 206];
const PROCESS_SYSCALLS: &[u32] = &[220, 221, 93, 94, 129];
const DANGEROUS_SYSCALLS: &[u32] = &[117, 105, 106, 142, 143, 40, 41, 165, 166];

/// Feature set v1 for a syscall-number sequence (a whole ADFA-LD trace when
/// training, the per-process window when deployed).
pub fn adfa_features(syscalls: &[u32]) -> [f32; ADFA_FEATURE_DIM] {
    let mut f = [0f32; ADFA_FEATURE_DIM];
    if syscalls.is_empty() {
        return f;
    }
    let n = syscalls.len();
    let total = n as f64;

    // collections.Counter semantics: keys in first-occurrence order.
    let mut order: Vec<u32> = Vec::new();
    let mut counts: HashMap<u32, u64> = HashMap::new();
    for &s in syscalls {
        let c = counts.entry(s).or_insert_with(|| {
            order.push(s);
            0
        });
        *c += 1;
    }
    let count_of = |s: u32| -> u64 { counts.get(&s).copied().unwrap_or(0) };
    let category = |set: &[u32]| -> f32 {
        (set.iter().map(|&s| count_of(s)).sum::<u64>() as f64 / total) as f32
    };

    // 0..6 category frequencies
    f[0] = category(IO_SYSCALLS);
    f[1] = category(FILE_SYSCALLS);
    f[2] = category(MEMORY_SYSCALLS);
    f[3] = category(NETWORK_SYSCALLS);
    f[4] = category(PROCESS_SYSCALLS);
    f[5] = category(DANGEROUS_SYSCALLS);

    // 6..16 ten most common syscalls (stable: ties keep first-occurrence order)
    let mut ranked: Vec<u64> = order.iter().map(|s| counts[s]).collect();
    ranked.sort_by(|a, b| b.cmp(a));
    for (i, c) in ranked.iter().take(10).enumerate() {
        f[6 + i] = (*c as f64 / total) as f32;
    }

    // 16..26 the first ten syscall numbers, scaled
    for (i, &s) in syscalls.iter().take(10).enumerate() {
        f[16 + i] = (s as f64 / 300.0) as f32;
    }

    // 26..36 ten most common bigrams
    if n >= 2 {
        let mut pair_order: Vec<(u32, u32)> = Vec::new();
        let mut pairs: HashMap<(u32, u32), u64> = HashMap::new();
        for w in syscalls.windows(2) {
            let k = (w[0], w[1]);
            let c = pairs.entry(k).or_insert_with(|| {
                pair_order.push(k);
                0
            });
            *c += 1;
        }
        let mut ranked: Vec<u64> = pair_order.iter().map(|k| pairs[k]).collect();
        ranked.sort_by(|a, b| b.cmp(a));
        for (i, c) in ranked.iter().take(10).enumerate() {
            f[26 + i] = (*c as f64 / (total - 1.0)) as f32;
        }
    }

    // 36..46 statistics
    let denom = (total - 1.0).max(1.0);
    f[36] = (total / 1000.0).min(1.0) as f32;
    f[37] = (counts.len() as f64 / total.max(1.0)) as f32;
    let mut ent = 0f64;
    for &s in &order {
        let p = counts[&s] as f64 / total;
        ent += p * (p + 1e-10).log2();
    }
    f[38] = (-ent / (counts.len() as f64).max(2.0).log2()) as f32;
    let maxc = order.iter().map(|s| counts[s]).max().unwrap_or(0) as f64;
    let mean_count = total / counts.len() as f64;
    f[39] = (maxc / mean_count / 10.0) as f32;
    f[40] = if syscalls.iter().any(|s| DANGEROUS_SYSCALLS.contains(s)) {
        1.0
    } else {
        0.0
    };
    let (mut consecutive, mut net_after_file, mut mem_after_proc) = (0u64, 0u64, 0u64);
    for w in syscalls.windows(2) {
        if w[0] == w[1] {
            consecutive += 1;
        }
        if FILE_SYSCALLS.contains(&w[0]) && NETWORK_SYSCALLS.contains(&w[1]) {
            net_after_file += 1;
        }
        if PROCESS_SYSCALLS.contains(&w[0]) && MEMORY_SYSCALLS.contains(&w[1]) {
            mem_after_proc += 1;
        }
    }
    f[41] = (consecutive as f64 / denom) as f32;
    f[42] = (net_after_file as f64 / denom) as f32;
    f[43] = (mem_after_proc as f64 / denom) as f32;
    let mean_nr = syscalls.iter().map(|&s| s as f64).sum::<f64>() / total;
    f[44] = (mean_nr / 300.0) as f32;
    if n > 1 {
        let var = syscalls
            .iter()
            .map(|&s| {
                let d = s as f64 - mean_nr;
                d * d
            })
            .sum::<f64>()
            / total;
        f[45] = (var.sqrt() / 100.0) as f32;
    }
    f
}

#[cfg(test)]
mod adfa_feature_tests {
    use super::*;

    #[test]
    fn empty_sequence_is_all_zero() {
        assert!(adfa_features(&[]).iter().all(|v| *v == 0.0));
    }

    #[test]
    fn hand_checked_values() {
        // 0 read, 1 write, 1 write, 57 close, 117 ptrace
        let f = adfa_features(&[0, 1, 1, 57, 117]);
        assert!((f[0] - 3.0 / 5.0).abs() < 1e-6, "io ratio");
        assert!((f[1] - 1.0 / 5.0).abs() < 1e-6, "file ratio");
        assert!((f[5] - 1.0 / 5.0).abs() < 1e-6, "dangerous ratio");
        assert!((f[6] - 2.0 / 5.0).abs() < 1e-6, "most common = write x2");
        assert!(
            (f[7] - 1.0 / 5.0).abs() < 1e-6,
            "ties keep first-seen order"
        );
        assert!((f[16] - 0.0).abs() < 1e-6 && (f[20] - 117.0 / 300.0).abs() < 1e-6);
        assert!((f[26] - 1.0 / 4.0).abs() < 1e-6, "bigram counts");
        assert!((f[36] - 0.005).abs() < 1e-6);
        assert!((f[37] - 4.0 / 5.0).abs() < 1e-6);
        assert_eq!(f[40], 1.0);
        assert!((f[41] - 1.0 / 4.0).abs() < 1e-6, "one consecutive repeat");
        assert!((f[44] - (176.0 / 5.0) / 300.0).abs() < 1e-6);
    }
}
