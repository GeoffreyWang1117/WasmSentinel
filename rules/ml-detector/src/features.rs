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
