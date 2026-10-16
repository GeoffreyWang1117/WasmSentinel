//! STIDE (Sequence Time-Delay Embedding) Detector
//!
//! Implements n-gram based anomaly detection for syscall sequences.
//! This is the "fast path" detector - low latency, moderate accuracy.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Configuration for STIDE detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StideConfig {
    /// N-gram size (typically 5-10)
    pub ngram_size: usize,
    /// Maximum database size to prevent memory bloat
    pub max_database_size: usize,
    /// Anomaly threshold (0.0-1.0)
    pub anomaly_threshold: f32,
}

impl Default for StideConfig {
    fn default() -> Self {
        Self {
            ngram_size: 6,
            max_database_size: 100_000,
            anomaly_threshold: 0.3,
        }
    }
}

/// STIDE detector state
#[derive(Debug)]
pub struct StideDetector {
    config: StideConfig,
    /// Normal database: set of known-good n-grams
    normal_database: HashSet<u64>,
    /// Current sliding window of syscalls
    window: VecDeque<u32>,
    /// Syscall name to ID mapping
    syscall_map: HashMap<String, u32>,
    /// Next syscall ID
    next_syscall_id: u32,
    /// Statistics
    stats: StideStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StideStats {
    pub normal_ngrams: usize,
    pub total_events: u64,
    pub anomalous_events: u64,
    pub training_samples: u64,
}

impl StideDetector {
    pub fn new() -> Self {
        Self::with_config(StideConfig::default())
    }

    pub fn with_config(config: StideConfig) -> Self {
        Self {
            config,
            normal_database: HashSet::new(),
            window: VecDeque::new(),
            syscall_map: Self::init_syscall_map(),
            next_syscall_id: 500, // Start after predefined syscalls
            stats: StideStats::default(),
        }
    }

    /// Initialize common syscall mappings
    fn init_syscall_map() -> HashMap<String, u32> {
        let mut map = HashMap::new();
        let syscalls = [
            ("read", 0),
            ("write", 1),
            ("open", 2),
            ("close", 3),
            ("stat", 4),
            ("fstat", 5),
            ("lstat", 6),
            ("poll", 7),
            ("lseek", 8),
            ("mmap", 9),
            ("mprotect", 10),
            ("munmap", 11),
            ("brk", 12),
            ("ioctl", 16),
            ("access", 21),
            ("pipe", 22),
            ("select", 23),
            ("sched_yield", 24),
            ("mremap", 25),
            ("dup", 32),
            ("dup2", 33),
            ("nanosleep", 35),
            ("getpid", 39),
            ("socket", 41),
            ("connect", 42),
            ("accept", 43),
            ("sendto", 44),
            ("recvfrom", 45),
            ("sendmsg", 46),
            ("recvmsg", 47),
            ("shutdown", 48),
            ("bind", 49),
            ("listen", 50),
            ("getsockname", 51),
            ("clone", 56),
            ("fork", 57),
            ("vfork", 58),
            ("execve", 59),
            ("exit", 60),
            ("wait4", 61),
            ("kill", 62),
            ("uname", 63),
            ("fcntl", 72),
            ("flock", 73),
            ("fsync", 74),
            ("fdatasync", 75),
            ("getcwd", 79),
            ("chdir", 80),
            ("fchdir", 81),
            ("rename", 82),
            ("mkdir", 83),
            ("rmdir", 84),
            ("creat", 85),
            ("unlink", 87),
            ("chmod", 90),
            ("fchmod", 91),
            ("chown", 92),
            ("fchown", 93),
            ("getuid", 102),
            ("getgid", 104),
            ("geteuid", 107),
            ("getegid", 108),
            ("setpgid", 109),
            ("getppid", 110),
            ("getpgrp", 111),
            ("setsid", 112),
            ("prctl", 157),
            ("arch_prctl", 158),
            ("openat", 257),
            ("mkdirat", 258),
            ("fchownat", 260),
            ("futimesat", 261),
            ("fstatat", 262),
            ("unlinkat", 263),
            ("renameat", 264),
            ("linkat", 265),
            ("symlinkat", 266),
            ("readlinkat", 267),
            ("fchmodat", 268),
            ("faccessat", 269),
        ];

        for (name, id) in syscalls {
            map.insert(name.to_string(), id);
        }
        map
    }

    /// Get or create syscall ID
    fn get_syscall_id(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.syscall_map.get(name) {
            return id;
        }

        let id = self.next_syscall_id;
        self.next_syscall_id += 1;
        self.syscall_map.insert(name.to_string(), id);
        id
    }

    /// Compute n-gram hash
    fn compute_ngram_hash(window: &VecDeque<u32>) -> u64 {
        let mut hash: u64 = 0;
        for (i, &syscall_id) in window.iter().enumerate() {
            hash ^= (syscall_id as u64).wrapping_shl((i * 8) as u32);
            hash = hash.wrapping_mul(31);
        }
        hash
    }

    /// Train on a single syscall event
    pub fn train_on(&mut self, syscall_name: &str) {
        let syscall_id = self.get_syscall_id(syscall_name);

        // Add to sliding window
        self.window.push_back(syscall_id);
        if self.window.len() > self.config.ngram_size {
            self.window.pop_front();
        }

        // If we have a complete n-gram, add to database
        if self.window.len() == self.config.ngram_size {
            if self.normal_database.len() < self.config.max_database_size {
                let hash = Self::compute_ngram_hash(&self.window);
                self.normal_database.insert(hash);
            }
        }

        self.stats.training_samples += 1;
    }

    /// Finalize training
    pub fn fit(&mut self) {
        self.stats.normal_ngrams = self.normal_database.len();
        // Clear window for inference
        self.window.clear();
    }

    /// Detect anomaly in a syscall
    ///
    /// Returns anomaly score (0.0 = normal, 1.0 = anomalous)
    pub fn detect(&mut self, syscall_name: &str) -> f32 {
        let syscall_id = self.get_syscall_id(syscall_name);

        // Add to sliding window
        self.window.push_back(syscall_id);
        if self.window.len() > self.config.ngram_size {
            self.window.pop_front();
        }

        self.stats.total_events += 1;

        // If we don't have a complete n-gram yet, return 0
        if self.window.len() < self.config.ngram_size {
            return 0.0;
        }

        // Check if n-gram is in normal database
        let hash = Self::compute_ngram_hash(&self.window);
        if self.normal_database.contains(&hash) {
            0.0
        } else {
            self.stats.anomalous_events += 1;
            1.0
        }
    }

    /// Detect with a sequence of recent syscalls
    pub fn detect_sequence(&mut self, syscalls: &[&str]) -> f32 {
        if syscalls.is_empty() {
            return 0.0;
        }

        let mut total_anomaly = 0.0;
        let mut count = 0;

        for syscall in syscalls {
            let score = self.detect(syscall);
            if self.window.len() >= self.config.ngram_size {
                total_anomaly += score;
                count += 1;
            }
        }

        if count > 0 {
            total_anomaly / count as f32
        } else {
            0.0
        }
    }

    /// Check if the current state indicates an anomaly
    pub fn is_anomalous(&self, score: f32) -> bool {
        score >= self.config.anomaly_threshold
    }

    /// Get statistics
    pub fn get_stats(&self) -> &StideStats {
        &self.stats
    }

    /// Reset the sliding window (e.g., for new process)
    pub fn reset_window(&mut self) {
        self.window.clear();
    }

    /// Get database size
    pub fn database_size(&self) -> usize {
        self.normal_database.len()
    }
}

impl Default for StideDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stide_basic() {
        let mut detector = StideDetector::new();

        // Train on normal sequence
        let normal_sequence = [
            "open", "read", "read", "read", "close", "open", "read", "close",
        ];
        for syscall in &normal_sequence {
            detector.train_on(syscall);
        }
        detector.fit();

        assert!(detector.database_size() > 0);
    }

    #[test]
    fn test_stide_detection() {
        let mut detector = StideDetector::with_config(StideConfig {
            ngram_size: 3,
            max_database_size: 1000,
            anomaly_threshold: 0.5,
        });

        // Train on normal sequence
        for _ in 0..10 {
            detector.train_on("open");
            detector.train_on("read");
            detector.train_on("close");
        }
        detector.fit();

        // Test normal sequence - should be 0
        detector.reset_window();
        let score1 = detector.detect("open");
        let score2 = detector.detect("read");
        let score3 = detector.detect("close");
        assert_eq!(score3, 0.0, "Known sequence should not be anomalous");

        // Test anomalous sequence
        detector.reset_window();
        detector.detect("execve");
        detector.detect("mprotect");
        let score = detector.detect("ptrace");
        assert_eq!(score, 1.0, "Unknown sequence should be anomalous");
    }
}
