//! Lightweight MLP (Multi-Layer Perceptron) Detector
//!
//! Pure Rust implementation of a small neural network for threat detection.
//! Designed to run efficiently in Wasm sandbox without external dependencies.
//!
//! This is the "deep path" detector - higher latency, higher accuracy.

use serde::{Deserialize, Serialize};

/// MLP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlpConfig {
    /// Input feature size
    pub input_size: usize,
    /// Hidden layer sizes
    pub hidden_sizes: Vec<usize>,
    /// Output size (typically 1 for binary classification)
    pub output_size: usize,
    /// Anomaly threshold
    pub threshold: f32,
}

impl Default for MlpConfig {
    fn default() -> Self {
        Self {
            input_size: 64,             // Feature vector size
            hidden_sizes: vec![32, 16], // Two hidden layers
            output_size: 1,
            threshold: 0.5,
        }
    }
}

/// A single layer in the MLP
#[derive(Debug, Clone)]
struct Layer {
    weights: Vec<Vec<f32>>, // [output_size][input_size]
    biases: Vec<f32>,       // [output_size]
}

impl Layer {
    fn new(input_size: usize, output_size: usize) -> Self {
        // Xavier initialization
        let scale = (2.0 / (input_size + output_size) as f32).sqrt();

        let weights = (0..output_size)
            .map(|_| {
                (0..input_size)
                    .map(|i| ((i * 7 + 13) % 100) as f32 / 100.0 * scale - scale / 2.0)
                    .collect()
            })
            .collect();

        let biases = vec![0.0; output_size];

        Self { weights, biases }
    }

    fn forward(&self, input: &[f32]) -> Vec<f32> {
        self.weights
            .iter()
            .zip(self.biases.iter())
            .map(|(w, &b)| {
                let sum: f32 = w.iter().zip(input.iter()).map(|(&wi, &xi)| wi * xi).sum();
                sum + b
            })
            .collect()
    }

    fn set_weights(&mut self, weights: Vec<Vec<f32>>, biases: Vec<f32>) {
        self.weights = weights;
        self.biases = biases;
    }
}

/// Lightweight MLP detector
#[derive(Debug)]
pub struct MlpDetector {
    config: MlpConfig,
    layers: Vec<Layer>,
    stats: MlpStats,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MlpStats {
    pub total_inferences: u64,
    pub anomalies_detected: u64,
    pub avg_inference_score: f32,
}

impl MlpDetector {
    pub fn new() -> Self {
        Self::with_config(MlpConfig::default())
    }

    pub fn with_config(config: MlpConfig) -> Self {
        let mut layers = Vec::new();

        // Build layers
        let mut prev_size = config.input_size;
        for &hidden_size in &config.hidden_sizes {
            layers.push(Layer::new(prev_size, hidden_size));
            prev_size = hidden_size;
        }
        layers.push(Layer::new(prev_size, config.output_size));

        Self {
            config,
            layers,
            stats: MlpStats::default(),
        }
    }

    /// ReLU activation function
    #[inline]
    fn relu(x: f32) -> f32 {
        if x > 0.0 {
            x
        } else {
            0.0
        }
    }

    /// Sigmoid activation function
    #[inline]
    fn sigmoid(x: f32) -> f32 {
        1.0 / (1.0 + (-x).exp())
    }

    /// Forward pass through the network
    pub fn forward(&self, input: &[f32]) -> Vec<f32> {
        let mut current = input.to_vec();

        // Hidden layers with ReLU
        for (i, layer) in self.layers.iter().enumerate() {
            current = layer.forward(&current);

            // Apply activation
            if i < self.layers.len() - 1 {
                // Hidden layers: ReLU
                current = current.iter().map(|&x| Self::relu(x)).collect();
            } else {
                // Output layer: Sigmoid for probability
                current = current.iter().map(|&x| Self::sigmoid(x)).collect();
            }
        }

        current
    }

    /// Score a feature vector (padded or truncated to the input size) without
    /// touching statistics. This is the function train/verify_wasm_parity.py
    /// compares against the NumPy reference.
    pub fn score(&self, features: &[f32]) -> f32 {
        let mut input = vec![0.0; self.config.input_size];
        let len = features.len().min(self.config.input_size);
        input[..len].copy_from_slice(&features[..len]);
        self.forward(&input).first().copied().unwrap_or(0.0)
    }

    /// Detect anomaly from feature vector
    ///
    /// Returns anomaly score (0.0 = normal, 1.0 = anomalous)
    pub fn detect(&mut self, features: &[f32]) -> f32 {
        let score = self.score(features);

        self.stats.total_inferences += 1;
        if score >= self.config.threshold {
            self.stats.anomalies_detected += 1;
        }

        // Update running average
        let n = self.stats.total_inferences as f32;
        self.stats.avg_inference_score = self.stats.avg_inference_score * (n - 1.0) / n + score / n;

        score
    }

    /// Check if score indicates anomaly
    pub fn is_anomalous(&self, score: f32) -> bool {
        score >= self.config.threshold
    }

    /// Load weights from a serialized format
    ///
    /// Format: JSON array of layers, each with "weights" and "biases"
    pub fn load_weights(&mut self, weights_json: &str) -> Result<(), String> {
        #[derive(Deserialize)]
        struct LayerWeights {
            weights: Vec<Vec<f32>>,
            biases: Vec<f32>,
        }

        let layer_weights: Vec<LayerWeights> = serde_json::from_str(weights_json)
            .map_err(|e| format!("Failed to parse weights: {}", e))?;

        if layer_weights.len() != self.layers.len() {
            return Err(format!(
                "Weight count mismatch: expected {}, got {}",
                self.layers.len(),
                layer_weights.len()
            ));
        }

        for (layer, lw) in self.layers.iter_mut().zip(layer_weights.into_iter()) {
            layer.set_weights(lw.weights, lw.biases);
        }

        Ok(())
    }

    /// Export weights to JSON
    pub fn export_weights(&self) -> String {
        #[derive(Serialize)]
        struct LayerWeights<'a> {
            weights: &'a Vec<Vec<f32>>,
            biases: &'a Vec<f32>,
        }

        let layers: Vec<_> = self
            .layers
            .iter()
            .map(|l| LayerWeights {
                weights: &l.weights,
                biases: &l.biases,
            })
            .collect();

        serde_json::to_string(&layers).unwrap_or_default()
    }

    /// Get statistics
    pub fn get_stats(&self) -> &MlpStats {
        &self.stats
    }

    /// Get configuration
    pub fn get_config(&self) -> &MlpConfig {
        &self.config
    }

    /// Override the decision threshold.
    pub fn set_threshold(&mut self, threshold: f32) {
        self.config.threshold = threshold;
    }
}

impl Default for MlpDetector {
    fn default() -> Self {
        Self::with_embedded_weights()
    }
}

impl MlpDetector {
    /// Create a detector with embedded (pre-trained) weights
    pub fn with_embedded_weights() -> Self {
        let embedded_weights = crate::weights::load_embedded_weights();

        // The architecture comes from the generated weights, never from here.
        let config = MlpConfig {
            input_size: crate::weights::INPUT_SIZE,
            hidden_sizes: crate::weights::HIDDEN_SIZES.to_vec(),
            output_size: 1,
            threshold: crate::weights::DEFAULT_THRESHOLD,
        };

        let mut detector = Self::with_config(config);

        // Load embedded weights
        for (layer_idx, (weights, biases)) in embedded_weights.into_iter().enumerate() {
            if layer_idx < detector.layers.len() {
                detector.layers[layer_idx].set_weights(weights, biases);
            }
        }

        detector
    }
}

/// Feature extraction utilities
pub mod features {
    use super::*;

    /// Extract features from a syscall sequence
    pub fn extract_syscall_features(syscall_names: &[&str], max_features: usize) -> Vec<f32> {
        let mut features = vec![0.0; max_features];

        // Feature 1-10: Syscall frequency histogram (top categories)
        let categories = [
            &["read", "write", "pread", "pwrite"][..],          // I/O
            &["open", "openat", "close", "creat"],              // File ops
            &["mmap", "mprotect", "munmap", "brk"],             // Memory
            &["socket", "connect", "bind", "listen", "accept"], // Network
            &["fork", "clone", "execve", "exit"],               // Process
            &["stat", "fstat", "lstat", "access"],              // Stat
            &["ioctl", "fcntl", "select", "poll"],              // Control
            &["getuid", "getgid", "setuid", "setgid"],          // Identity
            &["mkdir", "rmdir", "unlink", "rename"],            // Directory
            &["chmod", "chown", "fchmod", "fchown"],            // Permissions
        ];

        for (i, category) in categories.iter().enumerate() {
            if i >= max_features {
                break;
            }
            let count = syscall_names
                .iter()
                .filter(|&s| category.contains(s))
                .count();
            features[i] = count as f32 / syscall_names.len().max(1) as f32;
        }

        // Feature 11-20: Dangerous syscall indicators
        let dangerous = [
            "ptrace",
            "setuid",
            "setgid",
            "chroot",
            "mount",
            "umount",
            "init_module",
            "delete_module",
            "kexec_load",
            "reboot",
        ];
        let mut danger_idx = 10;
        for &syscall in &dangerous {
            if danger_idx >= max_features {
                break;
            }
            features[danger_idx] = if syscall_names.contains(&syscall) {
                1.0
            } else {
                0.0
            };
            danger_idx += 1;
        }

        // Feature 21-30: Sequence patterns
        if syscall_names.len() >= 2 {
            // Transition probabilities (simplified)
            let mut exec_to_mem = 0;
            let mut net_to_exec = 0;

            for window in syscall_names.windows(2) {
                if window[0] == "execve" && ["mmap", "mprotect"].contains(&window[1]) {
                    exec_to_mem += 1;
                }
                if ["socket", "connect"].contains(&window[0]) && window[1] == "execve" {
                    net_to_exec += 1;
                }
            }

            if 20 < max_features {
                features[20] = exec_to_mem as f32 / syscall_names.len() as f32;
            }
            if 21 < max_features {
                features[21] = net_to_exec as f32 / syscall_names.len() as f32;
            }
        }

        // Feature 31-40: Statistics
        if 30 < max_features {
            features[30] = syscall_names.len() as f32 / 1000.0; // Normalized length
        }

        // Unique syscall ratio
        if 31 < max_features {
            let unique: std::collections::HashSet<_> = syscall_names.iter().collect();
            features[31] = unique.len() as f32 / syscall_names.len().max(1) as f32;
        }

        features
    }

    /// Extract features from process event
    pub fn extract_process_features(
        executable: &str,
        command_line: &str,
        uid: u32,
        max_features: usize,
    ) -> Vec<f32> {
        let mut features = vec![0.0; max_features];

        // Executable risk indicators
        let shell_executables = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash"];
        let network_tools = ["nc", "netcat", "ncat", "socat", "curl", "wget"];
        let script_interpreters = ["python", "perl", "ruby", "php"];

        features[0] = if shell_executables.iter().any(|s| executable.contains(s)) {
            1.0
        } else {
            0.0
        };
        features[1] = if network_tools.iter().any(|s| executable.contains(s)) {
            1.0
        } else {
            0.0
        };
        features[2] = if script_interpreters.iter().any(|s| executable.contains(s)) {
            1.0
        } else {
            0.0
        };
        features[3] = if executable.contains("/tmp/") {
            1.0
        } else {
            0.0
        };

        // Command line analysis
        let suspicious_patterns = [
            "-c", "base64", "eval", "exec", "/dev/tcp", "/dev/udp", "wget", "curl", "rm -rf",
            "chmod +x",
        ];
        for (i, pattern) in suspicious_patterns.iter().enumerate() {
            if i + 4 < max_features {
                features[i + 4] = if command_line.contains(pattern) {
                    1.0
                } else {
                    0.0
                };
            }
        }

        // Command line length (normalized)
        if 14 < max_features {
            features[14] = (command_line.len() as f32 / 500.0).min(1.0);
        }

        // Pipe count
        if 15 < max_features {
            features[15] = command_line.matches('|').count() as f32 / 10.0;
        }

        // User ID risk
        if 16 < max_features {
            features[16] = if uid == 0 { 1.0 } else { 0.0 }; // root
        }

        features
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlp_forward() {
        let config = MlpConfig {
            input_size: 4,
            hidden_sizes: vec![4],
            output_size: 1,
            threshold: 0.5,
        };
        let detector = MlpDetector::with_config(config);

        let input = vec![0.5, 0.3, 0.8, 0.1];
        let output = detector.forward(&input);

        assert_eq!(output.len(), 1);
        assert!(output[0] >= 0.0 && output[0] <= 1.0);
    }

    #[test]
    fn test_mlp_detect() {
        let mut detector = MlpDetector::new();

        let features = vec![0.5; 64];
        let score = detector.detect(&features);

        assert!(score >= 0.0 && score <= 1.0);
        assert_eq!(detector.stats.total_inferences, 1);
    }

    #[test]
    fn test_feature_extraction() {
        let syscalls = vec!["execve", "mmap", "mprotect", "read", "write"];
        let features = features::extract_syscall_features(&syscalls, 64);

        assert_eq!(features.len(), 64);
        // Memory category should have count
        assert!(features[2] > 0.0);
    }

    #[test]
    fn test_weights_export_import() {
        let detector = MlpDetector::with_config(MlpConfig {
            input_size: 4,
            hidden_sizes: vec![2],
            output_size: 1,
            threshold: 0.5,
        });

        let weights_json = detector.export_weights();
        assert!(!weights_json.is_empty());

        let mut detector2 = MlpDetector::with_config(MlpConfig {
            input_size: 4,
            hidden_sizes: vec![2],
            output_size: 1,
            threshold: 0.5,
        });
        assert!(detector2.load_weights(&weights_json).is_ok());
    }
}
