# WasmSentinel

A lightweight real-time threat detection tool based on WebAssembly

[![Build Status](https://github.com/GeoffreyWang1117/WasmSentinel/workflows/CI/badge.svg)](https://github.com/GeoffreyWang1117/WasmSentinel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Rust Version](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://rustlang.org)

[中文文档](./README_cn.md)

## 🎬 Live Demo

**🌐 [Visit Demo Website](https://geoffreywang1117.github.io/WasmSentinel/)** | **📖 [Demo Guide](./DEMO.md)** | **🧪 [Test Report](./TEST_REPORT.md)**

### Quick Experience
```bash
# One-click complete demo launch
git clone https://github.com/GeoffreyWang1117/WasmSentinel
cd WasmSentinel
./scripts/demo-complete.sh
```

## 🎯 Project Overview

WasmSentinel is a lightweight, secure, and portable real-time threat detection tool based on WebAssembly technology. It provides high-performance, low-latency security detection capabilities by running detection rules in a Wasm sandbox environment.

## ✨ Core Features

- **🚀 Real-time Detection**: Millisecond-level threat response with average latency < 1ms
- **🛡️ Security Isolation**: Wasm sandbox ensures detection modules cannot access host resources beyond authorization
- **💡 Lightweight**: Memory footprint < 32MB, suitable for edge and resource-constrained environments
- **🔌 Extensibility**: Detection rules as hot-pluggable Wasm modules, supporting multi-language development
- **📊 Observability**: Complete Prometheus metrics and structured logging
- **☁️ Cloud-Native**: Containerized deployment, Kubernetes integration, DevOps-friendly

## 🏗️ Architecture Design

```
┌─────────────────────────────────────────────────────────────┐
│                      WasmSentinel                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   eBPF      │  │  Event      │  │    Rule Engine      │  │
│  │  Collector  │─→│ Processor   │─→│   (Wasm Runtime)    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                                             │                │
│  ┌─────────────┐  ┌─────────────┐         ▼                │
│  │   Output    │◄─│   Alert     │  ┌─────────────────────┐  │
│  │  Handlers   │  │  Manager    │  │  Detection Rules    │  │
│  └─────────────┘  └─────────────┘  │   (Wasm Modules)    │  │
│                                    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Rust 1.70+ (for writing Wasm rules)
- Linux kernel 4.18+ (eBPF support)
- Docker 20.10+ (optional, for containerized deployment)

### Build Host Program

```bash
cd host
go mod tidy
go build -o wasm-sentinel ./cmd/main.go
```

### Build Sample Detection Rules

```bash
cd rules/suspicious-shell
cargo build --target wasm32-wasi --release
```

### Run Detector

```bash
./wasm-sentinel --rules ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or run demo environment
docker-compose -f docker-compose.demo.yml up -d
```

## 📁 Project Structure

```
.
├── README.md                      # English documentation
├── README_cn.md                   # Chinese documentation
├── host/                          # Host program (Go)
│   ├── cmd/
│   │   └── main.go                # Main entry point
│   ├── internal/
│   │   ├── collector/             # eBPF event collectors
│   │   ├── engine/                # Wasm rule engine
│   │   ├── events/                # Event definitions
│   │   └── output/                # Output handlers
│   ├── go.mod
│   └── go.sum
├── rules/                         # Detection rules (Wasm modules)
│   ├── suspicious-shell/          # Example: suspicious shell detection
│   └── opa-policy/                # OPA/Rego policy example
├── test-datasets/                 # Test datasets and attack simulations
│   ├── malicious-commands/        # Malicious command samples
│   ├── network-attacks/           # Network attack samples
│   ├── privilege-escalation/      # Privilege escalation samples
│   └── evaluation/                # Evaluation scripts
├── demo-website/                  # Demo website
├── docs/                          # Documentation
├── scripts/                       # Build and deployment scripts
├── monitoring/                    # Monitoring configurations
└── examples/                      # Usage examples
```

## 🔧 Writing Detection Rules

### Rust Example

```rust
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
pub struct Event {
    pub event_type: String,
    pub process: Option<ProcessInfo>,
    pub network: Option<NetworkInfo>,
    pub timestamp: i64,
}

#[derive(Serialize)]
pub struct DetectionResult {
    pub threat: bool,
    pub confidence: f32,
    pub severity: String,
    pub description: String,
}

#[wasm_bindgen]
pub fn detect_threat(event_json: &str) -> String {
    let event: Event = serde_json::from_str(event_json).unwrap_or_default();
    
    let result = match event.event_type.as_str() {
        "process" => detect_process_threat(&event),
        "network" => detect_network_threat(&event),
        _ => DetectionResult {
            threat: false,
            confidence: 0.0,
            severity: "info".to_string(),
            description: "Unknown event type".to_string(),
        }
    };
    
    serde_json::to_string(&result).unwrap()
}

fn detect_process_threat(event: &Event) -> DetectionResult {
    if let Some(process) = &event.process {
        // Detect dangerous commands
        let dangerous_commands = ["rm -rf", "dd if=", "mkfs", ":(){:|:&};:"];
        
        for cmd in dangerous_commands {
            if process.command.contains(cmd) {
                return DetectionResult {
                    threat: true,
                    confidence: 1.0,
                    severity: "critical".to_string(),
                    description: format!("Dangerous command detected: {}", cmd),
                };
            }
        }
    }
    
    DetectionResult {
        threat: false,
        confidence: 0.0,
        severity: "info".to_string(),
        description: "No threat detected".to_string(),
    }
}
```

## 🧪 Testing and Validation

### Quick Test

```bash
# Run quick validation test
./test-datasets/evaluation/quick_test.sh

# Run comprehensive test suite
./test-datasets/evaluation/comprehensive_test.sh

# Run performance benchmarks
./test-datasets/evaluation/performance_test.sh
```

### Simulate Attacks

```bash
# Simulate malicious commands
./test-datasets/malicious-commands/reverse_shell.sh

# Simulate network attacks
./test-datasets/network-attacks/network_attacks.sh

# Simulate privilege escalation
./test-datasets/privilege-escalation/privilege_escalation.sh
```

## 📊 Monitoring and Observability

### Health Check

```bash
curl http://localhost:8080/health
```

### Prometheus Metrics

```bash
curl http://localhost:8080/metrics
```

### Key Metrics

- `wasm_sentinel_total_threats`: Total number of threats detected
- `wasm_sentinel_detection_latency`: Detection latency histogram
- `wasm_sentinel_threats_by_severity`: Threats grouped by severity
- `wasm_sentinel_rules_loaded`: Number of loaded detection rules

## 🐳 Deployment

### Docker

```bash
# Build image
docker build -t wasm-sentinel .

# Run container
docker run -d -p 8080:8080 \
  -v $(pwd)/rules:/app/rules:ro \
  wasm-sentinel
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=wasm-sentinel

# View logs
kubectl logs -f deployment/wasm-sentinel
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/GeoffreyWang1117/WasmSentinel
cd WasmSentinel

# Install dependencies
./scripts/build.sh

# Run tests
./test-datasets/evaluation/comprehensive_test.sh
```

## 📚 Documentation

- [Demo Guide](./DEMO.md)
- [Test Report](./TEST_REPORT.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [Contributing Guide](./CONTRIBUTING.md)

## 🛣️ Roadmap

### v1.1.0 (Q4 2025)
- [ ] Machine learning-based anomaly detection
- [ ] Support for more Wasm runtimes
- [ ] Enhanced eBPF collectors
- [ ] Distributed deployment support

### v1.2.0 (Q1 2026)
- [ ] Web UI for rule management
- [ ] Rule marketplace and sharing
- [ ] Advanced threat hunting capabilities
- [ ] Integration with major SIEM platforms

## 🙏 Acknowledgments

- [WebAssembly Community](https://webassembly.org/) for the amazing runtime technology
- [Wasmtime](https://github.com/bytecodealliance/wasmtime) for the excellent Wasm runtime
- [eBPF Community](https://ebpf.io/) for system-level event collection capabilities
- All contributors and users who make this project possible

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

- **Author**: Zhaohui Wang
- **GitHub**: [@GeoffreyWang1117](https://github.com/GeoffreyWang1117)
- **Project**: [WasmSentinel](https://github.com/GeoffreyWang1117/WasmSentinel)
- **Issues**: [GitHub Issues](https://github.com/GeoffreyWang1117/WasmSentinel/issues)

---

**⭐ If you find WasmSentinel useful, please consider giving us a star on GitHub!**
