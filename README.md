# WasmSentinel

> 📋 **改进方案**: 本仓有一份经过实查的改进方案 —— [`IMPROVEMENT_PLAN.md`](IMPROVEMENT_PLAN.md)（2026-10-13）。
> 🗺️ **开发计划（2026-10-16，取代 CCS2026_ROADMAP/RESEARCH/SESSION_STATE）**: [`DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md) —— 含证据链审计、AsiaCCS 2027 C2 时间线与 Go/No-Go 门禁。
> 跨项目索引（仓库外，本机）: `~/Engineering/ENGINEERING_IMPROVEMENT_INDEX_2026-10-13.md`


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

### Build

```bash
./scripts/build.sh      # host binary ./wasmsentinel + rules/wasm/{suspicious_shell,ml_detector}.wasm
make test               # Go (race) + Rust tests
make reproduce          # experiments -> evaluation/results/2026-11/ (isolation table, model parity)
```

### Run Detector

```bash
./wasmsentinel --rules ./rules/wasm
```

### Collectors

| flag / config key | values | notes |
|---|---|---|
| `--collector` | `proc` (default), `ebpf` | `ebpf` attaches the programs in `host/internal/ebpf/bpf/sentinel.bpf.c`; needs root (CAP_BPF + CAP_PERFMON) and a BTF-enabled kernel |
| `--ebpf-hooks` | `all` (default) or a comma list of `exec,exit,open,connect,accept,syscall` | one BPF program per hook; drop `open` on busy hosts, it dominates the volume |
| `--collector=replay` with `--replay-file`, `--replay-eps`, `--replay-loop` | a trace file or directory (ADFA-LD format: whitespace-separated syscall numbers) | replays recorded syscalls as events, paced at `--replay-eps` (0 = as fast as possible); the process exits when the trace ends unless `--replay-loop` |
| `--rule-train-dir` | directory of normal traces (same format) | at startup, feeds every rule that exports `train_sequence` (the ml_detector's STIDE normal database), then calls `train_finish` |
| `--rule-config` | `name=file` (repeatable or comma-separated) | hands the file's bytes to that rule's `init` export on every instantiation, including re-instantiation after a trap; a non-zero return fails the load instead of running the rule with defaults. `ml_detector=rf.json` with `{"model":"rf"}` switches the ml_detector's deep path from the MLP to the embedded random forest |

```bash
sudo ./wasmsentinel --collector=ebpf --rules ./rules/wasm            # all hooks
sudo ./wasmsentinel --collector=ebpf --ebpf-hooks=exec,connect,accept --log-level trace
./wasmsentinel --collector=replay --replay-file evaluation/datasets/raw/ADFA-LD/ADFA-LD/Attack_Data_Master --event-encoding=binary --rules ./rules/wasm
```

The eBPF path delivers exec events with the resolved path and the full argv,
file opens with path and flags, TCP connect/accept with peer address, and an
allow-list of high-risk syscalls by name. The JSON shape handed to rules is
documented on `collector.EventFromEBPF`.

### Event encoding

| flag / config key | values | notes |
|---|---|---|
| `--event-encoding` | `json` (default), `binary` | `binary` hands eBPF events to a rule's `detect_raw` export as the kernel record plus resolved names (`host/internal/wire`, `rules/sentinel-abi`); rules without the export, and events without a binary form, fall back to JSON |

Both paths give the same verdict for the same event (tested on every event
type). On this machine the binary path halves the end-to-end cost per event for
a rule that reads fields directly from the record (5.6 µs vs 11.7 µs).

### Rule sandbox limits

Every rule runs in its own long-lived wasmtime instance under three independent
limits (see `host/internal/engine`). A rule that exceeds one of them traps, is
re-instantiated on its next event, and never affects the other rules.

| flag / config key | default | enforced by |
|---|---|---|
| `--rule-memory-mb` | 64 | store limiter: `memory.grow` past the cap fails inside the guest |
| `--rule-fuel` | 50000000 | wasmtime fuel: instruction budget per `detect` call (0 = off) |
| `--rule-timeout` | 100ms | epoch interruption: wall-clock budget per `detect` call (0 = off) |

Guests get a WASI context with no capabilities: no inherited stdio, no environment,
no arguments, no preopened directories. The guest ABI a rule must export is
documented in [`rules/wasm/README.md`](rules/wasm/README.md).

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

All series are real counters fed by the pipeline (namespace `wasmsentinel`):

| metric | labels | source |
|---|---|---|
| `threats_total` | rule, severity | output path, one increment per detection |
| `events_total`, `events_dropped_total`, `detect_latency_seconds` | type | event loop |
| `rule_calls_total`, `rule_errors_total`, `rule_fuel_total`, `rule_latency_seconds` | rule, encoding / kind | engine observer, one callback per rule invocation |
| `rule_memory_bytes`, `rule_reinstantiations_total`, `rule_positive_calls_total` | rule | engine snapshot at scrape time |
| `collector_records_total`, `collector_dropped_total`, `collector_events_total` | type | eBPF collector snapshot (`--collector=ebpf`) |
| `build_info` | collector, encoding, wasmtime | constant 1 |
| `process_resident_memory_bytes`, `go_*` | | standard process and Go runtime collectors |

## 🐳 Deployment

### Docker

```bash
# Build image
docker build -t wasmsentinel .

# Run container
docker run -d -p 8080:8080 \
  -v $(pwd)/rules:/app/rules:ro \
  wasmsentinel
```

### Kubernetes

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=wasmsentinel

# View logs
kubectl logs -f deployment/wasmsentinel
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
