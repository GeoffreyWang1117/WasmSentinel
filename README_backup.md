# WASM-ThreatDetector

基于 WebAssembly 的轻量化实时威胁检测工具

[![Build Status](https://github.com/your-username/WASM-ThreatDetector/workflows/CI/badge.svg)](https://github.com/your-username/WASM-ThreatDetector/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Rust Version](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://rustlang.org)

## 🎬 在线演示

**� [访问演示网站](https://your-username.github.io/WASM-ThreatDetector/)** | **📖 [演示指南](./DEMO.md)** | **🧪 [测试报告](./TEST_REPORT.md)**

### 快速体验
```bash
# 一键启动完整演示
git clone https://github.com/your-username/WASM-ThreatDetector
cd WASM-ThreatDetector
./scripts/demo-complete.sh
```

## �🎯 项目概述

WASM-ThreatDetector 是一个基于 WebAssembly 技术的轻量级、安全、可移植的实时威胁检测工具。通过 Wasm 沙箱环境运行检测规则，提供高性能、低延迟的安全检测能力。

## ✨ 核心特性

- **🚀 实时检测**：毫秒级威胁响应，平均延迟 < 1ms
- **🛡️ 安全隔离**：Wasm 沙箱确保检测模块无法越权访问主机资源
- **💡 轻量化**：内存占用 < 32MB，适合边缘和资源受限环境
- **🔌 可扩展性**：检测规则以 Wasm 模块形式热插拔，支持多语言开发
- **📊 可观测性**：完整的 Prometheus 指标和结构化日志
- **☁️ 云原生**：容器化部署，Kubernetes 集成，DevOps 友好

## 🏗️ 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    WASM-ThreatDetector                      │
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

## 🚀 快速开始

### 构建主程序

```bash
cd host
go mod tidy
go build -o wasm-threat-detector ./cmd/main.go
```

### 构建示例检测规则

```bash
cd rules/suspicious-shell
cargo build --target wasm32-wasi --release
```

### 运行检测器

```bash
./wasm-threat-detector --rules ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm
```

## 📁 项目结构

```
.
├── README.md
├── host/                          # 宿主程序 (Go)
│   ├── cmd/
│   │   └── main.go                # 主入口
│   ├── internal/
│   │   ├── collector/             # eBPF 事件收集器
│   │   ├── engine/                # Wasm 规则引擎
│   │   ├── events/                # 事件定义
│   │   └── output/                # 输出处理器
│   ├── go.mod
│   └── go.sum
├── rules/                         # 检测规则 (Wasm 模块)
│   ├── suspicious-shell/          # 示例：可疑 shell 检测
│   └── opa-policy/                # OPA/Rego 策略示例
├── examples/                      # 使用示例
├── docs/                          # 文档
└── scripts/                       # 构建和部署脚本
```

## 🔧 开发环境要求

- Go 1.19+
- Rust 1.70+ (用于编写 Wasm 规则)
- Linux kernel 4.18+ (eBPF 支持)

## 📖 编写检测规则

### Rust 示例

```rust
use serde_json::Value;

#[no_mangle]
pub extern "C" fn detect(event_ptr: *const u8, event_len: usize) -> u32 {
    // 解析事件数据
    let event_data = unsafe { 
        std::slice::from_raw_parts(event_ptr, event_len) 
    };
    
    let event: Value = serde_json::from_slice(event_data).unwrap();
    
    // 检测逻辑
    if let Some(process_name) = event["process"]["name"].as_str() {
        if process_name.contains("/bin/sh") || process_name.contains("bash") {
            return 1; // 检测到威胁
        }
    }
    
    0 // 无威胁
}
```

## 🤝 贡献指南

我们欢迎社区贡献！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详细信息。

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 🔗 相关链接

- [WebAssembly](https://webassembly.org/)
- [eBPF](https://ebpf.io/)
- [Wasmtime](https://wasmtime.dev/)
- [Open Policy Agent](https://www.openpolicyagent.org/)
