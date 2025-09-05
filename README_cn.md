# WasmSentinel

基于 WebAssembly 的轻量级实时威胁检测工具

[![Build Status](https://github.com/GeoffreyWang1117/WasmSentinel/workflows/CI/badge.svg)](https://github.com/GeoffreyWang1117/WasmSentinel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Rust Version](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://rustlang.org)

[English Documentation](./README.md)

## 🎬 在线演示

**🌐 [访问演示网站](https://geoffreywang1117.github.io/WasmSentinel/)** | **📖 [演示指南](./DEMO.md)** | **🧪 [测试报告](./TEST_REPORT.md)**

### 快速体验
```bash
# 一键启动完整演示
git clone https://github.com/GeoffreyWang1117/WasmSentinel
cd WasmSentinel
./scripts/demo-complete.sh
```

## 🎯 项目概述

WasmSentinel 是一个基于 WebAssembly 技术的轻量级、安全、可移植的实时威胁检测工具。通过 Wasm 沙箱环境运行检测规则，提供高性能、低延迟的安全检测能力。

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
│                      WasmSentinel                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   eBPF      │  │  事件       │  │    规则引擎         │  │
│  │  收集器     │─→│ 处理器      │─→│   (Wasm 运行时)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                                             │                │
│  ┌─────────────┐  ┌─────────────┐         ▼                │
│  │   输出      │◄─│   告警      │  ┌─────────────────────┐  │
│  │  处理器     │  │  管理器     │  │  检测规则           │  │
│  └─────────────┘  └─────────────┘  │   (Wasm 模块)       │  │
│                                    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 快速开始

### 环境要求

- Go 1.21+
- Rust 1.70+ (用于编写 Wasm 规则)
- Linux kernel 4.18+ (eBPF 支持)
- Docker 20.10+ (可选，用于容器化部署)

### 构建主程序

```bash
cd host
go mod tidy
go build -o wasm-sentinel ./cmd/main.go
```

### 构建示例检测规则

```bash
cd rules/suspicious-shell
cargo build --target wasm32-wasi --release
```

### 运行检测器

```bash
./wasm-sentinel --rules ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm
```

### Docker 部署

```bash
# 使用 Docker Compose 构建和运行
docker-compose up -d

# 或运行演示环境
docker-compose -f docker-compose.demo.yml up -d
```

## 📁 项目结构

```
.
├── README.md                      # 英文文档
├── README_cn.md                   # 中文文档
├── host/                          # 宿主程序 (Go)
│   ├── cmd/
│   │   └── main.go                # 主入口点
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
├── test-datasets/                 # 测试数据集和攻击模拟
│   ├── malicious-commands/        # 恶意命令样本
│   ├── network-attacks/           # 网络攻击样本
│   ├── privilege-escalation/      # 权限提升样本
│   └── evaluation/                # 评估脚本
├── demo-website/                  # 演示网站
├── docs/                          # 文档
├── scripts/                       # 构建和部署脚本
├── monitoring/                    # 监控配置
└── examples/                      # 使用示例
```

## 🔧 编写检测规则

### Rust 示例

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
            description: "未知事件类型".to_string(),
        }
    };
    
    serde_json::to_string(&result).unwrap()
}

fn detect_process_threat(event: &Event) -> DetectionResult {
    if let Some(process) = &event.process {
        // 检测危险命令
        let dangerous_commands = ["rm -rf", "dd if=", "mkfs", ":(){:|:&};:"];
        
        for cmd in dangerous_commands {
            if process.command.contains(cmd) {
                return DetectionResult {
                    threat: true,
                    confidence: 1.0,
                    severity: "critical".to_string(),
                    description: format!("检测到危险命令: {}", cmd),
                };
            }
        }
    }
    
    DetectionResult {
        threat: false,
        confidence: 0.0,
        severity: "info".to_string(),
        description: "未检测到威胁".to_string(),
    }
}
```

## 🧪 测试和验证

### 快速测试

```bash
# 运行快速验证测试
./test-datasets/evaluation/quick_test.sh

# 运行综合测试套件
./test-datasets/evaluation/comprehensive_test.sh

# 运行性能基准测试
./test-datasets/evaluation/performance_test.sh
```

### 模拟攻击

```bash
# 模拟恶意命令
./test-datasets/malicious-commands/reverse_shell.sh

# 模拟网络攻击
./test-datasets/network-attacks/network_attacks.sh

# 模拟权限提升
./test-datasets/privilege-escalation/privilege_escalation.sh
```

## 📊 监控和可观测性

### 健康检查

```bash
curl http://localhost:8080/health
```

### Prometheus 指标

```bash
curl http://localhost:8080/metrics
```

### 关键指标

- `wasm_sentinel_total_threats`: 检测到的威胁总数
- `wasm_sentinel_detection_latency`: 检测延迟直方图
- `wasm_sentinel_threats_by_severity`: 按严重程度分组的威胁
- `wasm_sentinel_rules_loaded`: 已加载的检测规则数量

## 🐳 部署

### Docker

```bash
# 构建镜像
docker build -t wasm-sentinel .

# 运行容器
docker run -d -p 8080:8080 \
  -v $(pwd)/rules:/app/rules:ro \
  wasm-sentinel
```

### Kubernetes

```bash
# 部署到 Kubernetes
kubectl apply -f k8s/

# 检查部署状态
kubectl get pods -l app=wasm-sentinel

# 查看日志
kubectl logs -f deployment/wasm-sentinel
```

## 🤝 贡献

我们欢迎贡献！请查看我们的[贡献指南](CONTRIBUTING.md)了解详情。

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/GeoffreyWang1117/WasmSentinel
cd WasmSentinel

# 安装依赖
./scripts/build.sh

# 运行测试
./test-datasets/evaluation/comprehensive_test.sh
```

## 📚 文档

- [演示指南](./DEMO.md)
- [测试报告](./TEST_REPORT.md)
- [部署指南](./DEPLOYMENT.md)
- [贡献指南](./CONTRIBUTING.md)

## 🛣️ 路线图

### v1.1.0 (2025年第四季度)
- [ ] 基于机器学习的异常检测
- [ ] 支持更多 Wasm 运行时
- [ ] 增强的 eBPF 收集器
- [ ] 分布式部署支持

### v1.2.0 (2026年第一季度)
- [ ] 规则管理的 Web UI
- [ ] 规则市场和共享
- [ ] 高级威胁狩猎功能
- [ ] 与主要 SIEM 平台集成

## 🙏 致谢

- [WebAssembly 社区](https://webassembly.org/) 提供了出色的运行时技术
- [Wasmtime](https://github.com/bytecodealliance/wasmtime) 提供了优秀的 Wasm 运行时
- [eBPF 社区](https://ebpf.io/) 提供了系统级事件收集功能
- 所有让这个项目成为可能的贡献者和用户

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 📧 联系方式

- **作者**: 王朝晖 (Zhaohui Wang)
- **GitHub**: [@GeoffreyWang1117](https://github.com/GeoffreyWang1117)
- **项目**: [WasmSentinel](https://github.com/GeoffreyWang1117/WasmSentinel)
- **问题反馈**: [GitHub Issues](https://github.com/GeoffreyWang1117/WasmSentinel/issues)

---

**⭐ 如果您觉得 WasmSentinel 有用，请考虑在 GitHub 上给我们一个星标！**
