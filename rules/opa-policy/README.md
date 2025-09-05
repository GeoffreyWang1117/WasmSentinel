# OPA/Rego 策略规则

## 概述

本目录包含使用 Open Policy Agent (OPA) Rego 语言编写的威胁检测策略。这些策略可以编译为 WebAssembly 模块并在 WASM-ThreatDetector 中运行。

## 安装 OPA

```bash
# Linux
curl -L -o opa https://openpolicyagent.org/downloads/v0.57.0/opa_linux_amd64_static
chmod +x opa

# macOS
brew install opa
```

## 编译策略为 Wasm

```bash
# 编译单个策略
opa build -t wasm example.rego

# 编译策略包
opa build -t wasm -b policy/
```

## 策略结构

```rego
package threat.detection

# 默认决策
default allow = false
default threat_level = 0

# 检测规则
threat_level = level {
    input.type == "process"
    suspicious_process
    level := 7
}

suspicious_process {
    input.data.process.name == "bash"
    contains(input.data.process.command_line, "rm -rf")
}
```

## 集成到检测器

1. 编译策略为 Wasm
2. 将生成的 `bundle.tar.gz` 解压
3. 使用 `/policy.wasm` 文件作为规则模块
