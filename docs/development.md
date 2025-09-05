# WasmSentinel 开发指南

## 编写检测规则

### Rust 规则开发

WasmSentinel 支持使用 Rust 编写检测规则。每个规则都是一个独立的 Wasm 模块。

#### 1. 创建新规则项目

```bash
cargo new --lib my-detection-rule
cd my-detection-rule
```

#### 2. 配置 Cargo.toml

```toml
[package]
name = "my-detection-rule"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
lto = true
opt-level = "s"
panic = "abort"
```

#### 3. 实现检测逻辑

```rust
use serde_json::Value;

#[no_mangle]
pub extern "C" fn detect(event_ptr: *const u8, event_len: usize) -> i32 {
    // 读取事件数据
    let event_data = unsafe {
        if event_ptr.is_null() || event_len == 0 {
            return 0;
        }
        std::slice::from_raw_parts(event_ptr, event_len)
    };

    // 解析 JSON 事件
    let event: Value = match serde_json::from_slice(event_data) {
        Ok(event) => event,
        Err(_) => return 0,
    };

    // 实现您的检测逻辑
    detect_custom_threat(&event)
}

fn detect_custom_threat(event: &Value) -> i32 {
    // 您的检测逻辑
    // 返回 0-10 的威胁级别
    0
}
```

#### 4. 构建规则

```bash
cargo build --target wasm32-wasi --release
```

### Go 规则开发 (TinyGo)

```go
package main

import (
    "encoding/json"
    "unsafe"
)

//export detect
func detect(eventPtr *byte, eventLen int) int32 {
    // 读取事件数据
    eventData := (*[1 << 30]byte)(unsafe.Pointer(eventPtr))[:eventLen:eventLen]
    
    // 解析 JSON
    var event map[string]interface{}
    if err := json.Unmarshal(eventData, &event); err != nil {
        return 0
    }
    
    // 检测逻辑
    return detectThreat(event)
}

func detectThreat(event map[string]interface{}) int32 {
    // 实现检测逻辑
    return 0
}

func main() {}
```

构建：
```bash
tinygo build -o rule.wasm -target wasi main.go
```

### AssemblyScript 规则开发

```typescript
import { JSON } from "assemblyscript-json";

export function detect(eventPtr: usize, eventLen: i32): i32 {
    // 读取事件数据
    const eventData = String.UTF8.decodeUnsafe(eventPtr, eventLen);
    
    // 解析 JSON
    const event = JSON.parse(eventData);
    
    // 检测逻辑
    return detectThreat(event);
}

function detectThreat(event: JSON.Obj): i32 {
    // 实现检测逻辑
    return 0;
}
```

## 事件数据格式

### 进程事件

```json
{
    "id": "proc_1234_1677123456",
    "type": "process",
    "timestamp": "2024-02-23T10:30:00Z",
    "source": "process_collector",
    "data": {
        "action": "create",
        "process": {
            "pid": 1234,
            "ppid": 1,
            "name": "bash",
            "executable": "/bin/bash",
            "command_line": "/bin/bash -c 'echo hello'",
            "user": "root",
            "group": "root"
        }
    }
}
```

### 网络事件

```json
{
    "id": "net_192.168.1.100:4444_1677123456",
    "type": "network",
    "timestamp": "2024-02-23T10:30:00Z",
    "source": "network_collector",
    "data": {
        "network": {
            "protocol": "tcp",
            "source_ip": "192.168.1.100",
            "source_port": 12345,
            "dest_ip": "malicious.example.com",
            "dest_port": 4444,
            "direction": "outbound",
            "data_size": 1024,
            "process_name": "nc"
        }
    }
}
```

### 文件事件

```json
{
    "id": "file_etc_passwd_1677123456",
    "type": "file",
    "timestamp": "2024-02-23T10:30:00Z",
    "source": "file_collector",
    "data": {
        "file": {
            "path": "/etc/passwd",
            "operation": "read",
            "permissions": "0644",
            "process_name": "cat",
            "user": "attacker"
        }
    }
}
```

## 威胁级别定义

返回的威胁级别应该在 0-10 范围内：

- **0**: 无威胁
- **1-2**: 信息级别（Info）
- **3-4**: 低风险（Low）
- **5-6**: 中等风险（Medium）
- **7-8**: 高风险（High）
- **9-10**: 严重威胁（Critical）

## 测试规则

### 单元测试

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_detect_shell_process() {
        let event = json!({
            "type": "process",
            "data": {
                "process": {
                    "name": "bash",
                    "executable": "/bin/bash",
                    "command_line": "/bin/bash -c 'rm -rf /'"
                }
            }
        });

        let event_str = serde_json::to_string(&event).unwrap();
        let event_bytes = event_str.as_bytes();
        
        let result = detect(event_bytes.as_ptr(), event_bytes.len());
        assert!(result > 5); // 应该检测为高风险
    }
}
```

### 集成测试

```bash
# 构建规则
cargo build --target wasm32-wasi --release

# 测试规则
./wasm-threat-detector \
  --rules ./target/wasm32-wasi/release/my_rule.wasm \
  --log-level debug
```

## 性能优化

### Wasm 优化

1. **编译优化**：
   ```toml
   [profile.release]
   lto = true
   opt-level = "s"  # 优化大小
   panic = "abort"
   ```

2. **减少依赖**：只引入必要的 crate

3. **避免动态分配**：使用栈分配和固定大小的数据结构

### 宿主程序优化

1. **事件缓冲**：使用缓冲通道减少上下文切换
2. **规则缓存**：缓存已编译的 Wasm 模块
3. **并行处理**：使用 goroutine 并行处理事件

## 调试技巧

### 日志调试

```rust
// 在 Wasm 中使用简单的日志
#[no_mangle]
pub extern "C" fn log_message(ptr: *const u8, len: usize) {
    // 实现日志输出到宿主程序
}
```

### 宿主程序调试

```bash
# 启用详细日志
./wasm-threat-detector --log-level debug

# 使用 strace 监控系统调用
strace -f ./wasm-threat-detector

# 使用 perf 分析性能
perf record ./wasm-threat-detector
perf report
```

## 最佳实践

1. **错误处理**：始终检查输入数据的有效性
2. **内存安全**：在 unsafe 代码中仔细检查指针和长度
3. **性能考虑**：避免复杂的正则表达式和重复计算
4. **可维护性**：将检测逻辑模块化，便于测试和维护
5. **文档**：为每个规则编写清晰的文档说明其用途和检测逻辑
