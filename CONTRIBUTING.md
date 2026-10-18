# 贡献指南

感谢您对 WasmSentinel 项目的关注！我们欢迎各种形式的贡献。

## 🤝 如何贡献

### 报告问题

如果您发现了 bug 或有功能建议，请：

1. 检查 [Issues](https://github.com/GeoffreyWang1117/WasmSentinel/issues) 确保问题尚未被报告
2. 创建新 Issue，包含：
   - 详细的问题描述
   - 重现步骤
   - 预期行为和实际行为
   - 系统环境信息
   - 相关日志

### 提交代码

1. **Fork 项目**
   ```bash
   git clone https://github.com/your-username/wasmsentinel.git
   cd wasmsentinel
   ```

2. **创建特性分支**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **进行更改**
   - 遵循项目代码风格
   - 添加必要的测试
   - 更新文档

4. **提交更改**
   ```bash
   git add .
   git commit -m "feat: add new detection rule for XXX"
   ```

5. **推送分支**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **创建 Pull Request**

## 📝 代码规范

### Go 代码规范

- 使用 `go fmt` 格式化代码
- 使用 `go vet` 检查代码
- 添加适当的注释，特别是导出的函数和类型
- 错误处理要明确和一致

```go
// 好的示例
func LoadRule(name, path string) error {
    if name == "" {
        return fmt.Errorf("rule name cannot be empty")
    }
    
    // ... 实现
    return nil
}
```

### Rust 代码规范

- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 检查代码质量
- 优先使用安全的 Rust 代码，谨慎使用 `unsafe`
- 为公共函数添加文档注释

```rust
/// 检测进程事件中的威胁
/// 
/// # Arguments
/// * `event` - 进程事件数据
/// 
/// # Returns
/// * 威胁级别 (0-10)
fn detect_process_threat(event: &Value) -> i32 {
    // ... 实现
}
```

## 🧪 测试

### 运行测试

```bash
# Go 测试
cd host
go test ./...

# Rust 测试
cd rules/suspicious-shell
cargo test

# 集成测试
./scripts/test.sh
```

### 测试覆盖率

```bash
# Go 测试覆盖率
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Rust 测试覆盖率
cargo tarpaulin --out Html
```

## 📖 文档

### 文档更新

- API 变更需要更新相应文档
- 新功能需要添加使用示例
- 使用 Markdown 格式编写文档

### 文档结构

```
docs/
├── api.md              # API 文档
├── deployment.md       # 部署指南
├── development.md      # 开发指南
├── rules/             # 规则文档
│   ├── writing-rules.md
│   └── examples/
└── troubleshooting.md  # 故障排除
```

## 🔧 开发环境设置

### 依赖安装

```bash
# Go 1.19+
go version

# Rust 1.70+
rustc --version
rustup target add wasm32-wasip1

# 开发工具
go install golang.org/x/tools/cmd/goimports@latest
cargo install cargo-tarpaulin
```

### IDE 配置

推荐使用 VS Code 并安装以下插件：
- Go 官方插件
- Rust Analyzer
- WASM 插件

## 🎯 贡献类型

### 核心功能

- **事件收集器**：新的事件源（文件监控、网络流量等）
- **Wasm 引擎**：性能优化、新特性支持
- **输出处理器**：新的输出格式或集成

### 检测规则

我们特别欢迎新的检测规则贡献：

1. **恶意软件检测**
2. **网络入侵检测**
3. **权限提升检测**
4. **数据外泄检测**
5. **合规性检查**

### 规则贡献指南

1. 创建规则目录：`rules/your-rule-name/`
2. 实现检测逻辑
3. 添加测试用例
4. 编写规则文档
5. 提供使用示例

### 示例规则结构

```
rules/malware-detection/
├── Cargo.toml
├── src/
│   └── lib.rs
├── tests/
│   └── integration_tests.rs
├── README.md
└── examples/
    └── test_events.json
```

## 📊 性能考虑

### 性能要求

- Wasm 规则执行时间 < 1ms
- 内存使用 < 10MB per rule
- CPU 使用率 < 5% 平均负载

### 性能测试

```bash
# 性能基准测试
go test -bench=. ./internal/engine/
cargo bench
```

## 🔒 安全考虑

### 安全审查

所有涉及安全逻辑的代码都需要：

1. 安全代码审查
2. 静态分析检查
3. 渗透测试（如适用）

### 安全最佳实践

- 输入验证和清理
- 避免代码注入
- 最小权限原则
- 安全的默认配置

## 🎖️ 贡献者认可

### 贡献者类型

- **核心维护者**：长期贡献者，具有合并权限
- **规则作者**：编写和维护检测规则
- **文档贡献者**：改进文档和示例
- **测试贡献者**：添加测试用例和修复 bug
- **社区支持者**：回答问题，帮助新用户

### 认可方式

- 在 README 中列出贡献者
- 特殊贡献者获得 GitHub 徽章
- 年度贡献者奖励

## 📞 联系方式

- **GitHub Issues**: 技术问题和 bug 报告
- **GitHub Discussions**: 功能讨论和社区交流
- **安全问题**: 通过 GitHub Security Advisories 私下报告（https://github.com/GeoffreyWang1117/WasmSentinel/security/advisories），不要发公开 issue

## 📋 Pull Request 检查清单

提交 PR 前请确保：

- [ ] 代码遵循项目规范
- [ ] 添加了适当的测试
- [ ] 测试全部通过
- [ ] 更新了相关文档
- [ ] 提交信息清晰明确
- [ ] 已签署 CLA（如需要）

## 🔄 发布流程

### 版本规则

我们使用语义化版本控制：
- `MAJOR.MINOR.PATCH`
- 向后不兼容的 API 变更：MAJOR
- 向后兼容的功能增加：MINOR
- 向后兼容的 bug 修复：PATCH

### 发布周期

- **稳定版本**：每月发布
- **安全更新**：按需立即发布
- **预览版本**：每周发布

感谢您的贡献！🚀
