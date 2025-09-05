# 🎬 演示指南

## 🚀 在线演示

### GitHub Pages 演示网站
访问我们的在线演示：**https://your-username.github.io/WASM-ThreatDetector/**

> 注意：请将 `your-username` 替换为您的 GitHub 用户名

### 演示内容
- 📊 实时威胁检测展示
- 🏗️ 系统架构介绍  
- 📖 详细技术文档
- 🔧 API 接口说明
- 📈 性能指标展示

## 💻 本地演示

### 快速演示 (推荐)
一键启动完整演示环境：

```bash
# 克隆项目
git clone https://github.com/your-username/WASM-ThreatDetector
cd WASM-ThreatDetector

# 运行完整演示
./scripts/demo-complete.sh
```

演示将自动：
1. ✅ 检查依赖环境
2. 🔧 构建项目组件
3. 🚀 启动威胁检测器
4. 🌐 启动演示网站
5. 🔥 执行模拟攻击
6. 📊 展示检测结果
7. 🧪 运行自动化测试

### Docker 演示环境
使用 Docker Compose 启动完整的演示环境：

```bash
# 启动演示环境
docker-compose -f docker-compose.demo.yml up -d

# 查看服务状态
docker-compose -f docker-compose.demo.yml ps

# 查看日志
docker-compose -f docker-compose.demo.yml logs -f wasm-threat-detector
```

### 访问地址
- 🛡️ **威胁检测器**: http://localhost:8080
  - 健康检查: http://localhost:8080/health
  - 指标数据: http://localhost:8080/metrics
- 🌐 **演示网站**: http://localhost:3000
- 📊 **Prometheus**: http://localhost:9090
- 📈 **Grafana**: http://localhost:3001 (admin/demo123)

## 🧪 测试演示

### 基础功能测试
```bash
# 健康检查
curl http://localhost:8080/health

# 查看指标
curl http://localhost:8080/metrics

# 快速功能验证
./test-datasets/evaluation/quick_test.sh
```

### 威胁检测演示
```bash
# 模拟恶意命令
bash -c 'echo "rm -rf /" | cat'

# 模拟反向Shell
timeout 2 nc -l 4444

# 模拟网络扫描
nmap -p 22,80,443 localhost

# 查看检测结果
tail -f /tmp/wasm-threat-detector-test/*.log
```

### 性能测试
```bash
# 运行性能基准测试
./test-datasets/evaluation/performance_test.sh

# 压力测试
ab -n 1000 -c 10 http://localhost:8080/health
```

## 📖 演示场景

### 1. 实时威胁检测
- 🚨 **恶意命令检测**: 识别危险系统命令
- 🔍 **进程监控**: 监测可疑进程行为
- 🌐 **网络异常**: 检测异常网络连接
- 🔑 **权限提升**: 发现权限滥用尝试

### 2. 性能展示
- ⚡ **毫秒级响应**: 平均检测延迟 < 1ms
- 💾 **低资源占用**: 内存使用 < 32MB
- 🔄 **高并发处理**: 支持大量并发事件
- 📊 **实时指标**: Prometheus 格式指标

### 3. 架构演示
- 🧊 **WASM 沙箱**: 安全隔离的规则执行
- 🔌 **模块化设计**: 可插拔的检测规则
- 🐳 **容器化部署**: Docker & Kubernetes 支持
- 📈 **监控集成**: 完整的 DevOps 工具链

## 🛠️ 自定义演示

### 添加自定义规则
```bash
# 创建新规则
cd rules
cargo new --lib my-custom-rule
cd my-custom-rule

# 编写检测逻辑 (Rust)
cat > src/lib.rs << 'EOF'
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn detect_threat(event_json: &str) -> String {
    // 自定义检测逻辑
    "{\"threat\":false,\"confidence\":0.0}".to_string()
}
EOF

# 构建规则
cargo build --target wasm32-wasi --release

# 加载规则
./wasm-threat-detector --rules ./rules/my-custom-rule/target/wasm32-wasi/release/my_custom_rule.wasm
```

### 集成外部系统
```bash
# SIEM 集成示例
curl -X POST http://your-siem/api/events \
  -H "Content-Type: application/json" \
  -d @<(curl -s http://localhost:8080/api/events/latest)

# 告警通知
curl -X POST https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK \
  -H "Content-Type: application/json" \
  -d '{"text":"🚨 WASM-ThreatDetector: 检测到严重威胁!"}'
```

## 🔧 故障排除

### 常见问题
1. **端口占用**: 修改 `docker-compose.demo.yml` 中的端口映射
2. **权限问题**: 确保用户有 Docker 执行权限
3. **资源不足**: 至少需要 2GB RAM 和 1GB 磁盘空间
4. **网络问题**: 检查防火墙和代理设置

### 日志查看
```bash
# 检测器日志
docker logs wasm-detector-demo

# 网站日志
docker logs demo-website

# 监控日志
docker logs prometheus-demo
docker logs grafana-demo
```

### 重置环境
```bash
# 停止所有服务
docker-compose -f docker-compose.demo.yml down

# 清理数据卷
docker-compose -f docker-compose.demo.yml down -v

# 重新启动
docker-compose -f docker-compose.demo.yml up -d
```

## 📚 更多资源

- 📖 [详细文档](./docs/development.md)
- 🧪 [测试报告](./TEST_REPORT.md)
- 🏗️ [架构设计](./docs/architecture.md)
- 🤝 [贡献指南](./CONTRIBUTING.md)
- 🐛 [问题报告](https://github.com/your-username/WASM-ThreatDetector/issues)

---

**享受演示！如果您喜欢这个项目，请给我们一个 ⭐**
