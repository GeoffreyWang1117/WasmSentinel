# 快速开始指南

## 🚀 5 分钟快速体验

### 前置条件

- **Go 1.19+**: `go version`
- **Rust 1.70+**: `rustc --version`
- **Linux 系统**: Ubuntu 18.04+ 或其他主流发行版

### 1. 克隆项目

```bash
git clone https://github.com/your-username/wasm-threat-detector.git
cd wasm-threat-detector
```

### 2. 一键构建

```bash
./scripts/build.sh
```

### 3. 快速演示

```bash
./scripts/demo.sh
```

## 🔧 详细安装

### 安装依赖

#### Ubuntu/Debian
```bash
# 安装 Go
sudo apt update
sudo apt install golang-go

# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-wasip1
```

#### CentOS/RHEL
```bash
# 安装 Go
sudo yum install golang

# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-wasip1
```

#### macOS
```bash
# 使用 Homebrew
brew install go rust
rustup target add wasm32-wasip1
```

### 手动构建

```bash
# 1. 构建 Wasm 规则
cd rules/suspicious-shell
cargo build --target wasm32-wasip1 --release
cd ../..

# 2. 构建主程序
cd host
go mod tidy
go build -o ../wasm-threat-detector ./cmd/main.go
cd ..
```

## 🎯 基本使用

### 启动检测器

```bash
# 基本启动
./wasm-threat-detector --rules ./rules/suspicious-shell/target/wasm32-wasip1/release/suspicious_shell.wasm

# 详细日志
./wasm-threat-detector \
  --rules ./rules \
  --log-level debug \
  --log-file /tmp/threats.log

# 使用配置文件
./wasm-threat-detector --config ./examples/config.yaml
```

### 查看指标

```bash
# Prometheus 指标
curl http://localhost:8080/metrics

# 健康检查
curl http://localhost:8080/health
```

## 🐳 Docker 部署

### 快速启动

```bash
# 构建镜像
docker build -t wasm-threat-detector .

# 运行容器
docker run -d \
  --name threat-detector \
  --privileged \
  --pid host \
  --network host \
  -v /proc:/host/proc:ro \
  wasm-threat-detector
```

### 使用 Docker Compose

```bash
# 启动完整监控栈
docker-compose up -d

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs wasm-threat-detector
```

### 访问监控界面

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (admin/admin)
- **AlertManager**: http://localhost:9093
- **Kibana**: http://localhost:5601

## ☸️ Kubernetes 部署

### 简单部署

```bash
# 创建命名空间
kubectl create namespace security

# 部署 DaemonSet
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wasm-threat-detector
  namespace: security
spec:
  selector:
    matchLabels:
      app: wasm-threat-detector
  template:
    metadata:
      labels:
        app: wasm-threat-detector
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: threat-detector
        image: wasm-threat-detector:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
          readOnly: true
      volumes:
      - name: proc
        hostPath:
          path: /proc
EOF
```

## 🔍 验证安装

### 检查进程

```bash
# 检查主进程
ps aux | grep wasm-threat-detector

# 检查端口
netstat -tlnp | grep 8080
```

### 生成测试事件

```bash
# 执行一些可疑命令来测试检测
/bin/bash -c "echo 'test command'"
cat /etc/passwd > /dev/null
```

### 查看检测结果

```bash
# 查看日志
tail -f /tmp/threats.log

# 查看指标
curl -s http://localhost:8080/metrics | grep threat
```

## 🛠️ 故障排除

### 常见问题

#### 1. 权限错误
```bash
# 确保以 root 权限运行
sudo ./wasm-threat-detector

# 或添加必要的 capabilities
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep ./wasm-threat-detector
```

#### 2. Wasm 模块加载失败
```bash
# 检查 Wasm 文件
file rules/suspicious-shell/target/wasm32-wasip1/release/suspicious_shell.wasm

# 重新构建规则
cd rules/suspicious-shell && cargo clean && cargo build --target wasm32-wasip1 --release
```

#### 3. 网络连接问题
```bash
# 检查端口占用
sudo lsof -i :8080

# 修改端口
./wasm-threat-detector --metrics-port 8081
```

### 调试模式

```bash
# 启用详细日志
./wasm-threat-detector --log-level debug

# 使用 strace 调试
sudo strace -f ./wasm-threat-detector

# 使用 gdb 调试
gdb ./wasm-threat-detector
```

## 📚 下一步

- 📖 [开发指南](docs/development.md) - 编写自定义规则
- 🚀 [部署指南](docs/deployment.md) - 生产环境部署
- 🤝 [贡献指南](CONTRIBUTING.md) - 参与项目贡献
- 📊 [监控指南](docs/monitoring.md) - 设置监控和告警

## 🆘 获取帮助

- **GitHub Issues**: 报告 bug 和功能请求
- **GitHub Discussions**: 技术讨论和问答
- **文档**: 查看 `docs/` 目录下的详细文档

欢迎加入 WASM-ThreatDetector 社区！🎉
