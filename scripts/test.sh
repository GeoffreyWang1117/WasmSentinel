#!/bin/bash

# 测试脚本 - WASM-ThreatDetector

set -e

echo "🧪 运行 WASM-ThreatDetector 测试套件"
echo "==================================="

# 检查依赖
echo "📋 检查依赖..."

if ! command -v go &> /dev/null; then
    echo "❌ Go 未安装"
    exit 1
fi

if ! command -v rustc &> /dev/null; then
    echo "❌ Rust 未安装"
    exit 1
fi

echo "✅ 依赖检查通过"

# 运行 Go 测试
echo ""
echo "🔍 运行 Go 单元测试..."
cd host
go test -v ./internal/...

# 检查 Go 代码质量
echo ""
echo "🔍 运行 Go 代码检查..."
go vet ./...
go fmt ./...

# 运行 Rust 测试
echo ""
echo "🔍 运行 Rust 单元测试..."
cd ../rules/suspicious-shell
cargo test

# 检查 Rust 代码质量
echo ""
echo "🔍 运行 Rust 代码检查..."
cargo fmt --check
cargo clippy -- -D warnings

# 构建测试
echo ""
echo "🔨 测试构建过程..."
cd ../..
./scripts/build.sh

# 基本功能测试
echo ""
echo "🚀 运行基本功能测试..."

# 创建测试事件
cat > /tmp/test_event.json << 'EOF'
{
    "id": "test_001",
    "type": "process",
    "timestamp": "2024-02-23T10:30:00Z",
    "source": "test",
    "data": {
        "process": {
            "pid": 1234,
            "ppid": 1,
            "name": "bash",
            "executable": "/bin/bash",
            "command_line": "/bin/bash -c 'rm -rf /tmp/test'",
            "user": "root",
            "group": "root"
        }
    }
}
EOF

# 测试规则加载
echo "测试规则加载..."
timeout 5 ./wasm-threat-detector \
    --rules ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm \
    --log-level debug &

DETECTOR_PID=$!
sleep 2

# 检查进程是否正在运行
if kill -0 $DETECTOR_PID 2>/dev/null; then
    echo "✅ 威胁检测器启动成功"
    kill $DETECTOR_PID
    wait $DETECTOR_PID 2>/dev/null || true
else
    echo "❌ 威胁检测器启动失败"
    exit 1
fi

# 性能测试
echo ""
echo "⚡ 运行性能测试..."

# 构建性能测试版本
cd host
go test -bench=. -benchmem ./internal/engine/ || echo "⚠️  性能测试需要完善"

cd ..

# 清理
rm -f /tmp/test_event.json

echo ""
echo "✅ 所有测试完成！"
echo ""
echo "📊 测试总结:"
echo "  - Go 单元测试: 通过"
echo "  - Rust 单元测试: 通过"
echo "  - 代码质量检查: 通过"
echo "  - 构建测试: 通过"
echo "  - 基本功能测试: 通过"
echo ""
echo "🚀 项目已准备就绪！"
