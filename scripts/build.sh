#!/bin/bash

# 构建脚本 - WASM-ThreatDetector

set -e

echo "🚀 Building WASM-ThreatDetector..."

# 检查依赖
echo "📋 Checking dependencies..."

# 检查 Go
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.19 or later."
    exit 1
fi

# 检查 Rust
if ! command -v rustc &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust 1.70 or later."
    exit 1
fi

# 检查 Wasm 目标
if ! rustup target list --installed | grep -q "wasm32-wasi"; then
    echo "📦 Installing wasm32-wasi target..."
    rustup target add wasm32-wasi
fi

# 构建 Rust Wasm 规则
echo "🔧 Building Wasm rules..."
cd rules/suspicious-shell
cargo build --target wasm32-wasi --release
cd ../..

# 构建 Go 主程序
echo "🔧 Building host program..."
cd host
go mod tidy
go build -o ../wasm-threat-detector ./cmd/main.go
cd ..

echo "✅ Build completed successfully!"
echo ""
echo "📁 Generated files:"
echo "  - ./wasm-threat-detector (主程序)"
echo "  - ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm (示例规则)"
echo ""
echo "🚀 Quick start:"
echo "  ./wasm-threat-detector --rules ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm"
