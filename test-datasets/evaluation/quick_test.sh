#!/bin/bash

# 🚀 WASM-ThreatDetector 快速验证测试
# ========================================

set -e

echo "🚀 WASM-ThreatDetector 快速验证测试"
echo "=========================================="

# 配置
PROJECT_DIR="/home/coder-gw/CodingProjects/WASM_proj"
LOG_DIR="/tmp/wasm-threat-detector-test"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/quick_test_$TIMESTAMP.log"

mkdir -p "$LOG_DIR"

cd "$PROJECT_DIR"

echo "📋 测试配置:"
echo "  - 日志文件: $LOG_FILE"
echo "  - 项目目录: $PROJECT_DIR"

# 检查构建状态
echo ""
echo "🔧 检查构建状态..."
if [ ! -f "./wasm-threat-detector" ]; then
    echo "❌ 主程序未构建，开始构建..."
    ./scripts/build.sh
else
    echo "✅ 主程序已存在"
fi

if [ ! -f "./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm" ]; then
    echo "❌ WASM 规则未构建，开始构建..."
    cd ./rules/suspicious-shell
    cargo build --target wasm32-wasi --release
    cd "$PROJECT_DIR"
else
    echo "✅ WASM 规则已存在"
fi

echo ""
echo "🎯 启动检测器（后台模式）..."
# 使用 nohup 后台运行检测器
nohup ./wasm-threat-detector > "$LOG_FILE" 2>&1 &
DETECTOR_PID=$!

echo "检测器进程 PID: $DETECTOR_PID"

# 等待启动
sleep 3

# 检查进程是否仍在运行
if ! kill -0 $DETECTOR_PID 2>/dev/null; then
    echo "❌ 检测器启动失败"
    echo "日志内容:"
    cat "$LOG_FILE"
    exit 1
fi

echo "✅ 检测器启动成功"

echo ""
echo "🧪 执行测试命令..."

# 执行一些可疑命令
echo "1. 执行正常命令..."
ls -la > /dev/null

echo "2. 执行可疑Shell命令..."
bash -c 'echo "rm -rf /" | cat' > /dev/null

echo "3. 执行网络相关命令..."
timeout 2 nc -l 4444 2>/dev/null || true

echo "4. 执行系统信息收集..."
whoami > /dev/null
id > /dev/null

echo "5. 模拟文件操作..."
touch /tmp/test_file
rm -f /tmp/test_file

# 等待处理
sleep 5

echo ""
echo "📊 检查检测结果..."

# 检查健康状态
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ 健康检查通过"
    
    # 获取指标
    echo "📊 Prometheus 指标:"
    timeout 5 curl -s http://localhost:8080/metrics | grep -E "(threat|total)" | head -5 || echo "无法获取指标"
else
    echo "❌ 健康检查失败"
fi

echo ""
echo "📄 日志分析:"
echo "============"

# 分析日志
if [ -f "$LOG_FILE" ]; then
    echo "📈 总日志行数:"
    wc -l "$LOG_FILE"
    
    echo ""
    echo "⚠️  威胁检测结果:"
    grep -i "threat\|warning\|critical" "$LOG_FILE" | tail -10 || echo "未发现威胁检测日志"
    
    echo ""
    echo "🔍 最近的活动:"
    tail -20 "$LOG_FILE" | grep -E "(INFO|WARN|ERROR)" | tail -5 || echo "未发现活动日志"
    
else
    echo "❌ 日志文件不存在: $LOG_FILE"
fi

echo ""
echo "🛑 停止检测器..."
if kill $DETECTOR_PID 2>/dev/null; then
    echo "✅ 检测器已停止"
else
    echo "⚠️  检测器可能已经停止"
fi

echo ""
echo "📊 测试总结"
echo "============"
echo "✅ 测试完成"
echo "📁 日志文件: $LOG_FILE"
echo "🔍 查看完整日志: cat $LOG_FILE"
echo "💡 查看威胁检测: grep -i threat $LOG_FILE"

echo ""
echo "🎉 快速验证测试完成！"
