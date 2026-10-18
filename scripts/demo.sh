#!/bin/bash

# 演示脚本 - WasmSentinel

set -e

echo "🎭 WasmSentinel 演示"
echo "=============================="

# 检查是否已构建
if [ ! -f "./wasmsentinel" ]; then
    echo "❌ 主程序未找到，请先运行构建脚本："
    echo "   ./scripts/build.sh"
    exit 1
fi

if [ ! -f "./rules/suspicious-shell/target/wasm32-wasip1/release/suspicious_shell.wasm" ]; then
    echo "❌ Wasm 规则未找到，请先运行构建脚本："
    echo "   ./scripts/build.sh"
    exit 1
fi

echo "🚀 启动威胁检测器..."

# 创建临时日志文件
LOG_FILE="/tmp/wasmsentinel-demo.log"

# 在后台启动检测器
./wasmsentinel \
    --rules ./rules/suspicious-shell/target/wasm32-wasip1/release/suspicious_shell.wasm \
    --log-level debug \
    --log-file "$LOG_FILE" \
    --metrics-port 8080 &

DETECTOR_PID=$!

echo "✅ 威胁检测器已启动 (PID: $DETECTOR_PID)"
echo "📊 指标端点: http://localhost:8080/metrics"
echo "📄 日志文件: $LOG_FILE"

sleep 3

echo ""
echo "🔍 模拟可疑活动..."

# 模拟一些可疑活动
echo "1. 执行可疑 shell 命令..."
/bin/bash -c "echo 'This is a test command'" &
sleep 1

echo "2. 尝试访问敏感文件..."
cat /etc/passwd > /dev/null 2>&1 || true
sleep 1

echo "3. 模拟网络连接..."
# 注意：这里只是模拟，实际不会建立连接
timeout 1 nc -w 1 google.com 80 2>/dev/null || true
sleep 1

echo ""
echo "⏰ 等待检测结果..."
sleep 5

echo ""
echo "📋 检测结果:"
echo "=============="

# 显示最近的日志
if [ -f "$LOG_FILE" ]; then
    tail -20 "$LOG_FILE" | grep -E "(WARN|ERROR|threat|detection)" || echo "未检测到威胁警告"
else
    echo "日志文件未生成"
fi

echo ""
echo "📊 Prometheus 指标:"
echo "==================="
curl -s http://localhost:8080/metrics 2>/dev/null | head -10 || echo "指标服务未响应"

echo ""
echo "🧹 清理..."

# 停止检测器
kill $DETECTOR_PID 2>/dev/null || true
wait $DETECTOR_PID 2>/dev/null || true

echo "✅ 演示完成！"
echo ""
echo "💡 提示："
echo "  - 查看完整日志: cat $LOG_FILE"
echo "  - 生产环境部署: 参考 docs/deployment.md"
echo "  - 编写自定义规则: 参考 docs/development.md"
