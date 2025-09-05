#!/bin/bash

# WASM-ThreatDetector 综合测试脚本
# 启动检测器并运行各种攻击模拟，观察检测效果

set -e

echo "🧪 WASM-ThreatDetector 综合测试"
echo "=================================="

# 检查程序是否存在
if [ ! -f "./wasm-threat-detector" ]; then
    echo "❌ 检测器程序未找到，请先运行: ./scripts/build.sh"
    exit 1
fi

if [ ! -f "./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm" ]; then
    echo "❌ Wasm 规则未找到，请先运行: ./scripts/build.sh"
    exit 1
fi

# 创建日志目录
LOG_DIR="/tmp/wasm-threat-detector-test"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/test_$(date +%Y%m%d_%H%M%S).log"

echo "📋 测试配置:"
echo "  - 日志文件: $LOG_FILE"
echo "  - 规则文件: ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm"
echo ""

# 启动威胁检测器
echo "🚀 启动威胁检测器..."
./wasm-threat-detector \
    --rules ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm \
    --log-level debug \
    --log-file "$LOG_FILE" \
    --metrics-port 8080 &

DETECTOR_PID=$!
echo "检测器进程 PID: $DETECTOR_PID"

# 等待检测器启动
echo "⏰ 等待检测器启动..."
sleep 3

# 检查检测器是否正常运行
if ! kill -0 $DETECTOR_PID 2>/dev/null; then
    echo "❌ 检测器启动失败"
    exit 1
fi

echo "✅ 检测器启动成功"
echo ""

# 设置所有测试脚本为可执行
chmod +x test-datasets/malicious-commands/*.sh
chmod +x test-datasets/network-attacks/*.sh
chmod +x test-datasets/privilege-escalation/*.sh

# 运行测试场景
echo "🎯 开始攻击模拟..."
echo "===================="

echo "📍 场景 1: 恶意命令执行"
echo "执行反向 Shell 模拟..."
./test-datasets/malicious-commands/reverse_shell.sh
sleep 2

echo ""
echo "📍 场景 2: 系统破坏命令"
echo "执行破坏性命令模拟..."
./test-datasets/malicious-commands/destructive_commands.sh
sleep 2

echo ""
echo "📍 场景 3: 信息收集"
echo "执行信息收集模拟..."
./test-datasets/malicious-commands/information_gathering.sh
sleep 2

echo ""
echo "📍 场景 4: 网络攻击"
echo "执行网络攻击模拟..."
./test-datasets/network-attacks/network_attacks.sh
sleep 2

echo ""
echo "📍 场景 5: 权限提升"
echo "执行权限提升模拟..."
./test-datasets/privilege-escalation/privilege_escalation.sh
sleep 2

echo ""
echo "📍 场景 6: 正常活动模拟"
echo "执行正常命令..."
ls -la /home
ps aux | head -5
netstat -tulpn | head -5
df -h
whoami
date

echo ""
echo "⏰ 等待检测结果处理..."
sleep 5

echo ""
echo "📊 检测结果分析"
echo "=================="

# 检查指标端点
echo "🔗 检查指标端点..."
if curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo "✅ 健康检查通过"
    echo "📊 Prometheus 指标:"
    curl -s http://localhost:8080/metrics | grep wasm_threat_detector || echo "未找到指标数据"
else
    echo "❌ 健康检查失败"
fi

echo ""
echo "📄 日志分析:"
echo "============"

if [ -f "$LOG_FILE" ]; then
    echo "📈 总事件数:"
    grep -c "level=" "$LOG_FILE" || echo "0"
    
    echo ""
    echo "⚠️  威胁检测结果:"
    grep -i "threat\|warn\|error" "$LOG_FILE" | tail -10 || echo "未发现威胁警告"
    
    echo ""
    echo "🔍 最近的检测活动:"
    tail -20 "$LOG_FILE" | grep -E "(process|network|detection)" || echo "未发现相关活动"
else
    echo "❌ 日志文件未生成"
fi

echo ""
echo "🛑 停止检测器..."
kill $DETECTOR_PID 2>/dev/null || true
wait $DETECTOR_PID 2>/dev/null || true

echo ""
echo "📊 测试总结"
echo "============"
echo "✅ 测试场景: 6 个"
echo "📁 日志文件: $LOG_FILE"
echo "⏱️  测试时长: 约 30 秒"

if [ -f "$LOG_FILE" ]; then
    TOTAL_EVENTS=$(grep -c "level=" "$LOG_FILE" 2>/dev/null || echo "0")
    THREAT_EVENTS=$(grep -c -i "threat\|warn" "$LOG_FILE" 2>/dev/null || echo "0")
    
    echo "📈 总事件数: $TOTAL_EVENTS"
    echo "⚠️  威胁事件数: $THREAT_EVENTS"
    
    if [ "$THREAT_EVENTS" -gt 0 ]; then
        echo "🎯 检测率: $(echo "scale=2; $THREAT_EVENTS * 100 / $TOTAL_EVENTS" | bc 2>/dev/null || echo "N/A")%"
    fi
fi

echo ""
echo "💡 建议:"
echo "  - 查看完整日志: cat $LOG_FILE"
echo "  - 分析威胁模式: grep -i threat $LOG_FILE"
echo "  - 调整规则配置以优化检测效果"

echo ""
echo "🎉 测试完成！"
