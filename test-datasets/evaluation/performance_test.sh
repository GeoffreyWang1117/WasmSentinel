#!/bin/bash

# 性能测试脚本 - 测试检测器的延迟和吞吐量

echo "⚡ WASM-ThreatDetector 性能测试"
echo "================================"

# 检查依赖
if ! command -v bc &> /dev/null; then
    echo "⚠️  bc 未安装，部分计算可能不准确"
fi

# 检查程序
if [ ! -f "./wasm-threat-detector" ]; then
    echo "❌ 检测器程序未找到"
    exit 1
fi

LOG_FILE="/tmp/perf_test_$(date +%Y%m%d_%H%M%S).log"

echo "🚀 启动检测器..."
./wasm-threat-detector \
    --rules ./rules/suspicious-shell/target/wasm32-wasi/release/suspicious_shell.wasm \
    --log-level info \
    --log-file "$LOG_FILE" \
    --metrics-port 8080 &

DETECTOR_PID=$!
sleep 3

echo "📊 性能基准测试"
echo "================"

echo "1️⃣ 延迟测试 - 单个事件处理时间"
echo "执行 100 个命令，测量平均延迟..."

START_TIME=$(date +%s.%N)
for i in {1..100}; do
    /bin/bash -c "echo 'test command $i'" >/dev/null 2>&1
done
END_TIME=$(date +%s.%N)

TOTAL_TIME=$(echo "$END_TIME - $START_TIME" | bc 2>/dev/null || echo "N/A")
if [ "$TOTAL_TIME" != "N/A" ]; then
    AVG_LATENCY=$(echo "scale=3; $TOTAL_TIME / 100 * 1000" | bc 2>/dev/null || echo "N/A")
    echo "✅ 平均延迟: ${AVG_LATENCY} ms"
else
    echo "⚠️  延迟计算失败"
fi

echo ""
echo "2️⃣ 吞吐量测试 - 并发事件处理"
echo "并发执行多个进程..."

START_TIME=$(date +%s.%N)
for i in {1..50}; do
    (/bin/bash -c "ps aux | head -5" >/dev/null 2>&1) &
done
wait
END_TIME=$(date +%s.%N)

CONCURRENT_TIME=$(echo "$END_TIME - $START_TIME" | bc 2>/dev/null || echo "N/A")
if [ "$CONCURRENT_TIME" != "N/A" ]; then
    THROUGHPUT=$(echo "scale=2; 50 / $CONCURRENT_TIME" | bc 2>/dev/null || echo "N/A")
    echo "✅ 吞吐量: ${THROUGHPUT} events/second"
else
    echo "⚠️  吞吐量计算失败"
fi

echo ""
echo "3️⃣ 资源使用测试"
echo "检查内存和 CPU 使用..."

if command -v ps &> /dev/null; then
    PS_OUTPUT=$(ps -p $DETECTOR_PID -o pid,ppid,pcpu,pmem,vsz,rss,comm 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "$PS_OUTPUT"
    else
        echo "⚠️  无法获取进程信息"
    fi
fi

echo ""
echo "4️⃣ 规则执行效率测试"
echo "测试不同类型事件的处理速度..."

# 进程事件
echo "测试进程事件..."
START_TIME=$(date +%s.%N)
for i in {1..20}; do
    /bin/bash -c "sleep 0.01" &
done
wait
END_TIME=$(date +%s.%N)
PROCESS_TIME=$(echo "$END_TIME - $START_TIME" | bc 2>/dev/null || echo "N/A")

# 网络事件模拟
echo "测试网络事件..."
START_TIME=$(date +%s.%N)
for i in {1..20}; do
    timeout 0.1 nc -w 1 127.0.0.1 22 2>/dev/null &
done
wait
END_TIME=$(date +%s.%N)
NETWORK_TIME=$(echo "$END_TIME - $START_TIME" | bc 2>/dev/null || echo "N/A")

echo "✅ 进程事件处理时间: ${PROCESS_TIME}s"
echo "✅ 网络事件处理时间: ${NETWORK_TIME}s"

echo ""
echo "5️⃣ 内存泄漏测试"
echo "长时间运行检测内存使用..."

INITIAL_MEM=$(ps -p $DETECTOR_PID -o rss= 2>/dev/null | tr -d ' ')
echo "初始内存使用: ${INITIAL_MEM} KB"

# 运行一段时间的负载
for i in {1..200}; do
    /bin/bash -c "echo 'stress test $i'" >/dev/null 2>&1
    if [ $((i % 50)) -eq 0 ]; then
        sleep 1
    fi
done

sleep 2
FINAL_MEM=$(ps -p $DETECTOR_PID -o rss= 2>/dev/null | tr -d ' ')
echo "最终内存使用: ${FINAL_MEM} KB"

if [ ! -z "$INITIAL_MEM" ] && [ ! -z "$FINAL_MEM" ]; then
    MEM_DIFF=$((FINAL_MEM - INITIAL_MEM))
    echo "内存增长: ${MEM_DIFF} KB"
    if [ $MEM_DIFF -lt 10240 ]; then  # 小于 10MB
        echo "✅ 内存使用稳定"
    else
        echo "⚠️  可能存在内存泄漏"
    fi
fi

echo ""
echo "🛑 停止检测器..."
kill $DETECTOR_PID 2>/dev/null || true
wait $DETECTOR_PID 2>/dev/null || true

echo ""
echo "📊 性能测试总结"
echo "================"
[ "$AVG_LATENCY" != "N/A" ] && echo "平均延迟: ${AVG_LATENCY} ms"
[ "$THROUGHPUT" != "N/A" ] && echo "吞吐量: ${THROUGHPUT} events/sec"
echo "日志文件: $LOG_FILE"

echo ""
echo "💡 性能优化建议:"
echo "  - 如果延迟 > 10ms，考虑优化 Wasm 规则"
echo "  - 如果吞吐量 < 100 events/sec，检查并发处理"
echo "  - 如果内存持续增长，检查内存泄漏"

echo ""
echo "🎉 性能测试完成！"
