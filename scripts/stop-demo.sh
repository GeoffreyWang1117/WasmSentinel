#!/bin/bash

# WasmSentinel 演示停止脚本

echo "🛑 停止 WasmSentinel 演示环境..."

docker compose -f docker-compose.showcase.yml down 2>/dev/null

echo "✅ 演示环境已停止"
