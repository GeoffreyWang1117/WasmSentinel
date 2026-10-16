#!/bin/bash

# WasmSentinel 演示启动脚本
# 用于简历项目展示

set -e

echo "🛡️  WasmSentinel - 实时威胁检测系统演示"
echo "============================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker 未安装，请先安装 Docker${NC}"
    exit 1
fi

# 检查 Docker 是否运行
if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker 服务未运行，请启动 Docker${NC}"
    exit 1
fi

echo -e "${BLUE}📦 检查 Docker 镜像...${NC}"

# 检查是否需要构建镜像
if ! docker image inspect wasm-sentinel:latest &> /dev/null; then
    echo -e "${YELLOW}🔨 镜像不存在，开始构建...${NC}"
    docker build -t wasm-sentinel:latest .
    echo -e "${GREEN}✅ 镜像构建完成${NC}"
else
    echo -e "${GREEN}✅ 镜像已存在${NC}"
fi

# 确保目录权限
echo -e "${BLUE}📁 检查目录权限...${NC}"
mkdir -p logs config
chmod 777 logs
if [ ! -f config/config.yaml ]; then
    cp examples/config.yaml config/config.yaml
fi
echo -e "${GREEN}✅ 目录准备完成${NC}"

# 停止旧容器
echo -e "${BLUE}🧹 清理旧容器...${NC}"
docker compose -f docker-compose.showcase.yml down 2>/dev/null || true

# 启动服务
echo -e "${BLUE}🚀 启动演示环境...${NC}"
docker compose -f docker-compose.showcase.yml up -d

# 等待服务就绪
echo -e "${BLUE}⏳ 等待服务启动...${NC}"
sleep 5

# 检查服务状态
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}🎉 演示环境启动成功！${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "📊 ${YELLOW}演示界面:${NC}     http://localhost:3000"
echo -e "📈 ${YELLOW}Prometheus:${NC}   http://localhost:9091"
echo ""
echo -e "${BLUE}💡 提示:${NC}"
echo "  - 点击「模拟攻击演示」查看实时威胁检测"
echo "  - 查看 Prometheus 监控威胁指标变化"
echo "  - 使用 docker compose -f docker-compose.showcase.yml logs -f 查看日志"
echo ""
echo -e "${YELLOW}🛑 停止演示:${NC} docker compose -f docker-compose.showcase.yml down"
echo ""

# 尝试打开浏览器
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:3000 2>/dev/null || true
elif command -v open &> /dev/null; then
    open http://localhost:3000 2>/dev/null || true
fi
