#!/bin/bash

# 🎬 WasmSentinel 完整演示脚本
# =====================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 图标定义
ICON_SHIELD="🛡️"
ICON_ROCKET="🚀"
ICON_WARNING="⚠️"
ICON_SUCCESS="✅"
ICON_FIRE="🔥"
ICON_CHART="📊"
ICON_COMPUTER="💻"
ICON_GLOBE="🌐"

# 配置
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_PORT=8080
WEBSITE_PORT=3000

print_header() {
    echo -e "${WHITE}"
    echo "████████████████████████████████████████████████████████████████"
    echo "█                                                              █"
    echo "█  ${ICON_SHIELD} WasmSentinel ${ICON_ROCKET} 完整演示系统                        █"
    echo "█                                                              █" 
    echo "█  基于WebAssembly的轻量级实时威胁检测工具                       █"
    echo "█                                                              █"
    echo "████████████████████████████████████████████████████████████████"
    echo -e "${NC}"
}

print_step() {
    echo -e "${CYAN}${1}${NC}"
    echo -e "${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}${ICON_SUCCESS} ${1}${NC}"
}

print_warning() {
    echo -e "${YELLOW}${ICON_WARNING} ${1}${NC}"
}

print_error() {
    echo -e "${RED}❌ ${1}${NC}"
}

check_dependencies() {
    print_step "${ICON_COMPUTER} 检查依赖环境"
    
    # 检查 Go
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | grep -o 'go[0-9]\+\.[0-9]\+' | head -1)
        print_success "Go 版本: $GO_VERSION"
    else
        print_error "Go 未安装，请先安装 Go 1.21+"
        exit 1
    fi
    
    # 检查 Rust
    if command -v rustc &> /dev/null; then
        RUST_VERSION=$(rustc --version | awk '{print $2}')
        print_success "Rust 版本: $RUST_VERSION"
    else
        print_error "Rust 未安装，请先安装 Rust 1.70+"
        exit 1
    fi
    
    # 检查 Docker
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
        print_success "Docker 版本: $DOCKER_VERSION"
    else
        print_warning "Docker 未安装，将跳过容器化演示"
    fi
    
    # 检查端口占用
    if lsof -i :$DEMO_PORT &> /dev/null; then
        print_warning "端口 $DEMO_PORT 已被占用"
    fi
    
    if lsof -i :$WEBSITE_PORT &> /dev/null; then
        print_warning "端口 $WEBSITE_PORT 已被占用"
    fi
}

build_project() {
    print_step "${ICON_ROCKET} 构建项目"
    
    cd "$PROJECT_DIR"
    
    # 构建项目
    if [ -f "./scripts/build.sh" ]; then
        ./scripts/build.sh
    else
        print_error "构建脚本不存在"
        exit 1
    fi
    
    print_success "项目构建完成"
}

start_threat_detector() {
    print_step "${ICON_SHIELD} 启动威胁检测器"
    
    cd "$PROJECT_DIR"
    
    # 启动威胁检测器（后台）
    nohup ./wasmsentinel > demo_detector.log 2>&1 &
    DETECTOR_PID=$!
    
    echo "威胁检测器 PID: $DETECTOR_PID"
    
    # 等待启动
    sleep 3
    
    # 检查是否启动成功
    if kill -0 $DETECTOR_PID 2>/dev/null; then
        print_success "威胁检测器启动成功"
        echo "  - 健康检查: http://localhost:$DEMO_PORT/health"
        echo "  - 指标端点: http://localhost:$DEMO_PORT/metrics"
        echo "  - 日志文件: $PROJECT_DIR/demo_detector.log"
    else
        print_error "威胁检测器启动失败"
        cat demo_detector.log
        exit 1
    fi
}

start_demo_website() {
    print_step "${ICON_GLOBE} 启动演示网站"
    
    # 检查是否有 Python HTTP 服务器
    if command -v python3 &> /dev/null; then
        cd "$PROJECT_DIR/demo-website"
        nohup python3 -m http.server $WEBSITE_PORT > ../demo_website.log 2>&1 &
        WEBSITE_PID=$!
        echo "演示网站 PID: $WEBSITE_PID"
        
        sleep 2
        print_success "演示网站启动成功"
        echo "  - 访问地址: http://localhost:$WEBSITE_PORT"
        echo "  - 文档页面: http://localhost:$WEBSITE_PORT/docs/quickstart.html"
    elif command -v node &> /dev/null && command -v npx &> /dev/null; then
        cd "$PROJECT_DIR/demo-website"
        nohup npx http-server -p $WEBSITE_PORT > ../demo_website.log 2>&1 &
        WEBSITE_PID=$!
        echo "演示网站 PID: $WEBSITE_PID"
        
        sleep 2
        print_success "演示网站启动成功"
        echo "  - 访问地址: http://localhost:$WEBSITE_PORT"
    else
        print_warning "无法启动演示网站 (需要 Python3 或 Node.js)"
        WEBSITE_PID=""
    fi
}

run_demo_attacks() {
    print_step "${ICON_FIRE} 执行演示攻击"
    
    cd "$PROJECT_DIR"
    
    echo -e "${YELLOW}正在执行模拟攻击，观察威胁检测响应...${NC}"
    echo ""
    
    # 执行各种攻击模拟
    echo "1. ${ICON_WARNING} 恶意命令执行"
    bash -c 'echo "rm -rf /" | cat' > /dev/null
    sleep 1
    
    echo "2. ${ICON_WARNING} 反向Shell尝试"
    timeout 2 nc -l 4444 2>/dev/null || true
    sleep 1
    
    echo "3. ${ICON_WARNING} 系统信息收集"
    whoami > /dev/null
    id > /dev/null
    uname -a > /dev/null
    sleep 1
    
    echo "4. ${ICON_WARNING} 网络扫描模拟"
    timeout 2 nmap -p 22,80,443 localhost 2>/dev/null || true
    sleep 1
    
    echo "5. ${ICON_WARNING} 可疑文件操作"
    touch /tmp/suspicious_file
    chmod +x /tmp/suspicious_file
    rm -f /tmp/suspicious_file
    sleep 1
    
    print_success "演示攻击执行完成"
}

show_detection_results() {
    print_step "${ICON_CHART} 检测结果展示"
    
    echo "等待检测结果处理..."
    sleep 5
    
    # 显示健康状态
    echo "📊 系统状态:"
    if curl -s http://localhost:$DEMO_PORT/health > /dev/null; then
        echo -e "  ${GREEN}✅ 服务状态: 正常${NC}"
    else
        echo -e "  ${RED}❌ 服务状态: 异常${NC}"
    fi
    
    # 显示指标
    echo ""
    echo "📈 检测指标:"
    METRICS=$(curl -s http://localhost:$DEMO_PORT/metrics 2>/dev/null)
    if [ -n "$METRICS" ]; then
        echo "$METRICS" | grep -E "(threat|detection)" | head -5
    else
        echo "  无法获取指标数据"
    fi
    
    # 显示最新日志
    echo ""
    echo "📋 最新检测日志:"
    if [ -f "demo_detector.log" ]; then
        tail -10 demo_detector.log | grep -E "(warning|critical|threat)" | tail -5 || echo "  暂无威胁检测日志"
    fi
}

interactive_demo() {
    print_step "${ICON_COMPUTER} 交互式演示"
    
    echo "演示系统已启动，您可以："
    echo ""
    echo -e "${CYAN}1. 访问演示网站:${NC}"
    if [ -n "$WEBSITE_PID" ]; then
        echo "   http://localhost:$WEBSITE_PORT"
    else
        echo "   直接打开: $PROJECT_DIR/demo-website/index.html"
    fi
    echo ""
    echo -e "${CYAN}2. 查看API端点:${NC}"
    echo "   健康检查: curl http://localhost:$DEMO_PORT/health"
    echo "   指标数据: curl http://localhost:$DEMO_PORT/metrics"
    echo ""
    echo -e "${CYAN}3. 运行测试脚本:${NC}"
    echo "   快速测试: ./test-datasets/evaluation/quick_test.sh"
    echo "   综合测试: ./test-datasets/evaluation/comprehensive_test.sh"
    echo ""
    echo -e "${CYAN}4. 查看实时日志:${NC}"
    echo "   tail -f demo_detector.log"
    echo ""
    
    echo -e "${YELLOW}按 Enter 继续运行自动化测试，或按 Ctrl+C 退出进入手动模式...${NC}"
    read -r
}

run_automated_tests() {
    print_step "${ICON_ROCKET} 自动化测试"
    
    # 运行快速测试
    if [ -f "./test-datasets/evaluation/quick_test.sh" ]; then
        echo "执行快速验证测试..."
        timeout 60 ./test-datasets/evaluation/quick_test.sh || true
    fi
    
    # 运行性能测试
    if [ -f "./test-datasets/evaluation/performance_test.sh" ]; then
        echo ""
        echo "执行性能基准测试..."
        timeout 30 ./test-datasets/evaluation/performance_test.sh || true
    fi
}

cleanup() {
    print_step "🧹 清理演示环境"
    
    # 停止威胁检测器
    if [ -n "$DETECTOR_PID" ] && kill -0 $DETECTOR_PID 2>/dev/null; then
        kill $DETECTOR_PID
        print_success "威胁检测器已停止"
    fi
    
    # 停止演示网站
    if [ -n "$WEBSITE_PID" ] && kill -0 $WEBSITE_PID 2>/dev/null; then
        kill $WEBSITE_PID
        print_success "演示网站已停止"
    fi
    
    # 清理日志文件
    rm -f demo_detector.log demo_website.log
    
    echo ""
    echo -e "${GREEN}演示完成！感谢您体验 WasmSentinel${NC}"
    echo ""
    echo "🔗 项目链接:"
    echo "  GitHub: https://github.com/GeoffreyWang1117/WasmSentinel"
    echo "  文档: $PROJECT_DIR/README.md"
    echo "  测试报告: $PROJECT_DIR/TEST_REPORT.md"
}

# 主函数
main() {
    print_header
    
    # 设置清理函数
    trap cleanup EXIT
    
    check_dependencies
    build_project
    start_threat_detector
    start_demo_website
    
    run_demo_attacks
    show_detection_results
    
    interactive_demo
    run_automated_tests
    
    echo ""
    echo -e "${WHITE}演示已完成！按任意键退出...${NC}"
    read -r
}

# 运行主函数
main "$@"
