#!/bin/bash

# 恶意命令模拟 - 系统破坏攻击
# ⚠️ 仅用于测试！这些命令经过安全处理！

echo "🔴 模拟系统破坏攻击"
echo "================================"

# 创建临时测试目录
TEST_DIR="/tmp/wasm_threat_test_$$"
mkdir -p "$TEST_DIR"

echo "1. 模拟危险删除命令..."
# 注意：这里只是echo，不会真正执行
echo "rm -rf /"
echo "dd if=/dev/zero of=/dev/sda"
echo "mkfs.ext4 /dev/sda1"

echo "2. 在测试目录中执行安全的删除..."
touch "$TEST_DIR/test_file1" "$TEST_DIR/test_file2"
rm -rf "$TEST_DIR/test_file*"

echo "3. 模拟 fork bomb..."
echo ":(){ :|:& };:"

echo "4. 模拟文件权限修改..."
chmod 777 "$TEST_DIR" 2>/dev/null

echo "5. 模拟 crontab 修改..."
echo "* * * * * /tmp/malicious_script.sh" | echo "添加到 crontab（模拟）"

echo "6. 模拟系统文件修改..."
echo "echo 'evil_user:x:0:0::/:/bin/bash' >> /etc/passwd" 

echo "7. 模拟内核模块加载..."
echo "insmod /tmp/rootkit.ko"

# 清理测试目录
rm -rf "$TEST_DIR"

echo ""
echo "✅ 系统破坏模拟完成"
