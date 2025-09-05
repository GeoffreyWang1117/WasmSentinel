#!/bin/bash

# 权限提升模拟
# ⚠️ 仅用于测试！

echo "🔴 模拟权限提升攻击"
echo "================================"

echo "1. 模拟 sudo 滥用..."
# 检查 sudo 权限（安全）
sudo -l 2>/dev/null || echo "无 sudo 权限"

echo ""
echo "2. 模拟 SUID 文件利用..."
# 查找 SUID 文件（信息收集）
find /usr/bin -perm -4000 2>/dev/null | head -5
find /bin -perm -4000 2>/dev/null | head -5

echo ""
echo "3. 模拟配置文件修改..."
echo "尝试修改 /etc/sudoers..."
echo "evil_user ALL=(ALL) NOPASSWD:ALL" | echo "添加到 sudoers（模拟）"

echo ""
echo "4. 模拟环境变量操作..."
export LD_PRELOAD="/tmp/malicious.so"
echo "设置 LD_PRELOAD: $LD_PRELOAD"
unset LD_PRELOAD

echo ""
echo "5. 模拟内核漏洞利用..."
echo "gcc -o exploit kernel_exploit.c"
echo "./exploit"

echo ""
echo "6. 模拟密码文件操作..."
# 只是读取，不修改
echo "检查密码文件权限..."
ls -la /etc/passwd /etc/shadow /etc/group 2>/dev/null

echo ""
echo "7. 模拟 crontab 修改..."
echo "当前 crontab:"
crontab -l 2>/dev/null || echo "无 crontab"

echo ""
echo "8. 模拟服务操作..."
systemctl list-units --type=service --state=running 2>/dev/null | head -5 || echo "无 systemctl 权限"

echo ""
echo "✅ 权限提升模拟完成"
