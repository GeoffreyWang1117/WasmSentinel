#!/bin/bash

# 恶意命令模拟 - 信息收集
# ⚠️ 仅用于测试！

echo "🔴 模拟信息收集攻击"
echo "================================"

echo "1. 系统信息收集..."
uname -a
whoami
id
pwd
hostname

echo ""
echo "2. 网络信息收集..."
ifconfig 2>/dev/null || ip addr show
netstat -tulpn 2>/dev/null | head -10
ss -tulpn 2>/dev/null | head -10

echo ""
echo "3. 进程信息收集..."
ps aux | head -10
top -bn1 | head -10

echo ""
echo "4. 文件系统信息..."
df -h
mount | grep -v tmpfs | head -5
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null

echo ""
echo "5. 用户信息收集..."
cat /etc/passwd | head -10
last | head -5
w 2>/dev/null

echo ""
echo "6. 可疑目录扫描..."
find /tmp -type f -name ".*" 2>/dev/null | head -5
find /var/tmp -type f -name ".*" 2>/dev/null | head -5
find /dev/shm -type f 2>/dev/null | head -5

echo ""
echo "7. 网络连接探测..."
timeout 1 nmap -sT 127.0.0.1 -p 22,80,443,3389,4444 2>/dev/null || echo "nmap 不可用"

echo ""
echo "8. SSH 密钥收集..."
find /home -name "*.pem" -o -name "*_rsa" -o -name "*_dsa" 2>/dev/null | head -5
ls -la ~/.ssh/ 2>/dev/null

echo ""
echo "✅ 信息收集模拟完成"
