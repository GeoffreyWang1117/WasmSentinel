# 威胁模拟和测试数据集

本目录包含用于测试 WasmSentinel 的各种威胁模拟脚本和测试数据集。

## ⚠️ 安全警告

**这些脚本仅用于测试和演示目的！**

- 只在隔离的测试环境中运行
- 不要在生产系统中执行这些脚本
- 某些脚本可能触发安全软件警报

## 📁 目录结构

```
test-datasets/
├── README.md
├── malicious-commands/       # 恶意命令模拟
├── network-attacks/          # 网络攻击模拟
├── privilege-escalation/     # 权限提升模拟
├── data-exfiltration/        # 数据外泄模拟
├── persistence/              # 持久化攻击模拟
├── legitimate-activities/    # 正常活动（对照组）
└── evaluation/               # 评估脚本
```

## 🎯 测试场景

### 1. 恶意命令检测
- 反向 Shell 连接
- 文件删除攻击
- 系统信息收集
- 恶意下载执行

### 2. 网络攻击检测
- 端口扫描
- C&C 通信
- 异常外联
- 数据传输

### 3. 权限提升检测
- sudo 滥用
- SUID 利用
- 内核漏洞利用
- 配置文件修改

### 4. 数据外泄检测
- 敏感文件读取
- 网络传输
- 压缩打包
- 加密传输

## 🏃‍♂️ 快速测试

```bash
# 运行完整测试套件
./test-datasets/evaluation/run_all_tests.sh

# 运行特定类型测试
./test-datasets/evaluation/test_malicious_commands.sh

# 生成测试报告
./test-datasets/evaluation/generate_report.sh
```

## 📊 性能基准测试

```bash
# 延迟测试
./test-datasets/evaluation/latency_test.sh

# 吞吐量测试
./test-datasets/evaluation/throughput_test.sh

# 资源使用测试
./test-datasets/evaluation/resource_test.sh
```
