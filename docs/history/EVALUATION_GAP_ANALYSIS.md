# WasmSentinel 论文实验差距分析

**目标会议**: ACM CCS 2026 Cycle 2
**截止日期**: 2026-04-29
**分析日期**: 2026-01-05

---

## 📊 当前实验覆盖情况

### ✅ 已完成实验

| 实验类型 | 内容 | 质量评估 |
|----------|------|----------|
| 检测准确率 | ADFA-LD数据集, F1=0.72 | ⭐⭐⭐ 基础完成 |
| 架构搜索 | 8种MLP配置对比 | ⭐⭐⭐⭐ 较完整 |
| 超参数调优 | 7种LR/Epoch组合 | ⭐⭐⭐⭐ 较完整 |
| 交叉验证 | 5折CV, std=0.021 | ⭐⭐⭐⭐ 较完整 |
| 消融实验 | 4个组件贡献分析 | ⭐⭐⭐⭐ 较完整 |
| 性能基准 | 延迟/吞吐量/内存 | ⭐⭐⭐⭐ **已补充** |
| Baseline对比 | Falco/Tetragon/Sysdig | ⭐⭐⭐ **性能对比已完成** |
| 泛化性测试 | LID-DS (模拟) | ⭐⭐ 需要真实数据 |
| **真实工作负载** | nginx/redis/mysql/postgres | ⭐⭐⭐⭐ **新增完成** |
| **系统开销评估** | 微/宏基准测试 | ⭐⭐⭐⭐ **新增完成** |

---

## 🔴 关键缺失实验 (必须完成)

### 1. 真实工作负载测试 [Critical]

**问题**: 当前只有离线数据集评估，缺少真实系统测试。

**需要补充**:
```
- 在Docker/K8s环境下测试nginx/redis/mysql
- 测量正常工作负载下的误报率
- 评估不同系统调用频率下的性能
```

**预计工作量**: 3-5天

**参考代码**: `evaluation/scripts/real_workload_test.py`

---

### 2. 系统开销评估 [Critical]

**问题**: 没有展示监控对被监控系统的影响。

**需要补充**:
```
实验设计:
├── Micro-benchmark
│   ├── 单个syscall延迟增加量
│   ├── syscall吞吐量下降比例
│   └── 与ptrace/strace对比
│
├── Macro-benchmark
│   ├── Web服务器请求延迟影响
│   ├── 数据库TPS影响
│   └── 容器启动时间影响
│
└── 资源消耗
    ├── CPU占用率 (idle vs loaded)
    ├── 内存增长曲线
    └── 与Falco/Tetragon资源对比
```

**预计工作量**: 3-5天

---

### 3. 公平Baseline对比 [Critical]

**当前问题**:
- Falco的检测数据(F1=0.59)可能不是在相同任务上测试
- 没有说明Falco规则是如何配置的
- 性能对比可能不是apples-to-apples

**需要补充**:
```
1. 为Falco编写检测ADFA-LD攻击的规则
2. 在完全相同的数据集上测试Falco检测率
3. 使用相同的syscall输入测试性能
4. 说明每个系统的配置参数
```

**预计工作量**: 2-3天

---

### 4. 对抗性攻击评估 [Important]

**问题**: 没有测试系统对抗恶意绕过的能力。

**需要补充**:
```
1. Mimicry攻击
   - 攻击者模仿正常syscall模式
   - 测试检测率下降程度

2. 特征扰动
   - 添加噪声syscall
   - 改变syscall顺序

3. 模型逃逸
   - 知道模型架构时的对抗样本
   - 测试对抗训练的效果
```

**预计工作量**: 5-7天

---

## 🟡 建议补充实验 (提升竞争力)

### 5. 与深度学习方法对比

**当前缺失**: 没有与LSTM、Autoencoder等现代方法对比。

**建议**:
```python
# 需要实现的对比方法
BASELINES = {
    'LSTM': 'Kim et al. 2016',        # 经典syscall LSTM
    'Autoencoder': 'Standard AE',      # 无监督异常检测
    'Transformer': 'Attention-based',  # 现代架构
    'Random Forest': 'Traditional ML'  # 传统机器学习
}

# 对比维度
METRICS = ['F1', 'Precision', 'Recall', 'Latency', 'Model Size']
```

**预计工作量**: 5-7天

---

### 6. 多数据集验证

**当前状态**:
- ADFA-LD: 真实评估 ✅
- LID-DS: 模拟评估 ⚠️

**需要补充**:
```
1. 下载LID-DS 2021真实数据 (~10GB)
   URL: https://drive.proton.me/urls/BWKRGQK994#fCK9JKL93Sjm

2. 在真实LID-DS上训练和测试
   - 15个攻击场景分别评估
   - Leave-one-attack-out验证

3. 自建容器攻击数据集
   - Docker escape尝试
   - 容器间横向移动
   - 密码挖矿行为
```

**预计工作量**: 7-10天

---

### 7. 可扩展性测试

**需要补充**:
```
实验设计:
├── 单进程多容器
│   ├── 1/10/50/100容器并发监控
│   └── 性能线性度分析
│
├── 多进程监控
│   ├── 进程数vs吞吐量曲线
│   └── 瓶颈分析
│
└── 云原生场景
    ├── Kubernetes Pod监控
    └── Sidecar部署模式测试
```

**预计工作量**: 3-5天

---

### 8. 安全隔离验证

**需要补充**:
```
1. Wasm沙箱逃逸测试
   - 尝试访问沙箱外内存
   - 尝试调用未授权syscall

2. 恶意检测规则防护
   - 注入恶意Wasm模块
   - 验证资源限制有效性

3. 与其他隔离方案对比
   - vs 进程隔离 (Falco)
   - vs 容器隔离
   - vs VM隔离 (Kata)
```

**预计工作量**: 3-5天

---

## 📈 优先级排序

```
投递前必须完成 (4周):
├── [Week 1] 真实工作负载测试
├── [Week 2] 系统开销评估
├── [Week 2] 公平Baseline对比
└── [Week 3] LID-DS真实数据验证

强烈建议完成:
├── [Week 3-4] 对抗性攻击评估
└── [Week 4] 与深度学习方法对比

如有时间:
├── 可扩展性测试
└── 安全隔离验证
```

---

## 🎯 修改后的Evaluation章节结构

```
6. Evaluation
├── 6.1 Experimental Setup
│   ├── Hardware & Software
│   ├── Datasets (ADFA-LD, LID-DS, Custom)
│   └── Baselines (Falco, Tetragon, LSTM, etc.)
│
├── 6.2 Detection Accuracy
│   ├── ADFA-LD Results
│   ├── LID-DS Results (真实数据)
│   └── Per-attack-type Analysis
│
├── 6.3 System Overhead [NEW]
│   ├── Micro-benchmarks
│   ├── Application Impact
│   └── Comparison with Baselines
│
├── 6.4 Real Workload Evaluation [NEW]
│   ├── Web Server (nginx)
│   ├── Database (MySQL/Redis)
│   └── False Positive Analysis
│
├── 6.5 Comparison with ML Baselines [NEW]
│   ├── vs LSTM
│   ├── vs Autoencoder
│   └── Latency-Accuracy Trade-off
│
├── 6.6 Robustness Analysis [NEW]
│   ├── Mimicry Attack Resistance
│   ├── Feature Perturbation
│   └── Model Evasion
│
├── 6.7 Architecture Search
├── 6.8 Ablation Study
└── 6.9 Security Isolation Verification
```

---

## 📝 总结

| 类别 | 当前 | 目标 | 差距 |
|------|------|------|------|
| 数据集数量 | 2 (1真实+1模拟) | 3+ (全部真实) | 需要LID-DS真实数据 |
| Baseline数量 | 3 (系统) | 5+ (系统+ML) | 需要ML方法对比 |
| 开销评估 | 0 | 完整 | **关键缺失** |
| 真实工作负载 | 0 | 4+场景 | **关键缺失** |
| 对抗性测试 | 0 | 3+类型 | 建议补充 |
| 实验图表 | 6 | 10+ | 需要增加 |

**预计总工作量**: 4-6周 (全职)

---

*最后更新: 2026-01-05*
