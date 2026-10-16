# WasmSentinel CCS 2026 Cycle 2 实施路线图

**目标会议**: ACM CCS 2026 Cycle 2
**截止日期**: Abstract Apr 22, 2026 | Paper Apr 29, 2026
**剩余时间**: 116天 (截至2026-01-03)
**选定方案**: 方案C - Wasm沙箱内运行轻量级ML模型

---

## 核心创新点（强化版）

### 1. WasmML: 首个在Wasm沙箱内运行ML威胁检测的系统
- 使用tract-onnx在Wasm中运行ONNX模型
- 保持沙箱隔离的同时提供智能检测能力
- **区别于Falco/Tetragon**: 它们只有规则匹配，没有ML能力

### 2. 混合检测架构
- **快速路径**: STIDE n-gram序列匹配（低延迟）
- **深度路径**: 轻量MLP/决策树（高准确率）
- 自适应切换机制

### 3. 零拷贝eBPF-Wasm数据通道
- Ring Buffer直接映射到Wasm线性内存
- 消除JSON序列化开销

---

## 时间线规划

### Phase 1: Wasm-ML核心实现 (Jan 3 - Jan 31, 2026)

#### Week 1 (Jan 3-10): 技术验证
- [ ] 创建Rust ML规则模块框架
- [ ] 集成tract-onnx到Wasm规则
- [ ] 实现STIDE算法在Rust中
- [ ] 验证Wasm编译和运行

#### Week 2 (Jan 11-17): 模型训练
- [ ] 使用ADFA-LD数据集训练轻量MLP
- [ ] 导出ONNX模型
- [ ] 在Wasm中加载和推理验证
- [ ] 优化模型大小（目标<1MB）

#### Week 3 (Jan 18-24): 混合检测
- [ ] 实现STIDE+MLP混合检测逻辑
- [ ] 实现自适应切换机制
- [ ] 集成到WasmSentinel主程序

#### Week 4 (Jan 25-31): 优化和测试
- [ ] 性能优化（延迟<5ms）
- [ ] 内存占用优化（<50MB）
- [ ] 初步准确率评估

### Phase 2: 检测算法优化+评估 (Feb 1-28, 2026)

#### Week 5-6 (Feb 1-14): 算法优化
- [ ] 特征工程优化
- [ ] 超参数调优
- [ ] 实现序列模式挖掘
- [ ] 添加上下文感知检测

#### Week 7-8 (Feb 15-28): 数据集评估
- [ ] 完整ADFA-LD评估（目标Recall>70%）
- [ ] LID-DS评估
- [ ] 生成评估报告

### Phase 3: Baseline对比实验 (Mar 1-15, 2026)

#### Week 9-10 (Mar 1-14): 对比测试
- [ ] 部署Falco 0.38+
- [ ] 部署Tetragon 1.2
- [ ] 公平性能对比测试
- [ ] 检测准确率对比

#### Week 11 (Mar 15): 结果分析
- [ ] 生成对比图表
- [ ] 分析优势和不足

### Phase 4: 论文撰写 (Mar 16 - Apr 25, 2026)

#### Week 12-13 (Mar 16-28): 初稿
- [ ] 撰写Introduction和Background
- [ ] 撰写System Design
- [ ] 撰写Implementation

#### Week 14-15 (Mar 29 - Apr 11): 完善
- [ ] 撰写Evaluation
- [ ] 撰写Related Work
- [ ] 撰写Discussion和Conclusion

#### Week 16-17 (Apr 12-25): 修订
- [ ] 内部评审和修订
- [ ] 图表优化
- [ ] 最终检查

---

## 技术栈

### Wasm ML模块
```
规则引擎 (Rust → Wasm)
├── tract-onnx (ONNX推理)
├── serde_json (事件解析)
├── 自定义STIDE实现
└── 混合检测调度器
```

### 模型训练 (Python)
```
训练流程
├── PyTorch (MLP训练)
├── ONNX导出
├── 模型量化 (int8)
└── 尺寸优化
```

### eBPF数据收集
```
已有实现
├── sentinel.bpf.c (syscall追踪)
├── ebpf_collector.go (事件收集)
└── Ring Buffer (零拷贝)
```

---

## 目标指标

| 指标 | 当前值 | 目标值 |
|------|--------|--------|
| Precision | 75% | >85% |
| Recall | 49% | >70% |
| F1 Score | 59% | >77% |
| 延迟P99 | 1.66ms | <5ms |
| 内存 | 19MB | <50MB |
| 模型大小 | N/A | <1MB |

---

## 论文结构（预览）

1. **Introduction** - eBPF+Wasm+ML三位一体
2. **Background** - eBPF/Wasm/ML检测基础
3. **Threat Model** - 攻击者能力和安全目标
4. **System Design**
   - 4.1 Architecture Overview
   - 4.2 eBPF Event Collection
   - 4.3 Zero-Copy Data Transfer
   - 4.4 WasmML Detection Engine ⭐ (核心创新)
   - 4.5 Hybrid Detection Strategy
5. **Implementation** - Go/Rust/C代码细节
6. **Evaluation**
   - 6.1 Detection Accuracy (ADFA-LD, LID-DS)
   - 6.2 Performance Comparison (vs Falco, Tetragon)
   - 6.3 Security Analysis
7. **Discussion** - 局限性和未来工作
8. **Related Work**
9. **Conclusion**

---

## 风险和应对

| 风险 | 可能性 | 影响 | 应对措施 |
|------|--------|------|----------|
| tract-onnx Wasm兼容性问题 | 中 | 高 | 使用纯Rust实现小型MLP |
| Recall提升困难 | 中 | 高 | 尝试更多特征/模型架构 |
| 性能开销过大 | 低 | 中 | 模型量化、缓存优化 |
| 实验复现问题 | 低 | 中 | 详细记录环境和参数 |

---

## 立即行动 (今天)

1. ✅ 创建本路线图
2. 🔄 创建Wasm-ML规则模块框架
3. 🔄 添加tract-onnx依赖
4. 🔄 实现基础STIDE算法

---

*路线图创建于 2026-01-03*
