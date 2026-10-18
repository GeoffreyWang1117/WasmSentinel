# ml-detector 模型来源与验证

这份文件回答"Wasm 模块里跑的到底是哪个模型"。每一项都能在仓库里核对。

## 模型

| 项 | 值 | 证据 |
|---|---|---|
| 数据 | ADFA-LD（Creech & Hu, 2013），`scripts/fetch_datasets.sh` 取回 | `train/train_mlp.py::load_adfa_ld` |
| 特征集 v1 | 64 维（46 维有值），由 syscall **号**序列计算 | `train/train_mlp.py::extract_features` ≡ `src/features.rs::adfa_features`（逐位一致） |
| 结构 | 64 → 128 → 64 → 32 → 16 → 1，ReLU + sigmoid，19,201 参数 | `src/weights.rs::HIDDEN_SIZES`、`NUM_PARAMETERS` |
| 训练配置 | lr 0.01，200 epochs，类别加权 mini-batch SGD | `train/results/EXPERIMENT_REPORT.md` 实验 2 |
| 权重文件 | `train/best_model_weights.json`，sha256 `1ee0c5d26f35193655abc52559ccfcdc1cf3734baf5ec232ec0ebf67277b3832` | `src/weights.rs::MODEL_SHA256` |
| 阈值 | 0.7 | `EXPERIMENT_REPORT.md` 实验 4；`src/weights.rs::DEFAULT_THRESHOLD` |
| 2026-01 报告的指标 | 单次划分 F1 0.722 / P 0.635 / R 0.837；5 折 CV F1 0.612 ± 0.021 | `train/results/all_results.json`；**论文引用 E1 重跑的结果** |

特征集 v1 的类别集合混用了 ABI 编号（0/1 是 x86_64 的 read/write，56/57 是 aarch64 的 openat/close，
而 ADFA-LD 本身是 i386 编号）。它被原样保留，因为权重依赖它；换一套语义正确的特征集需要重新训练和评估（E1）。

## 再生成与验证

```bash
# 1. 把 JSON 权重嵌入 Rust（结构、参数量、sha256 一起写入）
python3 train/embed_weights.py --input train/best_model_weights.json --output src/weights.rs

# 2. 单测 + golden 对照（fixture 由 NumPy 参考实现生成，不需要 Python）
cargo test --release

# 3. 编译模块并与 NumPy 逐条比较（1,000 条合成序列 + ADFA-LD 轨迹；阈值 1e-5）
cargo build --release --target wasm32-wasip1
conda run -n wasmsentinel python3 train/verify_wasm_parity.py --wasm target/wasm32-wasip1/release/ml_detector.wasm

# 换权重后重新生成 golden fixture
conda run -n wasmsentinel python3 train/verify_wasm_parity.py --write-golden train/fixtures/features_golden.json
```

2026-10-18 的结果：1,400 条输入，特征最大绝对差 0，分数最大绝对差 1.97e-6。

## 导出

| 导出 | 用途 |
|---|---|
| `detect(ptr,len)` / `detect_raw(ptr,len)` | 宿主调用的检测入口（JSON / 二进制），返回 0–10 |
| `detect_extended(ptr,len,out_len)` | 带 `anomaly_score`、`detection_method` 的 JSON 结果 |
| `mlp_score(ptr,len)` | syscall 号序列 → 嵌入模型分数（评估与一致性检查用，绕过 STIDE 与进程状态） |
| `mlp_features(ptr,len,out)` | 同上，输出 64 维特征 |
| `model_info(out_len)` | 结构、参数量、阈值、来源、sha256 |
| `train_sequence(ptr,len)` / `train_finish()` | 用正常 syscall 号轨迹（小端 u32 字节串）训练 STIDE；返回消费的 syscall 数 / 正常 n-gram 数 |
| `init` / `train` / `get_stats` / `free_result` / `alloc` / `dealloc` | 配置、JSON 事件训练、统计、内存 |

## 已知限制（给 E1）

- 训练用整条轨迹，线上按进程维护 100 长的 syscall 窗口：分布不一致，离线评估按整轨迹做，在线窗口是部署选择。
- STIDE 的正常 n-gram 库通过 `train_sequence` / `train_finish` 导出加载（宿主 `--rule-train-dir`，或评估脚本直接调用）；不加载时库为空，所有 n-gram 走 MLP 深路径。`StideConfig.max_database_size` 默认 100,000，整套 ADFA 训练集可能超过它，E1 要先核对。
- STIDE 滑动窗口是全局的，多进程交错时会混在一起；ADFA 回放是单轨迹顺序，不受影响。
