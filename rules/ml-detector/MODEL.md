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

## 随机森林（同一模块里的第二个模型）

E1 显示同一组 v1 特征上随机森林明显强于 MLP（AUPRC 0.90 对 0.73），所以模块同时嵌入一棵
scikit-learn 随机森林。2026-10-26 起它是默认的深路径（E1 更准、E3 每事件更便宜）；`init` 的配置
`{"model": "mlp"}` 切回 MLP。E1 / E2 / E3 两个模型都报；E4 / E5 用默认路径（森林）重跑。部署里深路径的
分数不单独过阈值，而是 `0.4 × STIDE + 0.6 × 深路径分数` 再映射到威胁等级，所以换模型不涉及阈值选择
（E1 里森林的折内 F1 最优阈值 0.59 ± 0.02、FPR-5 阈值 0.08，供参考）。

| 项 | 值 | 证据 |
|---|---|---|
| 训练 | 全部 5,951 条 ADFA-LD 轨迹，`RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)`，与 E1 `rf` 基线同一组超参 | `train/train_rf.py`，`train/rf_model.json` |
| 规模 | 300 棵树，181,838 个节点，最大深度 43，2,183,280 字节（模块从 334 kB 变为 2.5 MB） | `src/forest_meta.rs` |
| 格式 | WSRF v1：24 字节头 + 每棵树的根索引 + 每节点 12 字节（feature i32 / value f32 / right u32），深度优先，左孩子隐含为下一个节点；阈值**向下**取整到 f32，使模块的 f32 比较与 scikit-learn 对 f64 阈值的判定逐位一致 | `train/forest_export.py`，`src/forest.rs` |
| 文件 | `train/rf_model.bin`，sha256 `efd32e50…1225`（`model_info` 的 `rf.sha256`） | `src/forest_meta.rs` |
| 一致性 | 导出器 vs scikit-learn `predict_proba`：5,951 条最大差 2.5e-9；模块 `rf_score` vs fixture：28 例最大差 2.8e-8；E1 的 `wasmsentinel_rf` 臂逐折记录 `wasm_vs_sklearn_max_abs_diff` | `train/rf_model.json`，`tests/forest_golden.rs`，`train/verify_wasm_parity.py` |
| 交叉验证精度 | E1 的 `wasmsentinel_rf` 臂（2026-10-25）：逐折训练同一超参的森林，经 `load_rf_model` 载入、`rf_score` 打分；AUPRC 0.897 ± 0.028、recall@5%FPR 0.908、@1%FPR 0.700，与 scikit-learn `predict_proba` 逐折相同（15 折最大差 2.9e-8）；同协议下 MLP 0.730 ± 0.056 | `evaluation/results/2026-11/e1/e1_summary.md` |

加载时校验整张图：每个右孩子索引严格向前且在图内、特征索引小于 64、叶子值是有限的概率，
所以遍历一定终止且不会越界；校验失败 `load_rf_model` 返回 -1，嵌入的森林不受影响。

## 再生成与验证

```bash
# 0. 训练并导出嵌入的随机森林（rf_model.bin、rf_model.json、src/forest_meta.rs、forest_golden.json）
conda run -n wasmsentinel python3 train/train_rf.py

# 1. 把 JSON 权重嵌入 Rust（结构、参数量、sha256 一起写入）
python3 train/embed_weights.py --input train/best_model_weights.json --output src/weights.rs

# 2. 单测 + golden 对照（MLP fixture 由 NumPy 参考实现生成，森林 fixture 由 scikit-learn 生成；都不需要 Python）
cargo test --release

# 3. 编译模块并与 NumPy 逐条比较（1,000 条合成序列 + ADFA-LD 轨迹；阈值 1e-5），再对森林 fixture 比较
cargo build --release --target wasm32-wasip1
conda run -n wasmsentinel python3 train/verify_wasm_parity.py --wasm target/wasm32-wasip1/release/ml_detector.wasm

# 换 MLP 权重后重新生成 golden fixture
conda run -n wasmsentinel python3 train/verify_wasm_parity.py --write-golden train/fixtures/features_golden.json
```

2026-10-18 的结果：1,400 条输入，特征最大绝对差 0，分数最大绝对差 1.97e-6。
2026-10-25（加入森林后）：MLP 同上；森林 28 例最大差 2.8e-8。

## 导出

| 导出 | 用途 |
|---|---|
| `detect(ptr,len)` / `detect_raw(ptr,len)` | 宿主调用的检测入口（JSON / 二进制），返回 0–10 |
| `detect_extended(ptr,len,out_len)` | 带 `anomaly_score`、`detection_method` 的 JSON 结果 |
| `mlp_score(ptr,len)` | syscall 号序列 → MLP 分数（评估与一致性检查用，绕过 STIDE 与进程状态） |
| `mlp_features(ptr,len,out)` | 同上，输出 64 维特征 |
| `rf_score(ptr,len)` | syscall 号序列 → 随机森林分数（同上） |
| `load_mlp_weights(ptr,len)` / `load_rf_model(ptr,len)` | 运行时替换 MLP 权重（训练导出的 JSON）/ 随机森林（WSRF 图）；E1 用它们逐折载入模型。载入森林后深路径改用森林，再载入 MLP 权重则切回 MLP |
| `model_info(out_len)` | MLP 的结构、参数量、阈值、来源、sha256；`default_model`；`rf` 下是森林的树数、节点数、深度、来源、sha256、训练说明 |
| `train_sequence(ptr,len)` / `train_finish()` | 用正常 syscall 号轨迹（小端 u32 字节串）训练 STIDE；返回消费的 syscall 数 / 正常 n-gram 数 |
| `init` / `train` / `get_stats` / `free_result` / `alloc` / `dealloc` | 配置、JSON 事件训练、统计、内存 |

## 已知限制（给 E1）

- 训练用整条轨迹，线上按进程维护 100 长的 syscall 窗口：分布不一致，离线评估按整轨迹做，在线窗口是部署选择。
- STIDE 的正常 n-gram 库通过 `train_sequence` / `train_finish` 导出加载（宿主 `--rule-train-dir`，或评估脚本直接调用）；不加载时库为空，所有 n-gram 走 MLP 深路径。`StideConfig.max_database_size` 默认 100,000，整套 ADFA 训练集可能超过它，E1 要先核对。
- STIDE 滑动窗口是全局的，多进程交错时会混在一起；ADFA 回放是单轨迹顺序，不受影响。
