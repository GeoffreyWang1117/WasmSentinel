# Claim ledger（每条论文主张 → 实验 → 文件）

论文里出现的每个数字都必须能在右列的 JSON 里 `grep` 到；`make numbers` 把它们生成为 `tables/numbers.tex` 宏，正文只用宏。

| # | 主张（草拟，随结果修改） | 实验 | 证据文件 | 状态 |
|---|---|---|---|---|
| C1.1 | 引擎一次空规则调用 2.1 µs；真实 ml_detector 处理一个进程事件 JSON 10.2 µs / 二进制 4.4 µs；整条轨迹（中位 343 syscall）原生 Rust MLP 23.8 µs、森林 19.5 µs | E2 | `evaluation/results/2026-11/e2/e2_results.json` | ✅ 2026-10-25（重跑 commit 3e804a6，含森林） |
| C1.2 | 同一模型 NumPy / 原生 Rust / Wasm 三路分数一致（5,951 条轨迹）：MLP max diff 1.9e-6、原生 vs Wasm 5e-9、0.7 阈值判决 5,951/5,951 一致；森林 NumPy 读取器 vs Wasm 3.0e-8、原生 vs Wasm 4.9e-9 | E2 | 同上 | ✅ 2026-10-25 |
| C1.3 | 回放 syscall 事件，两种深路径模型：10K eps 下 e2e p50 MLP 0.30 ms（二进制）/ 0.38 ms（JSON），森林 0.25 / 0.34 ms，p99 MLP 1.2 / 2.2 ms；可持续吞吐 MLP 18.3K（二进制）/ 15.1K（JSON）eps，森林 21.4K / 17.0K；detect p50 MLP 70–105 µs、森林 57–90 µs，由 ml_detector 的逐事件特征重算主导；森林臂 RSS 多 3–6 MiB | E3 | `e3/e3_results.json` | ✅ 2026-10-25（重跑 commit 3e804a6，含森林臂） |
| C1.4 | 吞吐 Δ（ml_detector 默认深路径 = 森林）：nginx −4.4% [−6.4, −2.5]（Falco −9.2%，Tetragon −17.5%）；redis −3.6% [−7.2, +0.0]（Falco −5.0%，Tetragon −1.2%）；postgres −9.2% [−12.5, −6.0]（Falco −8.6%，Tetragon −0.1%）。监控进程 RSS 峰值 142–180 MiB vs Falco 366–371；CPU 在 postgres 臂 163% vs Falco 82% / Tetragon 19%。WS 管道自身计数：pgbench 下处理 12.4K eps（JSON），采集器丢 45%，96% 的已处理事件告警（上次 MLP 默认：7.8K eps、丢 66%、94%）；nginx / redis 丢 0.8% / 0% | E4 | `e4/e4_results.json` | ✅ 2026-10-26（默认森林重跑，commit 2055159；机器有 vLLM 与其他容器，见日志） |
| C1.5 | 三场景 × 20 次（默认森林）：三套系统全部 20/20；告警延迟中位 0.7–2.9 ms 同量级；RSS 104 / 369 / 86 MiB（WS / Falco / Tetragon）；CPU 6.9 / 2.5 / 0.7% | E5 | `e5/e5_results.json` | ✅ 2026-10-26（默认森林重跑，commit 2055159） |
| C2.1 | 10 个越界模块 11 个用例全部被包含；1 GiB 单次分配标为 trap 而非 memory | E6 | `isolation/isolation.json` | ✅ 2026-10-18 |
| C3.1 | 部署模块与训练模型逐位一致（1,400 输入 max diff 2e-6） | P1.4 | `parity/parity.txt` | ✅ |
| C3.2 | ADFA-LD 5 折 × 3 种子，推理在 Wasm 内：**模块内随机森林 AUPRC 0.897 ± 0.028**（recall@5%FPR 0.908，@1%FPR 0.700），与 scikit-learn 森林逐折相同（15 折 max diff 2.9e-8，配对差 0）；MLP 0.730 ± 0.056（recall@5%FPR 0.718；Wasm vs NumPy 1.1e-6）；STIDE 0.437、IF 0.218、LSTM 0.825；配对差 RF−MLP +0.167 [+0.135, +0.199]，RF−LSTM +0.072 [+0.046, +0.098]，MLP−LSTM −0.095 [−0.126, −0.064] | E1 | `e1/e1_results.json` | ✅ 2026-10-25（含 `wasmsentinel_rf` 臂的重跑，commit d549f3c） |
| C3.3 | 按攻击家族的 recall（FPR-5 工作点）：模块内 RF 0.95（Web_Shell）–0.99（Hydra_FTP / Hydra_SSH / Java_Meterpreter）；MLP 0.66（Web_Shell）–0.87（Hydra_SSH） | E1 | 同上 | ✅ 2026-10-25 |
| C3.4 | 嵌入模块的森林：300 棵树、181,838 节点、2,183,280 B（模块 2.5 MB）；导出器 vs scikit-learn `predict_proba` 5,951 条 max diff 2.5e-9；阈值向下取整到 f32 的两条引理由 Z3 证明；2026-10-26 起森林是默认深路径，`init` 配置 `{"model":"mlp"}`（host `--rule-config`）切回 MLP | RF-in-Wasm | `rules/ml-detector/train/rf_model.json`，`train/verify/threshold_rounding_report.md`，`train/fixtures/forest_golden.json` | ✅ 2026-10-25 |
| — | 已删除的旧主张：F1 0.84 / 0.87、延迟 16.5 µs & "485×"、零拷贝 5×、沙箱 5/5 硬编码、Falco 文献值 | — | `DEVELOPMENT_PLAN.md` §1.4 | 不再出现 |
