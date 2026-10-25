# Claim ledger（每条论文主张 → 实验 → 文件）

论文里出现的每个数字都必须能在右列的 JSON 里 `grep` 到；`make numbers` 把它们生成为 `tables/numbers.tex` 宏，正文只用宏。

| # | 主张（草拟，随结果修改） | 实验 | 证据文件 | 状态 |
|---|---|---|---|---|
| C1.1 | 引擎一次空规则调用 2.1 µs；真实 ml_detector 处理一个进程事件 JSON 10.2 µs / 二进制 4.6 µs；整条轨迹（中位 343 syscall）原生 Rust 26.0 µs | E2 | `evaluation/results/2026-11/e2/e2_results.json` | ✅ 2026-10-25 |
| C1.2 | 同一模型 NumPy / 原生 Rust / Wasm 三路分数一致（5,951 条轨迹，max diff 1.9e-6；原生 vs Wasm 5e-9；0.7 阈值判决 5,951/5,951 一致） | E2 | 同上 | ✅ 2026-10-25 |
| C1.3 | 回放 syscall 事件：10K eps 下 e2e p50 0.30 ms（二进制）/ 0.38 ms（JSON），p99 1.2 / 1.9 ms；可持续吞吐 18.5K（二进制）/ 15.0K（JSON）eps；detect p50 70–105 µs 由 ml_detector 的逐事件特征重算主导 | E3 | `e3/e3_results.json` | ✅ 2026-10-25 |
| C1.4 | 吞吐 Δ：nginx −4.4% [−7.2, −1.7]（Falco −9.2%，Tetragon −16.6%）；redis −3.4%（Falco −4.2%，Tetragon −1.5%）；postgres −10.0%（Falco −10.2%，Tetragon −1.9%）。监控进程 RSS 97–161 MiB vs Falco ≈ 365；CPU 在 postgres 臂 150% vs Falco 81% | E4 | `e4/e4_results.json` | ✅ 2026-10-25（机器有后台负载，见日志） |
| C1.5 | 三场景 × 20 次：三套系统全部 20/20；告警延迟中位 0.7–2.9 ms 同量级；RSS 97 / 371 / 154 MiB（WS / Falco / Tetragon）；空闲 CPU 7.1 / 1.2 / 0.8% | E5 | `e5/e5_results.json` | ✅ 2026-10-25 |
| C2.1 | 10 个越界模块 11 个用例全部被包含；1 GiB 单次分配标为 trap 而非 memory | E6 | `isolation/isolation.json` | ✅ 2026-10-18 |
| C3.1 | 部署模块与训练模型逐位一致（1,400 输入 max diff 2e-6） | P1.4 | `parity/parity.txt` | ✅ |
| C3.2 | ADFA-LD 5 折 × 3 种子，推理在 Wasm 内：MLP AUPRC 0.730 ± 0.056（recall@5%FPR 0.718）；STIDE 0.437、IF 0.218、**RF 0.897**、LSTM 0.825；配对差 RF −0.167 [−0.199, −0.135]；Wasm vs NumPy 分数 max diff 1.1e-6 | E1 | `e1/e1_results.json` | ✅ 2026-10-25 |
| C3.3 | 按攻击家族的 recall（FPR-5 工作点）：MLP 0.66（Web_Shell）–0.87（Hydra_SSH）；RF 0.95–0.99 | E1 | 同上 | ✅ 2026-10-25 |
| — | 已删除的旧主张：F1 0.84 / 0.87、延迟 16.5 µs & "485×"、零拷贝 5×、沙箱 5/5 硬编码、Falco 文献值 | — | `DEVELOPMENT_PLAN.md` §1.4 | 不再出现 |
