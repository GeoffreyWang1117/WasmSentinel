# Claim ledger（每条论文主张 → 实验 → 文件）

论文里出现的每个数字都必须能在右列的 JSON 里 `grep` 到；`make numbers` 把它们生成为 `tables/numbers.tex` 宏，正文只用宏。

| # | 主张（草拟，随结果修改） | 实验 | 证据文件 | 状态 |
|---|---|---|---|---|
| C1.1 | 一次规则调用的引擎开销 ≈ X µs；真实规则 JSON / 二进制路径各 Y / Z µs | E2 | `evaluation/results/2026-11/e2/e2_results.json` | 待跑（需空闲机器） |
| C1.2 | 同一模型 NumPy / 原生 Rust / Wasm 三路分数一致（max diff ≤ 2e-6，5,951 条轨迹） | E2 | 同上 | 一致性部分已验证（quick） |
| C1.3 | 端到端延迟 P50/P99/P999 与可持续吞吐，JSON vs 二进制 | E3 | `e3/e3_results.json` | 待跑 |
| C1.4 | nginx/redis/postgres 吞吐下降与监控进程 CPU/RSS，对比 Falco/Tetragon | E4 | `e4/e4_results.json` | 待跑 |
| C1.5 | 同一三种检测在三套系统的检出与告警延迟 | E5 | `e5/e5_results.json` | 待跑 |
| C2.1 | 10 个越界模块 11 个用例全部被包含；1 GiB 单次分配标为 trap 而非 memory | E6 | `isolation/isolation.json` | ✅ 2026-10-18 |
| C3.1 | 部署模块与训练模型逐位一致（1,400 输入 max diff 2e-6） | P1.4 | `parity/parity.txt` | ✅ |
| C3.2 | ADFA-LD 5 折 × 3 种子：AUPRC / recall@5%FPR，MLP vs STIDE/IF/RF/LSTM；RF 更强 | E1 | `e1/e1_results.json` | 运行中 |
| C3.3 | 按攻击家族的 recall | E1 | 同上 | 运行中 |
| — | 已删除的旧主张：F1 0.84 / 0.87、延迟 16.5 µs & "485×"、零拷贝 5×、沙箱 5/5 硬编码、Falco 文献值 | — | `DEVELOPMENT_PLAN.md` §1.4 | 不再出现 |
