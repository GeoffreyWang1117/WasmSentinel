# evaluation/results/2026-11

每个文件都由仓库里的一条命令生成；论文（AsiaCCS 2027 C2）只引用这个目录。重新生成：`make reproduce`（或单项 `make isolation` / `make parity`）。

| 目录 / 文件 | 实验 | 生成命令 | 来源代码 |
|---|---|---|---|
| `isolation/isolation.json`, `isolation.md` | E6 沙箱隔离：10 个故意越界的 Wasm 模块、11 个用例，在默认限额下由引擎处理 | `make isolation` | `rules/adversarial/`，`host/internal/engine/adversarial_test.go` |
| `parity/parity.txt` | P1.4 模型一致性：NumPy 参考实现 vs Wasm 模块，1,000 条合成序列 + 400 条 ADFA-LD 轨迹 | `make parity` | `rules/ml-detector/train/verify_wasm_parity.py` |

JSON 里带 `generated` 时间戳与限额；提交到仓库的是本机（Ubuntu 26.04，Linux 7.0.0-34，wasmtime-go v17）的一次运行，CI 的 `isolation` job 在 ubuntu-latest 上重跑同一测试并把表格贴到 job summary。
