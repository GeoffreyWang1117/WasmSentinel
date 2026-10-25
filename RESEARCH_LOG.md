# WasmSentinel 研究日志

按日期倒序。每条写清：做了什么、证据在哪、下一步。任务编号对应 `DEVELOPMENT_PLAN.md` §3。

## 2026-10-25 · E5 完成：同一三种检测在 WasmSentinel / Falco / Tetragon 上的检出、延迟与资源

`make e5`（06:22–06:24；commit ba7af70），`evaluation/results/2026-11/e5/{e5_results.json, e5_summary.md}`。三个场景（读 `/etc/shadow`；把 `/bin/true` 拷到 `/tmp` 下执行；TCP 连 127.0.0.1:4444，harness 自己监听）各 20 次；WasmSentinel 用 suspicious_shell（eBPF 采集、JSON 编码），Falco 用三条自定义规则叠默认规则集（`evaluation/configs/falco-e5-rules.yaml`），Tetragon 用 `__x64_sys_openat` 入口 + `tcp_connect` dport 4444 + exec 按 `/tmp` 前缀（`tetragon-e5-policy.yaml`）。告警归到其之前最近的一次动作；延迟 = 动作前墙钟 → 首条告警。

| 系统 | 场景 | 检出 | 延迟中位 (ms) | p90 | RSS 峰值 (MiB) | 试验期间 CPU % |
|---|---|---|---|---|---|---|
| wasmsentinel | shadow / tmpexec / connect | 20/20 · 20/20 · 20/20 | 2.9 · 0.8 · 2.3 | 3.2 · 0.9 · 2.7 | 97 | 7.1 |
| falco | 同上 | 20/20 · 20/20 · 20/20 | 2.8 · 0.7 · 1.8 | 3.0 · 0.7 · 1.9 | 371 | 1.2 |
| tetragon | 同上 | 20/20 · 20/20 · 20/20 | 2.7 · 0.8 · 1.7 | 3.0 · 0.8 · 1.8 | 154 | 0.8 |

**解读**

- 三套系统三场景全部 20/20，告警延迟同量级（0.7–2.9 ms，差别在零点几毫秒，其中 WasmSentinel 的 connect 场景 2.3 ms 比另两家多 0.5 ms）。E5 回答的是"看得见同样的东西吗"——是；它不是性能实验。
- 资源：WasmSentinel RSS 97 MiB（Falco 371，Tetragon 154）；但空闲系统上的 CPU 7.1% 对 1.2% / 0.8%，原因与 E3/E4 一致：主机上每个 openat 与允许名单内 syscall 都进两条 Wasm 规则（ml_detector 的逐事件特征重算是大头），而 Falco/Tetragon 在内核侧先过滤。这是 Discussion 的设计杠杆，不是沙箱成本。
- Tetragon 语义差别：`security_file_open` 对被权限检查拒绝的打开（非 root 读 shadow 的 EACCES）不触发，所以策略挂在 `__x64_sys_openat` 入口；论文把这个写成三者的真实差异之一。
- 机器状态：E5 期间 1 分钟负载 15 → 5（E4 刚结束、其他容器陆续退出）；检出率与毫秒级延迟对此不敏感。

**CLAIMS**：C1.5 ✅。**Phase 2 的 E1–E6 至此全部有真实 JSON**；E7/E8 仍可砍。

## 2026-10-25 · E4 完成：nginx / redis / postgres 在四种监控臂下的吞吐与监控进程开销

`make e4`（05:59–06:22；commit ba7af70），`evaluation/results/2026-11/e4/{e4_results.json, e4_summary.md}`。nginx（wrk -t8 -c128）、redis（redis-benchmark SET/GET，pipeline 16）、postgres（pgbench -c16 -j8，客户端在容器内）× {none, wasmsentinel, falco, tetragon}，每格 5 次交错重复、每次 20 s；监控进程 CPU%/RSS 与整机 CPU 每 0.25 s 采样；Δ 为与 none 臂的配对差、95% CI。WasmSentinel 走 eBPF 采集器、两条规则、JSON 编码（默认）；Falco modern eBPF 默认规则集；Tetragon 带 file-open + tcp-connect 策略（`evaluation/configs/tetragon-e4-policy.yaml`）。版本见 JSON provenance。

| 负载 | 臂 | 吞吐（均值 ± 标准差） | Δ vs none | 95% CI | 监控 CPU % | 监控 RSS (MiB) |
|---|---|---|---|---|---|---|
| nginx | none | 178,007 ± 2,706 req/s | — | — | — | — |
| nginx | wasmsentinel | 170,071 ± 1,989 | **−4.4%** | [−7.2, −1.7] | 18.4 | 111 |
| nginx | falco | 161,597 ± 3,918 | −9.2% | [−11.8, −6.6] | 82.0 | 368 |
| nginx | tetragon | 148,390 ± 2,112 | −16.6% | [−18.1, −15.2] | 282.1 | 195 |
| redis | none | 960,059 ± 11,272 ops/s | — | — | — | — |
| redis | wasmsentinel | 927,451 ± 9,860 | −3.4% | [−5.0, −1.8] | 8.1 | 97 |
| redis | falco | 919,601 ± 19,853 | −4.2% | [−7.2, −1.2] | 7.4 | 369 |
| redis | tetragon | 945,367 ± 10,336 | −1.5% | [−3.5, +0.5] | 11.9 | 96 |
| postgres | none | 26,450 ± 1,082 tps | — | — | — | — |
| postgres | wasmsentinel | 23,799 ± 1,001 | −10.0% | [−14.4, −5.5] | **149.6** | 161 |
| postgres | falco | 23,712 ± 284 | −10.2% | [−15.3, −5.1] | 80.7 | 365 |
| postgres | tetragon | 25,907 ± 350 | −1.9% | [−7.9, +4.1] | 14.2 | 104 |

**解读**

- 吞吐下降：WasmSentinel 与 Falco 同量级（nginx 上更低：−4.4% vs −9.2%；postgres 上相同 ≈ −10%；redis 都在 −3 到 −4%）。Tetragon 在 redis/postgres 上几乎无开销（CI 含 0），但在 nginx 上 −16.6%、监控进程 CPU 282%——这是在我们这份策略（file-open + tcp-connect 钩子，事件全部导出）下的观测，论文要写清配置，不能当作 Tetragon 的一般结论。
- 监控进程自身：WasmSentinel RSS 97–161 MiB，Falco 固定 ≈ 365 MiB。CPU 上 WasmSentinel 在 postgres 臂到 **150%**（Falco 81%）：pgbench 16 个客户端产生大量 openat 与允许名单内 syscall，每个事件都进两条 Wasm 规则且 ml_detector 走逐事件特征重算（E3 已量化 70–105 µs/事件）。与 E5 quick 看到的现象一致，是论文 Discussion 要讲的设计杠杆（内核侧预过滤、规则声明所需钩子、增量特征）。
- **机器状态**：E4 期间有别的 autogen 代码执行容器与 vLLM 服务在跑，1 分钟负载中位 15、最高 49（`scratchpad/background_load.log`，36 个采样）。交错重复与配对差能抵消慢漂移，但不能抵消突发；绝对吞吐（尤其 nginx 178K req/s）带噪，Δ 的 CI 已经反映了部分噪声。投稿前若机器能空出来，`make e4` 重跑一次（25 分钟）替换这组数字。
- 系统整体 CPU（整机）各臂差别不大（nginx ≈ 91%，redis ≈ 20%，postgres ≈ 60%），说明监控进程的 CPU 主要是"挤占"而非"叠加"。

**CLAIMS**：C1.4 ✅（带噪声标注）。

## 2026-10-25 · E3 完成：端到端延迟与吞吐（回放，JSON vs 二进制）

`make e3`（05:43–05:59；commit ba7af70），`evaluation/results/2026-11/e3/{e3_results.json, e3_summary.md}`。ADFA-LD Attack_Data_Master 全部轨迹按 syscall 事件回放进完整管道（eBPF 事件形状 → 背压队列 → 两条规则 → 输出链，`--alert-log=false`、`--metrics-port 0`），启动时用 Training_Data_Master 训练 STIDE 库；1K / 10K / 50K eps × {json, binary} × 3 次，每次 30 s 的事件量。延迟为"事件产生 → 告警处理完"。

| 编码 | 提供 eps | 实际 eps | e2e p50 (µs) | p99 | p999 | detect p50 | detect p99 | RSS (MiB) |
|---|---|---|---|---|---|---|---|---|
| json | 1,000 | 964 | 118 | 183 | 325 | 105 | 149 | 90 |
| binary | 1,000 | 961 | 101 | 144 | 240 | 89 | 119 | 92 |
| json | 10,000 | 9,689 | 378 | 1,853 | 4,686 | 81 | 131 | 99 |
| binary | 10,000 | 9,688 | 304 | 1,246 | 3,585 | 70 | 112 | 100 |
| json | 50,000 | **14,996** | 334,813 | 425,654 | 445,640 | 82 | 117 | 178 |
| binary | 50,000 | **18,466** | 270,773 | 352,795 | 366,660 | 71 | 95 | 189 |

**解读**

- 1K 与 10K eps 两种编码都跟得上（实际 ≈ 96–97% 是回放节拍的粒度，不是丢事件；管道不丢事件，背压阻塞）。10K 时 e2e p50 0.3–0.4 ms、p99 1.2–1.9 ms、p999 3.6–4.7 ms（3 次里 rep 1 的 p999 到 7 ms，取均值）。
- 50K eps 是饱和点：单管道可持续约 **15.0K eps（JSON）/ 18.5K eps（二进制）**，之后延迟就是队列深度（p50 270–335 ms），论文里这一格报"可持续吞吐"，不把延迟当延迟数字。二进制比 JSON 多 23% 吞吐、低 15–20% 延迟。
- **瓶颈不在引擎**：detect p50 70–105 µs（两条规则合计），而 E2 的引擎空调用 2.1 µs、进程事件二进制路径 4.6 µs。差别在于回放的是 syscall 事件：ml_detector 对每个 syscall 事件都在 100 长窗口上重算 v1 特征（HashMap 计数）再过 MLP。增量更新特征是明确的优化杠杆（Discussion）。1K 时 detect 反而比 10K 慢（105 vs 81 µs），是低负载下核心降频/缓存冷，论文要注一句。
- RSS 90–100 MiB，饱和时 180–190 MiB（队列）。
- 机器状态同 E2（vLLM 常驻 ~2.5 核，1 分钟负载 4–5）。

**CLAIMS**：C1.3 ✅。

## 2026-10-25 · 论文：Evaluation（E1/E2/E6）与 Related Work 成文；参考文献审计

- `evaluation/scripts/paper_numbers.py` 除宏外直接生成四个表体 `paper-asiaccs/tables/{e1_table,e1_family_table,e2_table,isolation_table}.tex`，正文 `\input`；新增 `\provCpu`/`\provKernel`（取自 JSON provenance）、`\eTwoTraceLen`、按家族 recall 的宏（共 101 个，E3–E5 的 3 个占位仍是 `??`）。`make -C paper-asiaccs figures` 把 `e1_pr_curves.pdf` 拷进 `figures/`。
- `sections/evaluation.tex`：四个问题、Setup（硬件/内核来自宏，注明机器上有用户的 vLLM 常驻）、E2、E6、E1 成文；E3–E5 留位。`sections/related-work.tex` 成文：syscall HIDS、eBPF 监控（规则在这些系统里是受信代码）、Wasm 隔离基底、Wasm+eBPF 的最近工作。全文不写 "first"。
- **参考文献审计**：DIMVA 稿沿用的 `falco`（"FPGA '23"）、`tetragon`（"LPC '22"）、`tracee`（"Cloud Native Security Conference 2021"）三条是不存在的论文，改为项目引用；`transformer-sec`、`gnn-sec` 查无实据，删除。新增 wasm-bpf（arXiv 2408.04856）、Abbadini et al. ASIACCS '23 poster（DOI 10.1145/3579856.3592831）、Heinrich et al. ICISSP '24（DOI 10.5220/0012252800003648）、RLBox（USENIX Security '20）、Proxy-Wasm 规范。其余 24 条按标题/场合判断是真实的，投稿前逐条核 DOI（已列入 Phase 3 W1）。
- **先验检索结论**（web search；asta 连接时断时续）：没有找到"eBPF 采集 + Wasm 沙箱运行检测规则"的已发表系统；最近的是反方向的三篇（eBPF 加固 Wasm 运行时的 hostcall；Wasm 打包 eBPF 程序；对 Wasm 应用本身做异常检测）。Related Work 据此只列最近工作并说明差别。
- **同日晚些时候**：E3–E5 落地后补齐 Evaluation 其余三节，并写完 Introduction、Background、Threat Model、Design（含架构图）、Implementation、Discussion、Conclusion、摘要与两个附录（事件记录布局、v1 特征、基线超参）。`make -C paper-asiaccs numbers figures all`：10 页（正文约 8 页 + 参考文献 + 附录），229 个宏全部有值，0 个 overfull，`make lint` 干净。正文还有约 4 页预算，留给 W2 的贡献打磨与审稿人视角的补充。
- 教训：`conda run` 不转发 stdin，heredoc 喂给它的 Python 静默不执行；文本改动一律用 `/usr/bin/python3` 跑脚本文件。并行 Bash 调用共享 cwd，相对路径写文件会落错目录——全部用绝对路径。

## 2026-10-25 · E2 完成：同一模型三种实现的一致性与每次调用成本

`make e2`（05:43 起 23 s；commit ba7af70，`ml_detector.wasm` sha256 8e4238a2…，权重 sha256 1ee0c5d2…），输出 `evaluation/results/2026-11/e2/{e2_results.json, e2_summary.md}`。

- **一致性**：全部 5,951 条 ADFA-LD 轨迹，NumPy vs Wasm 最大差 1.91×10⁻⁶，NumPy vs 原生 Rust 1.90×10⁻⁶，原生 vs Wasm 5.0×10⁻⁹；0.7 阈值下判决 5,951/5,951 一致（与 quick 相同）。
- **整条轨迹一次打分**（662 条轨迹，中位长度 343 个 syscall，每条 30 次重复取中位）：NumPy 164.6 µs，原生 Rust 26.0 µs，Wasm（wasmtime-py，含 Python 侧调用与内存拷贝）126.3 µs；p90 分别 414 / 54 / 193 µs。Python 那一列度量的是 wasmtime-py 的调用路径，不是引擎；论文引擎成本只用下面三行。
- **Go 引擎**（`go test -bench`）：空规则一次调用 2.1 µs（`BenchmarkInvokeEcho`）；真实 ml_detector 处理一个进程事件 JSON 10.2 µs、二进制 4.6 µs。单位不同于上一条（一个事件 vs 一整条轨迹），表格里要分开。
- **机器状态**：E1 结束后静置 60 s 才跑；用户自己的 vLLM 服务常驻（两个 TP worker 各占约一核），整机 32 逻辑核、1 分钟负载 8。这些是单线程微基准，受影响有限，但 CI 不重跑计时部分。

**CLAIMS**：C1.1、C1.2 ✅。

## 2026-10-25 · E1 完成：ADFA-LD 5 折 × 3 种子，推理全部在 Wasm 模块内

**运行**：`e1_adfa_eval.py --device cpu`（`make e1` 的脚本部分）01:43 启动、05:42 结束，共 14,341 s，其中 LSTM 在 CPU 上训练占 14,239 s（GPU 被别的任务占满，`pick_device` 回退）。commit ba7af70，`ml_detector.wasm` sha256 8e4238a2…。输出 `evaluation/results/2026-11/e1/{e1_results.json, e1_summary.md, e1_pr_curves.{json,png,pdf}}`（图由 `plot_e1.py` 单独生成）。每折训练 4,760 / 测试 1,191 条轨迹。MLP 每折在 NumPy 里训练（上限 200 轮、25 轮早停，实际最佳轮次 44–165），权重经 `load_mlp_weights` 装进编译好的模块，**全部测试分数来自模块的 `mlp_score`**；15 折里 Wasm 与 NumPy 的分数最大差 1.1×10⁻⁶。

| 模型 | AUPRC | ROC-AUC | recall@5%FPR | recall@1%FPR | F1 @FPR5 工作点 | F1 @训练折 F1 最优 |
|---|---|---|---|---|---|---|
| WasmSentinel MLP（Wasm，v1 特征） | **0.730 ± 0.056** | 0.946 ± 0.011 | 0.718 | 0.345 | 0.691 | 0.700 |
| STIDE 6-gram 新颖率（仅正常） | 0.437 ± 0.043 | 0.787 ± 0.024 | 0.377 | 0.157 | 0.344 | 0.345 |
| Isolation Forest（仅正常，v1 特征） | 0.218 ± 0.007 | 0.745 ± 0.013 | 0.046 | 0.002 | 0.060 | 0.360 |
| Random Forest（监督，v1 特征） | **0.897 ± 0.028** | 0.982 ± 0.004 | 0.908 | 0.700 | 0.636 | 0.724 |
| LSTM（原始序列，监督，早停） | 0.825 ± 0.061 | 0.965 ± 0.012 | 0.858 | 0.488 | 0.760 | 0.792 |

配对 AUPRC 差（WasmSentinel − 基线，15 次 (seed, fold)，t-CI + Wilcoxon）：STIDE +0.293 [+0.257, +0.328]；IF +0.512 [+0.480, +0.544]；**RF −0.167 [−0.199, −0.135]**；LSTM −0.095 [−0.126, −0.064]；p 全部 ≤ 1.9×10⁻⁴。折间共享数据，CI 偏乐观（JSON `notes` 已写）。

按攻击家族、FPR-5 工作点的 recall（均值）：

| 模型 | Adduser | Hydra_FTP | Hydra_SSH | Java_Meterpreter | Meterpreter | Web_Shell |
|---|---|---|---|---|---|---|
| MLP (Wasm) | 0.79 | 0.80 | 0.87 | 0.80 | 0.71 | 0.66 |
| STIDE | 0.78 | 0.85 | 0.84 | 0.85 | 0.68 | 0.78 |
| IF | 0.04 | 0.00 | 0.03 | 0.05 | 0.13 | 0.06 |
| RF | 0.96 | 0.99 | 0.99 | 0.99 | 0.97 | 0.95 |
| LSTM | 0.83 | 0.91 | 0.92 | 0.91 | 0.87 | 0.76 |

**解读**

- MLP 对两种无监督基线有显著优势，对两种监督基线显著落后；1% FPR 下差距更大（recall 0.345 vs RF 0.700 / LSTM 0.488）。MLP 最弱的家族是 Web_Shell 与 Meterpreter。STIDE 在固定工作点上对 Hydra / Java_Meterpreter 的 recall 不输 MLP，它输在整体排序（AUPRC 0.44）。
- quick 模式（20 轮）看到的 0.38–0.42 是训练不足；训满后 0.73。折间方差不小：0.59–0.83（最低 seed 2 fold 1）。
- **论文怎么写**：C3 的主张是"部署模块输出的就是训练模型的分数"（E2 三路一致）加一张诚实的准确率表——**同一组 v1 特征上 RF 明显更好**，"轻量 MLP 的准确率"不是卖点；Isolation Forest 在这组特征上几乎不可用（recall@1%FPR 0.002）。
- **待用户拍板的产品决定**：把 RF（或深度受限的树集成）编进 Wasm 规则，以 `rf_wasm` 臂重跑 E1。估 1–2 人日：sklearn 树导出为扁平节点数组 → Rust 遍历 → 与 sklearn 的逐位一致性测试 → E1 加臂。做了之后论文可以说"规则语言不绑定模型族，RF 在沙箱内复现 0.90"；不做则只能在 Discussion 里讲。
- **标注**：`provenance.git_dirty = true` 是 `git status --porcelain` 把未跟踪文件（`paper-asiaccs/main.pdf`、输出目录自身）算了进来；运行期间跟踪文件与 ba7af70 一致（之后没有新提交）。脚本已改为 `--untracked-files=no`，已生成的 JSON 不追改。

**CLAIMS**：C3.2、C3.3 ✅。

## 2026-10-25 · 论文骨架 `paper-asiaccs/`

acmart sigconf + anonymous + review，AsiaCCS '27 会议信息占位；九个章节文件只含对应计划 §2 三条主张（C1 成本、C2 隔离、C3 等价与诚实的准确率）的提纲注释，Open Science 附录单独成文件；`CLAIMS.md` 是主张 → 实验 → JSON 的台账；正文数字一律走 `tables/numbers.tex` 宏（`make numbers` 由 `evaluation/scripts/paper_numbers.py` 从结果 JSON 生成）。`make lint` 会抓 "first system / zero-copy / 5x / 485" 这些不许再出现的词。参考文献沿用 DIMVA 稿的 29 条（是 CCS 稿 24 条的超集）。骨架可编译。

## 2026-10-25 · E4 / E5 驱动器就位（功能验证通过，正式数字等机器空闲）

**E4（`e4_overhead.py`，`make e4`）**：nginx（wrk -t8 -c128）、redis（redis-benchmark SET/GET，pipeline 16）、postgres（pgbench -c16 -j8，客户端在容器里跑，宿主只有 Debian 的 pg_wrapper）三种负载 × {none, wasmsentinel, falco, tetragon} 四臂，容器只发布到 127.0.0.1；每格 5 次交错重复；监控进程的 CPU%/RSS 与整机 CPU 每 0.25 s 采样；输出吞吐 Δ% 与配对 95% CI。`monitors.py` 负责以 root 拉起三套系统（WasmSentinel 走特权容器 chroot 回主机；Falco modern eBPF；Tetragon 带 file-open + tcp-connect 策略）。原稿里 `real_workload_test.py` 的 `monitoring='simulated'` 分支由这个脚本取代。

**E5（`e5_fair_comparison.py`，`make e5`）**：三种场景（读 /etc/shadow、把 /bin/true 拷到 /tmp 下执行、TCP 连 127.0.0.1:4444——harness 自己在 4444 监听并立即关闭）各跑 N 次，三套系统用等价规则：WasmSentinel 的 suspicious_shell；Falco 自定义三条规则叠在默认规则集上；Tetragon 策略 hook `__x64_sys_openat` 入口（`security_file_open` 看不到被权限检查拒绝的尝试，这是三者语义上的一个真实差别，论文要写）与 `tcp_connect` dport 4444，exec 用内建事件按 /tmp 前缀过滤。每条告警归到它之前最近的那次动作；报检出率、告警延迟（动作前的墙钟到首条告警）、RSS、CPU。

**调试里学到的（都写进代码注释）**：Falco 0.45 丢弃 enter 事件，`evt.dir=<` 是废弃项；"Falco initialized" 早于探针挂载，就绪要等 "One ring buffer every" 那行；Falco 输出要 `-U` 否则有缓冲；Tetragon 的 `security_file_open` 对 EACCES 的打开不触发。

**quick 一瞥（3 次、负载机器）**：三套系统三场景都 3/3，告警延迟 1–6 ms 量级。WasmSentinel 在试验期间 CPU 15.6%、RSS 97 MiB；Falco 4.5% / 363 MiB；Tetragon 1.6% / 76 MiB。WasmSentinel 高 CPU 的原因明确：每个 openat 都进两条 Wasm 规则且 ml_detector 走深路径，而 Falco/Tetragon 在内核侧先过滤——这是 E4 要量化、论文 Discussion 要讲的设计杠杆（规则驱动的钩子选择 / 内核侧预过滤）。

## 2026-10-25 · Phase 2 开工：E1 在跑，E2 一致性已出，E3 脚手架就位

**E1（`evaluation/scripts/e1_adfa_eval.py`，`make e1`）**：5,205 正常 + 746 攻击轨迹，分层 5 折 × 3 种子。WasmSentinel 的 MLP 每折在 NumPy 里训练（向量化重写的 `SimpleMLP`，内部 10% 验证集早停），权重用新导出 `load_mlp_weights` 装进编译好的模块，每个测试分数都来自模块的 `mlp_score`（特征与推理都在 Wasm 内）。基线：STIDE 6-gram 新颖率（仅正常）、Isolation Forest（仅正常，v1 特征）、Random Forest（监督，v1 特征）、LSTM（原始序列，早停；GPU 被别的任务占满，走 CPU）。指标：AUPRC、ROC-AUC、FPR≤5%/1% 下的 recall、两个在训练折上固定的工作点（训练正常分数 95 分位；训练折 F1 最优阈值）、按攻击家族的 recall、与 WasmSentinel 的配对 AUPRC 差（t-CI + Wilcoxon）。JSON 带 commit、wasm sha256、库版本、CPU。全量运行已在后台启动（01:43），quick 模式（1 种子 2 折，MLP 20 轮）先看到的数字：MLP AUPRC 0.38–0.42，STIDE 0.35–0.47，IF 0.21，**RF 0.85–0.88**，LSTM（3 轮）0.53。RF 在同一组特征上远好于 MLP——论文不能再讲"轻量 MLP 准确率"，这正是 §2 改为系统论文的理由；也提示下一个产品决定：把树模型编进 Wasm 规则（E1 收尾后评估）。

**E2（`e2_consistency.py`，`make e2`）**：同一模型三种实现跑完全部 5,951 条轨迹——NumPy vs Wasm 最大差 1.9×10⁻⁶，NumPy vs 原生 Rust 1.9×10⁻⁶，原生 vs Wasm 5×10⁻⁹，0.7 阈值下 5,951/5,951 判决一致。延迟部分（三种实现的 ns/call、Go 引擎调用开销）要等机器空闲再跑（现在 E1 在用 CPU）。原生 scorer 在负载下约 50 µs/轨迹，其中特征提取（HashMap 计数）占大头。

**E3（`e3_throughput.py`，`make e3`）**：管道增加端到端延迟分位数（事件产生 → 告警处理完）、检测分位数、max RSS；回放加 `--replay-max-events`；`--metrics-port 0` 关掉 HTTP；`--alert-log=false` 关掉逐条告警的控制台输出（输出链仍运行）。quick 模式在**负载机器**上的一瞥：1K eps 时 e2e p50 ≈ 150–170 µs；10K eps 时 JSON 臂排队到 p50 11.6 ms / p99 65 ms，binary 臂 0.8 ms / 20 ms，detect p50 ≈ 100 µs——ml_detector 的深路径（每个 syscall 事件对 100 长窗口算 v1 特征 + MLP）是瓶颈，引擎本身只占 ~2 µs。正式数字等机器空闲。

**待办**：E1 跑完 → 写结果；空闲时 `make e2 e3`；E4 需要 Falco/Tetragon 与 nginx/redis/postgres 的负载生成器，先盘点工具。

## 2026-10-25 · 决策：Track A（全量投 AsiaCCS 2027 Cycle 2）

用户于 2026-10-25 选定 Track A。截稿 2026-12-11 AoE，剩 47 天；Go/No-Go 门禁 11-20 不变。Phase 2 从 E1 开始，顺序 E1 → E2 → E3 → E4 → E5，E7/E8 视时间。

## 2026-10-18 · P2.0 STIDE 正常库的加载路径（E1 前置，完成）

**做了什么**

- ml-detector 新导出 `train_sequence(ptr, len)`（小端 u32 字节串，一条轨迹一次调用，调用前重置 n-gram 窗口）与 `train_finish()`（返回正常 n-gram 数）。STIDE 的键改为 **syscall 号**优先（有号用号，没号才用名），这样训练库与 eBPF 实时事件、回放事件用同一套键。
- 引擎新增通用 `HasExport` / `InvokeExport(rule, export, payload)`：对任意 `(i32,i32)->i32` 或 `()->i32` 导出复用同一套缓冲区、限额与统计；缺导出返回 `abi` 错误，不丢实例。
- CLI `--rule-train-dir <目录>`：启动时把目录里的 ADFA 格式轨迹喂给所有导出 `train_sequence` 的规则，再调 `train_finish`，打印 traces / syscalls / normal_ngrams。

**验收**：`TestInvokeExportTrainsSTIDE`：同一模块两份实例，一份用 UTD-0472 训练后再回放它自己 → 0/305 告警；未训练实例 → 300/305。Rust 侧 `train_sequence_makes_the_training_trace_quiet` 同样成立。全部 Go/Rust 测试通过。

**第一次有意义的在线数字（不是 E1，只是看一眼）**：用 ADFA-LD Training_Data_Master 全部 833 条轨迹训练（308077 个 syscall，正常 n-gram 59885 个，60–330 ms），然后按 syscall 事件回放：

| 回放 | 事件数 | ml_detector 告警 | 告警率 |
|---|---|---|---|
| Hydra_FTP_5 攻击轨迹，未训练 | 5,275 | 5,270 | 99.9%（空库，全部异常） |
| Hydra_FTP_5 攻击轨迹，已训练 | 5,275 | 3,728 | 70.7% |
| 50 条 Validation 正常轨迹，已训练 | 17,783 | 3,108 | 17.5% |

**解读与给 E1 的输入**：按单个 syscall 事件报警，正常流量也有 17.5% 的事件被标记——这不是可部署的工作点。原因有两个候选（`StideConfig.max_database_size` 默认 100,000，训练集只产生 59,885 个唯一 6-gram，**没有截断**，可以排除）：(1) 组合分数里 STIDE 一旦判新就贡献 0.4，再加 MLP 的分数很容易过 0.1 的 level-1 门槛，应该按轨迹（或按窗口）聚合而不是逐事件报警；(2) 训练用整条轨迹、在线用 100 长窗口。另外 Validation 轨迹本身含训练集没见过的 6-gram（STIDE 的经典弱点），逐 n-gram 判新必然有这一层误报。E1 的离线评估按整条轨迹用 `mlp_score` 做 PR 曲线，不受这三条影响；在线路径的工作点属于 E7/论文 Discussion。

## 2026-10-18 · E6 沙箱隔离实验（完成，替换硬编码的 "5/5 blocked"）

**做了什么**

- `rules/adversarial/`：10 个故意越界的规则模块（Rust → wasm32-wasip1，共 348 KB）：读 /etc/passwd、列 /、写 /tmp；枚举环境变量与 argv；TCP 连接；8 MiB 刷 stdout/stderr；读时钟（允许的能力，作对照）；16 MiB 步长撑内存直到被拒；一次申请 1 GiB；死循环；`proc_exit(3)`；无界递归。
- `host/internal/engine/adversarial_test.go`：在默认限额（64 MiB / 5×10⁷ fuel / 100 ms）下逐个加载、调用、记录结果、确认邻居规则不受影响、确认下一次调用引擎已恢复；`WASMSENTINEL_RESULTS_DIR` 设置时写出 `isolation.json` 与 `isolation.md`。
- 根目录 `Makefile`：`make isolation` / `make parity` / `make reproduce` → `evaluation/results/2026-11/`（附 README 说明每个文件的生成命令）。CI 新增 `isolation` job，在 ubuntu-latest 上重跑并把表格贴进 job summary。
- 删除 `evaluation/scripts/sandbox_isolation_test.py`（整个脚本是 `simulate_test` 的硬编码字典）。

**结果（本机，commit 见 git log）**：11/11 包含。

| 模块 | 结果 | 耗时 |
|---|---|---|
| fs_read / env_leak / net_connect / stdout_flood | 全部返回 0：读不到、看不到、连不上、刷不出去 | ≤ 1.6 ms |
| clock | 返回 1：时钟是允许的能力（论文里要写明白） | 0.01 ms |
| mem_bomb_graceful | 到 32 MiB 时 `try_reserve` 失败停下（Vec 翻倍 + 拷贝需要 80 MiB 瞬时），实例内存 49.1 MiB < 64 MiB | 20 ms |
| mem_bomb_abort | 1 GiB 请求被 limiter 直接拒绝 → 分配器 abort → trap；实例重建 | 0.06 ms |
| cpu_spin（fuel） | `fuel` trap | 3.5 ms |
| cpu_spin（仅超时） | `timeout` trap | 104 ms |
| proc_exit | `exit` trap | 0.03 ms |
| stack_overflow | trap | 2 ms |

**一个诚实的标注**：一次性申请 1 GiB 时线性内存根本没有增长（grow 被整体拒绝），引擎无法把这个 abort 和普通 `unreachable` 区分开，只能标为通用 `trap`；"被拒绝、实例重建、邻居无感"三条都成立，但论文表格里这一行的类别要写 trap 而不是 memory。wasmtime-go 的静态 limiter 没有回调，要精确归类需要换成带回调的 limiter（升级到 v49 后看 API）。

## 2026-10-18 · P1.7 命名统一（完成）

三个名字收敛为一个：项目 **WasmSentinel**，二进制 / 容器 / 镜像 / compose 服务 **`wasmsentinel`**，Go 模块 **`github.com/GeoffreyWang1117/WasmSentinel/host`**（与仓库地址一致）。

- 57 个文件、248 处替换（脚本化，按"先具体后一般"的顺序：模块路径 → GitHub URL → 旧指标名 `wasm_threat_detector_total_threats` / `_threats_by_severity` → `wasmsentinel_threats_total` → `WASM-ThreatDetector` → `wasm-threat-detector` → `wasm-sentinel`）。`docs/history/`、`paper*/`、`evaluation/results/`、三份计划/日志文件保留历史写法。
- 路径随之变化：配置 `/etc/wasmsentinel/config.yaml`、日志 `/var/log/wasmsentinel.log`、用户配置 `~/.wasmsentinel.yaml`、Grafana 面板文件 `wasmsentinel.json`、compose 网络 `wasmsentinel-*`。`CONTRIBUTING.md` 里不存在的 `security@…org` 邮箱改为 GitHub Security Advisories。
- 验收：`go build/vet/test -race` 全绿；`./wasmsentinel --collector=replay` 冒烟正常；四个 compose 文件 `docker compose config` 通过；CI / Pages workflow、config、Prometheus 配置、Grafana JSON 解析正常。

**Phase 1 至此全部完成**（P1.1–P1.7）。下一步是 10-19 决策点与 Phase 2 实验；Phase 2 开工前必须先解决"STIDE 正常库没人加载"（见 P1.4 / P1.6 观察）。

## 2026-10-18 · P1.6 测试与端到端回放（完成）

**做了什么**

- 事件循环从 `main.go` 搬进 `host/internal/pipeline`：`Run(ctx, Config)` 合并采集器通道、驱动引擎、交给输出链，返回 `Stats{Events, Alerts, DetectErrors, OutputErrors, Elapsed}`；采集器全部关闭或 ctx 取消时结束。合并队列改为**背压**（阻塞发送），不再在管道里静默丢事件；内核侧丢弃由 eBPF 采集器自己计数。
- `collector.ReplayCollector`（`--collector=replay`，`--replay-file` 文件或目录、`--replay-eps`、`--replay-loop`）：把 ADFA-LD 格式的 syscall 号轨迹按 eBPF 事件形状回放（经 `EventFromEBPF`，含二进制载荷），每条轨迹一个 pid，播完关闭通道 → 进程自行退出并打印 Pipeline / Rule statistics。这就是 E3 吞吐实验的驱动器。
- 测试：`pipeline` 三个用例——50 个事件经两个采集器全部送达两条规则、指标计数一致；取消即停且 `Elapsed` 正确；**端到端**：真实模块 + `testdata/adfa_attack_hydra_ftp.txt`（306 个 syscall）在 `EncodingBinary` 下回放，两条规则各 306 次调用且全部走 `detect_raw`、0 错误、告警只来自 ml_detector。`collector` 四个回放用例（解析、顺序与 pid、节流与循环、坏路径）。
- 顺手修掉 `Run` 的 `Elapsed` 永远为 0（defer 改写的是值拷贝）。

**验收**：`go test -race ./...` 七个包全绿（collector / ebpf / engine / metrics / pipeline / wire），CI 跑同一套。CLI 冒烟：`--collector=replay --event-encoding=binary` 回放两条轨迹 611 个 syscall，自动退出，ml_detector 606 告警、suspicious_shell 0 告警，最大单次延迟 276 µs，fuel 总量 3.8×10⁸。

**观察**：STIDE 正常库为空时几乎每个 syscall 事件都升级到 MLP 深路径并报警（306 → 301）；这不是 bug，是 P1.4 已记录的"没人加载 STIDE 库"问题，E1 前必须给 `init` 配置或 `train` 一条真实加载路径，否则在线路径的告警量没有意义。

## 2026-10-18 · P1.5 真实 Prometheus 指标（完成）

**做了什么**

- 删除假的 `/metrics`（把 `time.Now().Unix()` 当计数器输出）和 `output.PrometheusOutputHandler` 桩；新建 `host/internal/metrics`（prometheus/client_golang v1.25.0，私有 registry）。
- 指标（namespace `wasmsentinel`）及来源：`threats_total{rule,severity}` 来自输出链；`events_total{type}`、`events_dropped_total`、`detect_latency_seconds` 来自事件循环；`rule_calls_total{rule,encoding}`、`rule_errors_total{rule,kind}`、`rule_fuel_total{rule}`、`rule_latency_seconds{rule}` 来自引擎新增的 `Observer` 钩子（每次规则调用一次回调，含 fuel 与错误类别）；`rule_memory_bytes`、`rule_reinstantiations_total`、`rule_positive_calls_total` 抓取时读引擎快照；`collector_records_total`、`collector_dropped_total`、`collector_events_total{type}` 读 eBPF 采集器快照；`build_info{collector,encoding,wasmtime}`；外加 Go 运行时与进程采集器（`process_resident_memory_bytes` 等，E4 的开销测量直接用）。
- `main.go` 接线：引擎 `SetObserver`、输出链加 metrics handler、eBPF 采集器注册、事件循环计时与丢弃计数；`/metrics` 走 `promhttp`，`/health` 保留。
- 顺带：评估脚本里的 `/home/coder-gw/...` 绝对路径改为相对仓库（`run_experiments.py`、`train_mlp.py`、`wasm_benchmark.py`、`evaluate_lid_ds.py`、`quick_test.sh`）；`go.mod` 随依赖升到 go 1.26。

**验收**：`metrics` 包单测抓取文本并断言 21 个序列。本机 proc 模式冒烟，两次抓取间隔 3 s：`events_total{type="process"}` 943 → 1,071，`threats_total` 各严重度同步递增（suspicious_shell critical 316 → 412，ml_detector low 14 → 26），`rule_memory_bytes` 1.18 MB / 1.38 MB，`rule_fuel_total` 累计 5.6×10⁷，RSS 81.5 MB，`/health` 200。

**观察**：proc 采集器启动时把现存进程全部当作新事件（3 s 内 943 个），suspicious_shell 对其中约 99% 报警（root + shell 名就够分），ml_detector 去掉未训练的 MLP 后只报 16 个。规则质量归 E1 / E7。

## 2026-10-18 · P1.4 模型与 ABI 统一（完成）

**发现（比改动本身更重要）**

- 部署的 ml_detector **从未使用训练权重**：`HybridDetector::with_config` 用 `MlpDetector::with_config(config.mlp)` 构造，权重是确定性公式的伪随机初始化；宿主从不调用 `load_mlp_weights`，`with_embedded_weights` 只在单测里出现。
- 即便用上权重也对不上：Rust 给 MLP 喂的是按 syscall **名**分类的另一套 64 维特征（`mlp::features::extract_syscall_features`），训练用的是按 syscall **号**计算的 `train_mlp.extract_features`（46 维有值）。进程事件还把进程特征塞进这个 syscall 模型。
- 嵌入的 weights.rs 是 64-32-16-1（6,785 参数）的 `mlp_weights.json`，论文描述的是 128-64-32-16（19,201 参数）的 `best_model_weights.json`。
- 结论：DIMVA 稿里任何"Wasm 内 MLP"的检测数字都不可能来自这个模块；§1.4 的 ❌ 有了机制层面的原因。

**做了什么**

- `features::adfa_features`：逐行移植 Python `extract_features`（Counter 的首现顺序、`most_common` 的稳定排序、全部按 f64 计算再转 f32）。类别集合混用 ABI 编号（0/1 是 x86_64，56/57 是 aarch64，ADFA-LD 是 i386），原样保留，换特征集是 E1 的评估问题。
- `weights.rs` 由 `embed_weights.py` 从 `best_model_weights.json` 重新生成：128-64-32-16，19,201 参数，`MODEL_SHA256` `1ee0c5d2…`，阈值 0.7（EXPERIMENT_REPORT 阈值分析）。`MlpDetector::with_embedded_weights` 的结构从 `HIDDEN_SIZES` 读取，不再写死。
- `hybrid.rs` 重写在 `EventFields` 上（JSON 与二进制同一套代码）：MLP 永远是嵌入模型，config 只能改阈值；syscall 路径按进程维护 syscall 号窗口（默认 100）喂 `adfa_features`；进程 / 网络 / 文件只走规则；处理 `process_exit` 释放状态；`max_processes`（默认 4096）按最近访问淘汰。
- 新导出 `mlp_score`、`mlp_features`、`model_info`（结构、参数量、阈值、来源、sha256）；`detect_extended` 继续返回 `anomaly_score`。
- `train/verify_wasm_parity.py`：用 wasmtime-py 加载模块，对 1,000 条合成序列 + 400 条 ADFA-LD 轨迹逐条比较 NumPy 参考与 Wasm 的特征与分数；`--write-golden` 生成 `train/fixtures/features_golden.json`（18 例），`tests/parity_golden.rs` 在 `cargo test` 里对照，CI 不需要 Python；CI 的 ml-detector job 另跑 1,000 条合成序列的 wasmtime 对照。
- 来源说明写在 `rules/ml-detector/MODEL.md`。

**验收**：1,400 条输入，特征最大绝对差 **0**（逐位一致），分数最大绝对差 **1.97×10⁻⁶** < 10⁻⁵（第 32 条，长度 100：0.371615 vs 0.371613）。Rust 21 个单测 + golden 测试通过；Go 全绿，JSON/二进制对等测试仍通过。hybrid 迁到 trait 后 ml_detector 二进制路径 4.4 µs（JSON 8.1 µs），P1.3 时是 18.9 µs。

**给 E1 的输入**

- 训练用整条轨迹（数百到数千 syscall），线上是 100 长窗口：训练/部署分布不一致，离线评估按整轨迹做，在线窗口是部署选择，论文要写明。
- STIDE 正常库目前没人加载（`train` 导出存在，宿主不调用）：空库让所有 n-gram 异常、全部走 MLP。E1 和部署都需要一条加载路径。
- STIDE 窗口是全局的，多进程交错会混；ADFA 回放是单轨迹顺序，不受影响。

## 2026-10-18 · P1.3 二进制事件通道（完成；含一个推翻预期的测量）

**做了什么**

- 定义二进制事件载荷（Go `host/internal/wire`，Rust `rules/sentinel-abi`）：16 B 头（magic `WSB1`、版本、记录长度、字符串区长度）+ 内核记录原样 592 B + 宿主解析好的字符串（user、group、syscall_name，NUL 结尾）。记录从 ring buffer 到 guest 线性内存只经过一次拷贝，不经过 Go 结构体编码或 JSON。
- `events.Event` 增加 `Binary []byte`（不序列化），eBPF 适配层每个事件构造一次；`ebpf.Event` 保留 `Raw` 记录并提供 `Record()` 逆向编码（测试与回放用）。
- 引擎：`--event-encoding=json|binary`；规则可选导出 `detect_raw(ptr,len)`；binary 模式下有二进制形式且规则导出 `detect_raw` 时走 raw，否则该规则回退 JSON（JSON 每事件最多序列化一次）；`InvokeRaw`、`RuleStats.CallsRaw`；缺导出时返回 `abi` 类错误且不丢实例。
- 两个规则 crate 都导出 `detect_raw`。sentinel-abi 提供 `to_value()`（从记录重建与 Go `EventFromEBPF` 相同的 JSON 结构）和 `EventFields` trait（`JsonEvent` / `RawEvent` 两个视图，直接按字段读取、不建树）。suspicious-shell 的三段检测逻辑改写到 trait 上；ml-detector 暂用 `to_value()`。
- 删除 `host/internal/bridge/zero_copy.go`（515 行，自定义格式，从未被引用）。
- CI 的 Rust matrix 加入 `rules/sentinel-abi`。

**验收**：`TestRawAndJSONPathsAgreeOnRealModules` 用 9 个覆盖全部事件类型的内核记录，对 suspicious_shell 与 ml_detector 各开两份实例（一份喂 JSON，一份喂二进制），逐条比较 level，全部相等且含正例；sentinel-abi 内 `raw_view_matches_json_view` 逐访问器比较两个视图；suspicious-shell crate 内 `raw_and_json_paths_agree`。`go test -race ./...` 全绿（collector / ebpf / engine / wire 四个包）。

**测量（本机单 goroutine，`-benchtime 2s`）**

| 基准 | JSON | binary | 备注 |
|---|---|---|---|
| suspicious_shell 单次调用，`to_value()` 重建 JSON 树的第一版 | 7.6 µs | **8.1 µs** | 更慢：建树的分配量与 serde_json 文本解析相当，"省掉解析"只是把成本搬了地方 |
| suspicious_shell 单次调用，改为 `EventFields` 直接读记录 | 7.8 µs | **4.2 µs** | −46%；剩余 4.2 µs 中约 2.2 µs 是引擎调用开销 |
| ml_detector 单次调用（仍用 `to_value()`） | 17.5 µs | 18.9 µs | 同第一行的原因；P1.4 把 hybrid.rs 迁到 trait 上 |
| 端到端：适配层转换 + `DetectThreat`（suspicious_shell） | 11.7 µs / 39 allocs / 2.5 KB | **5.6 µs / 26 allocs / 1.8 KB** | 2.1×，省掉 `json.Marshal` 与 guest 解析 |

**结论与对论文的影响**：论文草稿里"零拷贝 5×（165→33 µs）"没有来源，本次实测给出的是 **2.1×（端到端）**，且前提是规则按字段读记录；一旦规则在 guest 内重建通用 JSON 结构，收益归零。E3 应报告两臂的端到端数字与这个前提。命名上不再用"zero-copy"：ring buffer → guest 至少一次拷贝，文稿改称 binary direct-write / in-place record。

**遗留**：ml_detector 的 raw 路径仍建树（P1.4 一并迁移）；默认编码保持 `json`，E3 两臂对比后再定默认值。

## 2026-10-17 · P1.1 eBPF 采集器接入（完成）

**做了什么**

- `bpf/sentinel.bpf.c` 重写：事件结构按自然对齐排布（592 B，无 `packed`，C/Go 布局一致，Go 侧用 bpf2go `-type event` 直接生成）；exec 钩子从 `syscalls/sys_enter_execve` 换成 `sched/sched_process_exec`（exec 成功后触发，从 `mm->arg_start..arg_end` 读完整 argv，≤256 B，NUL 分隔）；exit 只记线程组 leader 并带退出码；网络字段用 CO-RE 读；raw `sys_enter` 允许列表扩到 20 个高风险 syscall（clone/fork/execve/kill/ptrace/setuid/setgid/pivot_root/prctl/chroot/mount/umount2/init_module/unshare/setns/finit_module/memfd_create/bpf/execveat/clone3）；ring buffer 256 KiB → 1 MiB。
- cilium/ebpf v0.12.3 → v0.22.0（go.mod `go 1.25.0`，Dockerfile 换 `golang:1.26-bookworm`）。
- `host/internal/ebpf` 重写：`--ebpf-hooks` 逐钩子挂载、原子计数、`Stop()` 不再持锁等 goroutine（旧实现会死锁）、解码走生成的 `sentinelEvent`；x86_64 syscall 名表（385 项）由 `/usr/include/x86_64-linux-gnu/asm/unistd_64.h` 生成。
- `collector.EBPFCollector` 适配层：内核事件 → `events.Event`，字段名与规则一致（`data.process.{executable,command_line,user,…}`、`data.file.{path,operation}`、`data.network.{dest_ip,dest_port,direction}`、`data.{syscall_nr,syscall_name}`）；exit 事件类型为 `process_exit`，规则不会把同一进程算两次；uid/gid → 用户名缓存。
- `main.go`：`--collector=proc|ebpf`（默认 proc，不需特权）、`--ebpf-hooks`；config 键同名。
- `rules/ml-detector/src/hybrid.rs`：syscall 事件改从 `data` 下读字段（兼容扁平记录）。
- 单测 10 个（无需 root）：记录大小 592、exec/截断 argv/网络/syscall 解码、钩子解析、允许列表都有名字；适配层对 exec/exit/file/network/syscall 的 JSON 形状。

**验收（7.0.0-34-generic，本机无免密 sudo，用 `docker run --privileged --pid=host -v /:/host … chroot /host` 以 root 身份运行主机二进制）**

| 运行 | 结果 |
|---|---|
| 全部 6 钩子，16 s，主机侧跑 `bash -c 'cat /etc/hostname; ls /tmp; id -un'`、`curl 127.0.0.1:1`、`rm -rf <不存在路径>` | 6 个钩子全部挂上；收到 30,670 条、丢 0：file_open 26,352 / syscall 2,917 / process_exit 815 / process_exec 515 / network_connect 71。exec 事件带完整 argv（`["bash","-c","cat /etc/hostname > /dev/null; …"]`）与解析后的路径 `/usr/bin/bash`；connect 带目标 `172.64.155.209:443`；syscall 命名为 `bpf`、`prctl` |
| 仅 connect,accept，9 s，`curl 127.0.0.1:22` ×3 | 13 connect + 3 accept（`sshd`，对端 `127.0.0.1:39626/39642/39644`） |
| 规则侧（第一轮） | 两条规则各 27,996 次调用，0 trap，最大延迟 220 µs / 444 µs；suspicious_shell 标记 4,182、ml_detector 3,168 |

**观察 / 限制**
- `openat` 占事件量 86%（空闲桌面约 1,650/s）；忙机器上用 `--ebpf-hooks=exec,exit,connect,accept,syscall` 去掉它，或在 P1.3/E3 做内核侧过滤。
- IPv6 连接只带 `family=10`，地址为空（事件结构没留 16 B 字段），后续需要时扩展结构。
- ml_detector 实例内存 1.18 → 1.31 MB（`process_states` 随 pid 增长，没有淘汰）——P1.4 处理。
- 关闭时 `dropped_after_cancel` 585：ctx 取消后到钩子卸载之间的事件，预期行为。
- `vmlinux.h` 未重生成：CO-RE 重定位在 7.0 内核上加载成功，现有头文件够用；需要时 `make -C host/internal/ebpf vmlinux`。
- 用 `--log-level trace` 可逐条打印内核事件（argv、目标地址、syscall 名），用于核对。

## 2026-10-17 · P1.2 引擎限额（完成；wasmtime-go 升级顺延）

**做了什么**（`host/internal/engine/`，替换 `simple_engine.go` 与 `wasm_engine.go`）

- 每条规则一个长寿 Store/Instance，跨事件复用；事件 JSON 写进 guest 用 `alloc` 导出的缓冲区（按需翻倍增长），不再写固定偏移 1024（那块地址落在 Rust 的 shadow stack 里）。
- Guest ABI v2：必须导出 `memory`、`alloc(i32)->i32`、`dealloc(i32,i32)`、`detect(i32,i32)->i32`，可选 `init(i32,i32)->i32`（实例化后以 (0,0) 调用一次）。两个 Rust crate 各加 10 行 alloc/dealloc；没有 alloc 的旧模块在加载时被拒绝，错误信息指明缺哪个导出。
- 三重限额，互相独立、可单独关闭：`Store.Limiter` 线性内存上限（默认 64 MiB；超限时 guest 内 `memory.grow` 失败，Rust 分配器 abort → 记为 `memory` trap）；fuel 指令预算（默认 5×10⁷/次）；epoch 墙钟超时（默认 100 ms，后台 ticker 周期 = timeout/10 夹在 1–10 ms）。
- Trap 处理：任何 trap（unreachable / fuel / 超时 / 内存 / `proc_exit`）都丢弃该规则的实例，下一次调用从已编译 Module 重建；其它规则各有自己的 Store，不受影响。
- WASI 零能力：`NewWasiConfig()` 不继承 stdio、无 env、无 args、无 preopen。
- 每规则统计 `Stats()`：calls / threats / errors / traps 分五类 / reinstantiations / fuel（last、total）/ latency（last、max、total）/ 当前内存；`main.go` 退出时逐规则打日志（P1.5 接 Prometheus 时直接用）。
- 新 flag 与 config 键：`--rule-memory-mb`、`--rule-fuel`、`--rule-timeout`。

**验收（`go test -race ./...` 全绿，14 个用例）**

| 用例 | 覆盖 |
|---|---|
| InvokeReturnsGuestLevel / DetectThreatMapsLevelsAndOrdersRules | 正常检测、level→severity 映射、规则按名字序执行 |
| FuelBudgetStopsRunawayRule | 死循环 guest 在 2×10⁶ fuel 处被切断，`TrapFuel`；邻居规则照常，再次调用自动重建 |
| EpochDeadlineStopsRunawayRule | fuel 关闭、30 ms 超时：在 ≥30 ms、≪2 s 内中断，`TrapTimeout` |
| MemoryCapIsEnforcedInsideTheGuest | 8 页上限下 guest 的 grow 循环恰好停在 8 页；初始 2 页的模块在 1 页上限下拒绝加载 |
| TrapIsIsolatedAndInstanceIsReplaced | `unreachable` 只影响本规则，Reinstantiations=1，后续调用正常 |
| WasiHasNoCapabilities | guest 看到 0 个环境变量、0 个参数；写 fd 1 不会出现在宿主 stdout |
| LoadRejectsModuleWithoutAllocator / LargeEventGrowsGuestBuffer / UnloadAndUnknownRule / ConcurrentInvocations / CloseIsIdempotent | ABI 校验、300 KiB 事件、卸载、8 goroutine 并发（-race）、Close 幂等 |
| RealSuspiciousShellRule / RealMLDetectorLoadsAndRuns | 真实模块：良性 `ls` 不报，`bash -c 'rm -rf …'` 报 critical；ml_detector 带 `init` 正常加载运行（模块未构建时 skip） |

测试桩是 7 个 WAT 文件（`testdata/`），用 `wasmtime.Wat2Wasm` 编译，CI 不需要 Rust 即可覆盖全部限额路径。

**数字（本机，单 goroutine）**

| 指标 | 值 | 来源 |
|---|---|---|
| 引擎每次调用开销（stub guest，256 B） | 2.2 µs，13 allocs | `BenchmarkInvokeEcho` |
| suspicious_shell 一次检测（含 JSON 解析） | 6.2 µs | `BenchmarkRealSuspiciousShell` |
| fuel / 事件 | suspicious_shell ≈ 6.3×10⁴，ml_detector ≈ 1.6×10⁵ | 6 s 冒烟运行的退出统计（各 1,096 次调用） |
| 单规则最大延迟（冒烟） | 134 µs / 496 µs | 同上 |
| 实例线性内存 | 1,179,648 B（Rust 1 MiB 栈 + 数据） | 同上 |

默认 fuel 5×10⁷ 对现有规则有 300–800 倍余量；真正的阈值在 E3 用 ADFA-LD 回放再定。

**顺延：wasmtime-go v17 → v49。** 本机此刻对 proxy.golang.org、goproxy.cn、GitHub codeload 的大文件下载只有 2–6 KB/s，v49 模块包 11 分钟只到 2.4 MB，已中止。v17 已具备 `SetFuel/GetFuel`、`Limiter`、`SetEpochDeadline`、`IncrementEpoch`、`Trap.Code`、`Error.ExitStatus` 全部所需 API，代码对 v49 只差 import 路径。网络恢复后：`go -C host get github.com/bytecodealliance/wasmtime-go/v49@v49.0.0`，改两处 import，`go mod tidy`，同时把 Dockerfile 的 `golang:1.21` 升到 v49 要求的版本。

**顺带观察**：/proc 采集器 + 关键词规则下，6 s 内 1,096 个事件被 suspicious_shell 全部标记（root + 常见 shell 名就能凑够分），ml_detector 对每个进程事件都给 level 2。检测质量属 P1.4 / E1 范畴，这里只记录。

## 2026-10-16 · Phase 0 止血与地基（全部完成）

**用户确认的决策**：DIMVA 2026 / ICICS 2026 均未投出；目标会议为 AsiaCCS 2027 Cycle 2（截稿 2026-12-11 AoE）；27 GB 日志可删。

| 编号 | 结果 | 证据 / 命令 |
|---|---|---|
| P0.1 | 实体目录迁至 `~/Engineering/WasmSentinel`（NVMe）；`/data/EngineeringFrozen/WasmSentinel` 改为 symlink；HDD 旧副本保留为 `/data/EngineeringFrozen/WasmSentinel.hdd-ro-2026-10-16`（不再更新） | `readlink -f /data/EngineeringFrozen/WasmSentinel` |
| P0.2 | push `a293001`、`83e8819` → `origin/main`；工作区按主题提交（见 `git log --oneline 83e8819..main`） | `git log origin/main..HEAD` 为空 |
| P0.3 | `.gitignore` 新增 `*.wasm`、`/wasm-threat-detector`、`evaluation/datasets/raw/`、`.claude/`，保留 `host/internal/ebpf/sentinel_bpfel.o`；取消跟踪 32 MB 二进制、`rules/suspicious-shell/target/`（127 文件）和两个没有 `.gitmodules` 的 gitlink；新增 `scripts/fetch_datasets.sh`（钉住 ADFA-LD `68bedf5`、LID-DS `587d158`） | `git ls-files | grep -c target/` → 0 |
| P0.4 | 删除 `logs/wasm-threat-detector.log`（27,156,108,061 B）及其在 `/data/EngineeringBackup/snapshots/daily/daily.2026-10-{14,15,16}_*/WasmSentinel/logs/` 的 4 个硬链接（不删硬链接空间不会释放）；4 个 compose 文件给检测器加 json-file 20 MB × 5 轮转；`config/config.yaml` 默认 `log-file: ""`（stdout）；showcase 仍写文件供 demo-ui 读取并已注释 | `df /data` used 5.2T → 5.1T |
| P0.5 | `rustup target add wasm32-wasip1`；conda env `wasmsentinel`（clone 自 `fisherkd`：torch 2.5.1+cu121、sklearn 1.7.2、wasmtime 49.0.0）；wasmtime CLI 49.0.3 → `~/.local/bin/wasmtime`（release tarball，sha256 已核）；`falcosecurity/falco:latest`、`quay.io/cilium/tetragon:v1.7.1` 已 pull；bpf2go 不单独安装，`go generate` 用 go.mod 钉住的 cilium/ebpf v0.12.3 | `conda run -n wasmsentinel python -c "import wasmtime"` |
| P0.6 | `host/internal/ebpf`：go:generate 加 `-D__TARGET_ARCH_x86 -target bpfel`（缺它 clang 报错），生成并提交 `sentinel_bpfel.{go,o}`；删未用 import；`go build ./...`、`go vet`、`gofmt`、`go test -race` 本地通过。两个 Rust crate `cargo fmt`、`cargo test --release`（ml-detector 17/17）、wasm32-wasip1 构建通过。CI 重写为 `go` / `wasm-rules`（matrix 两 crate）/ `ebpf`（重生成绑定并 diff）/ `release`（仅 tag）四个 job，换用 setup-go v5、dtolnay/rust-toolchain、upload-artifact v4、softprops/action-gh-release v2；删除 Docker Hub push、codecov、nancy、actions-rs | CI run 38963081060（c17f8d4）：go ✅、两个 wasm-rules ✅、ebpf ❌（runner 缺 `bpf/bpf_helpers.h`）→ 加 `libbpf-dev` 后 run 38963364381（aa7ae17）四个 job 全绿；Pages 部署 run 38963081351 ✅ |
| P0.7 | `CCS2026_ROADMAP.md`、`RESEARCH.md`、`SESSION_STATE.md`（→ `_2026-01-04`）、`README_backup.md`、`paper/EVALUATION_GAP_ANALYSIS.md` 移入 `docs/history/`（附 README 说明为何过期）；`ml_comparison_results_v2.json` 移入 `evaluation/results/2026-02/` 并标注为 smoke run；删 `texput.log` | 根目录 `ls *.md` |

**顺手修的**：README / README_cn / QUICKSTART / CONTRIBUTING / DEMO / `docs/development.md` / `test-datasets/evaluation/*.sh` 里的 `wasm32-wasi` → `wasm32-wasip1`（旧 target 名已被 Rust 移除）；`scripts/build.sh` 现在构建两个 crate 并把 `.wasm` 放进 `rules/wasm/`。

**注意事项**
- `rules/wasm/ml_detector.wasm` 不再入库。本地重建的模块（172,355 B，rustc 1.97.1）与 2026-01-04 的旧模块（184 KB）哈希不同；P1.4 统一模型版本时一并处理。
- `docker-compose.yml` 里的 fluentd 仍 tail `/var/log/wasm-threat-detector.log`，默认改 stdout 后它读不到内容；ELK 演示链路如要保留，改用 Docker fluentd 日志驱动（Phase 4）。
- clippy 未纳入 CI：ml-detector 有大量 warning，suspicious-shell 2 个；P1 重构时清理。
- 旧 HDD 副本与每日快照共享 inode（备份脚本用 `--link-dest`）：在 `.hdd-ro-2026-10-16` 上原地改文件会同时改掉快照，不要在那里工作。
- `evaluation/datasets/raw/` 现为 git-ignore；本机数据仍在原位，新机器用 `scripts/fetch_datasets.sh`。

**下一步**：10-19 决策点（Track A 全量投稿 / Track B 工程收尾 + arXiv），见 `DEVELOPMENT_PLAN.md` §2.3。无论哪条 Track，P1.2（引擎限额）先做。
