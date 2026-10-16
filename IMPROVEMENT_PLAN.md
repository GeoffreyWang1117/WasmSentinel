# WasmSentinel 改进方案

**生成**: 2026-10-13 · **当前**: public，201K 行，有 DIMVA 论文线，CI + LICENSE 齐全
**注意**: 实体在 `/data/EngineeringFrozen/WasmSentinel`，`~/Engineering/WasmSentinel` 是 symlink。

---

## P0 —— 历史没有任何远端备份，而本地有 2 个未推送 commit + 172 个未提交改动

实查（2026-10-13）：
```
unpushed commits: 2
dirty files:    172
```
而你那两套 nightly rsync 备份（`/data/EngineeringBackup`、`/data/ProjectsBackup`）
**都带 `--exclude='.git'`**（见各自 sync.sh:86，注释写明是 2026-08-02 刻意改的，
理由是「历史保护是 remote 的事」）。

组合起来的后果：**这 2 个 commit 和 172 个改动，目前只存在于这一块盘上。**
机械盘故障就是永久丢失。这是本次全盘扫描里风险最高的一条，和项目价值无关。

### 立刻做（几分钟）
```bash
cd /data/EngineeringFrozen/WasmSentinel
git status                      # 先看 172 个改动是什么
git log origin/main..HEAD       # 看那 2 个 commit
# 要么 push，要么至少 tar 一份 .git 到别的物理盘
tar czf /backup/wasmsentinel-git-$(date +%F).tar.gz .git
```

---

## P1 —— 26G 日志，占整个 Engineering 体积的 62%

```
logs/        26G      ← 项目总 26G 里的全部
evaluation/  498M
wasm-threat-detector/ 32M
其余          <5M
```
26G 的 `logs/` 对一个 201K 行的项目是异常的。先分类：
- **实验证据**（论文表格的来源）→ 压缩 + 留校验和，搬 `/data`，仓里留 MANIFEST
- **运行日志 / 调试输出** → 删，加 `.gitignore`

做完这条，Engineering 从 42G 掉到 16G 左右。不过**注意**：系统盘现在剩 1002G
（你 10-11 那次 Frozen 搬迁已释放约 600G），所以这条的紧迫性是「卫生」而非「救火」。

---

## P2 —— 13 个文件里有 TODO/FIXME/XXX

对一个有论文线的仓，散落的 TODO 的问题不是「没做完」，而是**审稿人或读者
会把它当成代码质量信号**。扫一遍分三类：
- 已经不成立的 → 删
- 真待办 → 挪进 issue 或一份 `ROADMAP.md`
- 「这里有已知局限」→ 这类应该**升级进论文的 limitations 一节**，而不是留在代码注释里

---

## P3 —— 定位：Wasm 供应链安全在 2026 仍然成立，但要说清打的是谁

这个题目没过时（Wasm 在边缘/插件沙箱的部署在涨）。但 README 需要回答：
**威胁模型里的攻击者是谁，能力边界在哪。** 一个「检测 Wasm 威胁」的工具，
如果不划清是防恶意模块、防被污染的工具链、还是防运行时逃逸，就无法被评估。

你在 VerifyAgent 的论文里已经把这件事做对了（P1–P5 五条设计原则 + 明确的
红队向量表）。把同一套结构搬过来。

---

## 不要做的事
- 不要在 P0 做完之前动任何别的东西。
- 不要在 /data 上继续开发；要动它就先拉回 SSD（参考 VerifyAgent 的拉回流程）。
