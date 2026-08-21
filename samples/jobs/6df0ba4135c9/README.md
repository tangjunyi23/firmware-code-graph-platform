# Archer C7 分析快照（job `6df0ba4135c9`）

固件：`ArcherC7v2_en_us_3_15_4_up(260427).bin`

本目录只收录可分享的摘要，不含解包 rootfs、IDA 数据库、逐函数伪代码（合计约 4GB）。

| 文件 | 说明 |
|---|---|
| `job.json` | 任务状态 |
| `decompile_summary.json` | rootfs_elf 反编译统计（64 ELF） |
| `symbols_index.json` | 各二进制函数数量（无伪代码正文） |
| `graph_done.json` | 图谱摄入完成标记 |
| `graphext_done.json` | CFG/AST 扩展完成标记 |
| `attack_paths.json` / `attack_done.json` / `ai_review.json` | 攻击路径与分诊 |
| `routes_done.json` | 路由扫描结果 |
| `job-6df0ba4135c9.md` | 中文综合报告 |

反编译导出器：`rootfs_elf`。挖矿引擎：DeepSeek Harness（dsh）。
