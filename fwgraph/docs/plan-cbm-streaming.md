# CBM 图谱索引内存治本方案（排期）

状态：设计定稿，未排期实施。前置缓解已交付（见下）。

## 问题

CBM `index_repository` 的并行提取阶段把每个文件的提取结果
（`result_cache`：defs / string refs / AST 衍生数据，`pass_parallel.c`）
**全程常驻内存**，RSS 随 corpus 线性增长：

- daemon 内存背压只能回收瞬态工作集，对常驻集无效
  （`mem.backpressure.futile → soft_overshoot`），超硬限后 worker 被 SIGKILL。
- worker 预算 = 聚合预算 ÷ worker 数（实测 1592MB/4 = 398MB/worker）；
  调大预算受物理内存约束，线性增长下无解。
- 实测边界（2026-09-21，6.2Gi VM）：
  - 成功最大样本 TP-Link C7V2：39,609 文件 / 48.6MB corpus；
  - 失败样本 D-Link R15A1：121,432 文件 / 129.9MB corpus，
    worker RSS 在 3.9% 进度即触 398MB 软上限，5.6% 进度被杀
    （`data/extracted/9160aafaa095`，worker 日志
    `~/.cache/codebase-memory-mcp/logs/.worker-log-*`）。
- 文件数与字节数均非精确内存代理（B/file 差异小，规模才是主因）。

## 已交付的前置缓解（fwgraph 侧保险丝）

`pipeline/graph/ingest.py`：

- `CBM_TREE_MAX_FILES`（默认 40000）/ `CBM_TREE_MAX_BYTES`（默认 45MB）
  双预算，按「网络服务名（`_SERVICE_HINTS`）→ 普通程序 → lib*」tier
  + 可反编译函数数降序贪心纳入，binary 粒度保持子图完整；
- 截断事实记入 `stats["truncated"]` → `graph_done.json` 与
  `GET /jobs/{id}/graph` 的 `summary.warnings`/`summary.truncated`；
- R15A1 实测：385 binaries/121,432 文件 → 87 binaries/40,000 文件
  （83 个网络服务 binary 全保留）。

## 治本方案（CBM 侧，~/src/codebase-memory-mcp）

目标：索引内存与 corpus 规模解耦（有界），任何规模不再 SIGKILL。

1. **提取结果分批落盘**：`pass_parallel.c` 中 worker 完成文件后，
   `CBMFileResult` 批量序列化进 store（SQLite 批量事务；每 ~2,000 文件
   或 arena 阈值触发 flush），`result_cache` 只保留有界滑动窗口。
2. **跨文件 LSP 按需读回**：`pass_lsp_cross` 需要的源文本改为从 store
   读回（`retain_sources` 的 49MB 上限改为 spill-to-disk 队列，语义不变）。
3. **基准与回归**：
   - a) OOM 复现基准（121k corpus 脚本，RSS 曲线记录）；
   - b) flush 通道 + 单测（含 crash/hang quarantine 路径）；
   - c) soak（复用现有 soak30-linux 框架）；
   - d) 重建二进制 → 重新 vendor → fwgraph 六固件回归。

## 风险

- mimalloc/slab 跨线程释放语义（历史 #773：parser 必须由创建它的
  allocator 释放，切换 ts allocator 前需销毁线程 parser）；
- SQLite 批量写放大（WAL + synchronous 配置需基准）；
- worker→daemon 结果回传路径（`application.c` job 编排）改动面大，
  需保持 `index_repository` CLI 契约不变。

## 完成后

fwgraph 侧截断保险丝保留为纯保护，默认值可放宽
（如 `CBM_TREE_MAX_FILES=200000`）或改为按空闲内存探测。
