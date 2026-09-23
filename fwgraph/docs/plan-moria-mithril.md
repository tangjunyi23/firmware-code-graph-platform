# 解包链分层强化与语义扫描接入方案（moria + mithril）

> 状态：待实施 ｜ 依赖：无新外部服务 ｜ 改动面：pipeline/extract、sca、vulnlib、vulnagent/dsh/plugin ｜ 预估总量：约 500 行代码 + 构建/部署脚本

## 1. 背景与结论

引入两款 MIT 协议、C++20、零第三方依赖的离线工具，与现有 EMBA 解包链互补而非替代：

- **moria**（结构识别/解包）：41 个进程内 parser，UPX 自解壳（含清零头 stub），squashfs 厂商魔数变体与压缩算法谎言探测，SafeRoot（openat+O_NOFOLLOW）与压缩炸弹防护，`-j` 输出带偏移/类型/置信度的结构树。
- **mithril**（解包产物语义扫描）：secrets（形状→结构→校验和三层阶梯）、SBOM（无包管理元数据时从 ELF 版本横幅/libc 文件名/内核 banner 恢复组件）、CVE（本地 OSV+NVD 镜像，版本区间匹配，KEV/EPSS 标注）、licenses、boot 安全（U-Boot env/FIT/AVB/UEFI）、弱公钥（ROCA/batch-GCD/Fermat/Wiener/已知坏钥匙）。

源码级对比结论（详见评审记录）：EMBA 组合（binwalk v3 + unblob 73 handler + 21 个厂商 P 模块）在**格式覆盖与厂商加密固件**上不可替代，继续任主力；moria 在**单格式解析深度、工程安全、速度、agent 友好度**上占优，定位为快诊与补刀；mithril 补齐平台四块空白（深度密钥扫描、弱公钥、SBOM 版本恢复、启动安全审计）。

## 2. 总体架构

```
固件上传 POST /firmware
   │
   ▼
[fwdecrypt 一层剥壳/加密识别]（现状不动）
   │
   ▼
① moria 快诊（纯识别 -j，秒级）
   · 结构树（偏移/类型/置信度）→ data/extracted/<job>/moria-tree.json
   · UPX 加壳 ELF 清单 → manifest binaries[].packed
   · 加密容器/高熵区提前路由；炸弹/恶意结构在此拦截
   │
   ▼
② EMBA 主解包（extract-only profile，现状不动，权威）
   │
   ▼
③ moria 对账补刀
   · 结构树 vs EMBA 产物 diff → 未解出结构定点 moria -e
     （典型：厂商改魔数 squashfs、声明 gzip 实为 LZMA1）
   · 补刀产物 → data/extracted/<job>/moria_extracted/（source=moria）
   · EMBA 失败/超时 → moria -e 全量降级，job 标记 degraded_unpack
   │
   ▼  rootfs 目录（统一树）
[mithril 语义扫描]（AUTO_SCA 阶段与 Trivy 并行）
   ├─ secrets + 弱公钥 + boot → data/sca/<job>.json 的 mithril 段（认证风险）
   ├─ SBOM → data/sbom/<job>/{sbom.cdx.json, sbom.spdx.json}
   └─ CVE（版本区间+EPSS/KEV）→ vulnlib 入库（source=mithril）
   │
   ▼
挖掘 agent（fw_deep_secrets / fw_weak_keys / fw_structure_tree 工具）
模拟 agent（消费就绪环境做密钥类发现的动态置信度升级）
```

## 3. moria 接入设计

### 3.1 三阶段职责

| 阶段 | 触发 | 动作 | 产物 |
|---|---|---|---|
| ① 快诊 | `_extract_worker` 中 fwdecrypt 成功后 | `moria -j --max-bytes … firmware.bin` | `moria-tree.json`、UPX 清单、加密/高熵提示 |
| ② 主解包 | 现有 EMBA 链 | 不变 | 现有 firmware/ 树 + p99 CSV |
| ③ 对账补刀 | EMBA 完成后 | 树 diff → `moria -e -C` 定点提取；EMBA 失败则全量降级 | `moria_extracted/` + manifest 合并 |

### 3.2 权威与冲突规则

- 文件内容以 EMBA 为准；moria 产物只落 `moria_extracted/`，manifest 合并按 md5 去重，`binaries[].source ∈ {emba, moria}`。
- `packed`（UPX）为显式标记：攻击面/反编译跳过该二进制并在洞察页提示「N 个加壳二进制未覆盖（可 moria 解壳后重跑）」——盲区显式化，不再静默丢失。
- 对账只针对「moria 识别到文件系统/归档、EMBA 未产出对应挂载点」的差异项，避免重复提取已知结构。

### 3.3 实现落点

| 文件 | 改动 |
|---|---|
| `pipeline/extract/moria.py`（新，~150 行） | `identify()`：跑 `-j` 并解析结构树；`extract()`：封装 `-e`（带 --depth/--max-files/--max-bytes 防护参数）；`diff_against()`：树 vs EMBA 产物对账 |
| `orchestrator/app/main.py` `_extract_worker` | 快诊插入（fwdecrypt 后）、对账补刀插入（EMBA 后），各约 20 行，`MORIA_ENABLED` 门控 |
| `orchestrator/app/extractor.py` `build_manifest()` | 合并 packed 标记与 moria 补刀二进制（md5 去重、source 字段） |
| `setup.sh` / 部署 | moria 二进制：优先 vendor 预编译产物，否则 cmake 构建（依赖 zlib/lzma/lz4/zstd 开发库）；`MORIA_BIN` 可覆盖路径 |

### 3.4 配置项

```ini
MORIA_ENABLED=1          # 总开关（0 时完全回退现状链）
MORIA_BIN=               # 二进制路径覆盖
MORIA_MAX_FILES=100000   # 提取文件数上限（防炸）
MORIA_MAX_BYTES=8589934592  # 8GiB 提取字节上限
MORIA_DEPTH=16           # 递归深度
```

### 3.5 验收标准

- ArcherC7 样本：快诊 <2s 出结构树；EMBA 链行为与现状完全一致（MORIA_ENABLED=0 时逐字节等价）。
- 构造样本：改魔数 squashfs（qshs）在 EMBA 拆失败后由补刀阶段解出；UPX 加壳 ELF 在 manifest 带 packed 标记且洞察页可见提示。
- EMBA 人为超时 → 降级解包产出可用 rootfs，job 状态与提示正确。

## 4. mithril 接入设计

### 4.1 扫描封装

`pipeline/mithril.py`（新，~200 行）：

- `run_scan(rootfs, sections)` → `mithril <rootfs> -j [--secrets|--keys|--boot|--sbom|--cve]`，解析 JSON 并归一化（发现项带路径/类型/证据/置信度字段，对齐 evidence.py 的证据锚点格式）。
- 数据库：`MITHRIL_DB=data/mithril-db`；`fetch_db()` 供 admin 维护端点调用（唯一联网点，之后气隙）。
- CVE 段在无数据库时自动跳过（secrets/keys/boot/SBOM 零前置）。

### 4.2 SCA 管线并行（归属①认证风险 + ②SBOM/CVE）

- `_run_analysis` 框架新增分析类型：AUTO_SCA 触发时 Trivy 与 mithril 并行，结果合并进 `data/sca/<job>.json`：
  - `mithril.secrets[]`（以 mithril 为主源，Trivy secret 保留交叉）
  - `mithril.weak_keys[]`（ROCA/共享素数/已知坏钥匙，独立类别「认证凭据风险」）
  - `mithril.boot[]`（启动安全姿势）
  - `components[]` 合并（mithril 恢复的组件补 Trivy 空缺，标 source）
- CVE 入库：`vulnlib.py` 新增 `upsert_mithril_findings()`（仿 `upsert_sca_findings()` :335-377），条目带 epss/kev/version_range 元数据，source=mithril，不覆盖人工条目——N-day 匹配从厂商名启发式升级为版本区间命中。

### 4.3 报告中心

- SBOM 文件落 `data/sbom/<job>/`，`report_export` 增加下载端点（CycloneDX/SPDX）。
- `pipeline/report.py` 增 mithril 段：密钥泄露摘要（脱敏展示）、弱公钥、boot 姿势，确定性中文文案。

### 4.4 挖掘 agent 集成（归属④）

`vulnagent/dsh/plugin/src/index.js` 注册三个只读工具（读 `data/sca` 与 `moria-tree` 已有产物，不现场扫描）：

| 工具 | 数据源 | 返回 |
|---|---|---|
| `fw_deep_secrets` | sca.json mithril.secrets | 泄露密钥/JWT/私钥清单：路径、类型、校验状态 |
| `fw_weak_keys` | sca.json mithril.weak_keys | 弱公钥明细：ROCA 指纹/共享素数/已知坏钥匙 + 影响面 |
| `fw_structure_tree` | moria-tree.json | 未解包结构/加密区域/加壳清单（含置信度） |

挖掘 persona（`cordis.patch.yml`）攻击面清单新增维度：

> 密钥泄露 → 认证绕过/固件伪造；ROCA/共享素数/已知坏钥匙 → 签名伪造/中间人。此类发现为 static-only，置信度锚 ≤0.7；在模拟环境中用该密钥实际完成一次认证或签名验证后方可升级 observed/verified。

——与现有证据纪律、模拟环境闭环（fw_emul_report 通道）天然衔接：静态密钥发现可驱动模拟 agent 拉起对应服务做动态升级。

### 4.5 配置项

```ini
MITHRIL_ENABLED=1
MITHRIL_BIN=
MITHRIL_DB=/var/lib/fwgraph/mithril-db   # CVE 镜像（--fetch-db 下载）
```

### 4.6 验收标准

- ArcherC7 样本：secrets/boot/keys/SBOM 四段无数据库即可出结果；SBOM 组件数 ≥ Trivy 组件数（恢复能力生效）。
- `--fetch-db` 后 CVE 段命中并写入 vulnlib（source=mithril，EPSS/KEV 字段可查）。
- 挖掘会话中 `fw_deep_secrets`/`fw_weak_keys` 可调用且返回结构化结果；构造含 ROCA 弱钥样本 → agent 产出认证类 finding 且置信度 ≤0.7（未动态验证时）。

## 5. 实施计划

| 阶段 | 内容 | 预估 | 依赖 |
|---|---|---|---|
| M1 | moria/mithril 构建接入（vendor + setup.sh） | 0.5 天 | 无 |
| M2 | moria 快诊 + packed 标记 + 洞察页提示 | 1 天 | M1 |
| M3 | moria 对账补刀 + EMBA 降级兜底 | 1 天 | M2 |
| M4 | mithril 扫描封装 + SCA 并行合并（secrets/keys/boot/SBOM） | 1 天 | M1 |
| M5 | CVE 镜像 + vulnlib 入库 + N-day 版本区间 | 0.5 天 | M4 |
| M6 | agent 三工具 + persona + 报告/SBOM 导出 | 1 天 | M4 |
| M7 | 端到端验收（含恶意样本防护、降级链路） | 0.5 天 | 全部 |

## 6. 风险与回退

- **moria 单作者新项目（253★）**：格式库更新与维护存在不确定性 → 全部能力挂 `MORIA_ENABLED`/`MITHRIL_ENABLED` 开关，关闭即逐字节回退现状链；moria 只在快诊/补刀位，不在关键路径。
- **CVE 镜像体积与更新**：`--fetch-db` 一次下载、每周上游重建 → 挂 admin 维护动作，不自动联网；无库时 CVE 段静默跳过。
- **结果冲突**：双源 CVE/组件以 source 字段共存不去重判定，报告层标注来源；文件内容冲突以 EMBA 为权威（3.2 节）。
- **安全**：两个工具均以非 root、限参运行；moria 的防护参数显式传入；扫描输入为不可信固件产物，沿用 sandbox 原则（不新增特权）。
