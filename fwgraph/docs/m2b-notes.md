# M2b 探测与结论笔记：静态 stripped 二进制的函数命名恢复（Lumina + FLIRT）

对象样本（均为静态链接、stripped、uClibc 系，BusyBox v1.21.1，2013 年构建）：

- `~/firmware-graph/samples/busybox-mips`：ELF32 BE，**mips1**，o32（flags 0x1007）
- `~/firmware-graph/samples/busybox-armv7l`：ELF32 LE，ARM v7，EABI v4（flags 0x4000002）

基线（IDA 9.1 默认自动分析后）：mips 3305 函数仅 12 个命名（sub_ 3293）；arm 3329 函数 14 个命名（sub_ 3315）。

---

## 1. Lumina：不可用（license 被服务器拒绝），代码路径已预留

探测过程（`fwgraph/scripts/probe_lumina*.py`，结果存 `~/firmware-graph/samples/probe*.json`）：

1. **无 `ida_lumina` 模块**（probe1）：IDA 9.1 的 IDAPython 只有常量暴露——`idc.FUNC_LUMINA`、`idaapi.VDRUN_LUMINA / IDA_DEBUG_LUMINA / COLOR_LUMINA / MERGE_KIND_LUMINA`。没有任何可直接调用的 pull/push Python API。
2. **UI action 在无头模式整体失效**（probe2/3/4）：`ida_kernwin` 里注册了 17 个 `Lumina*` action（`LuminaPullAllMds`、`LuminaPullMd` 等），但 `process_ui_action()` 对**全部** action 返回 false——包括对照组 `About`。这不是 lumina 特有问题，而是 TVHEADLESS/autonomous（`-A`）模式下没有 UI 上下文，action 分发整体不工作。去掉 `-A` 也一样。
3. **唯一可行的无头触发点**：`ida_hexrays.decompile_many(outfile, eas, VDRUN_LUMINA|VDRUN_SILENT|VDRUN_NEWFILE)`（probe5）。批量反编译会触发 Lumina 查询流程，但本机 license 被服务器拒绝——内核日志出现 **`lumina: bad signature`**（`~/firmware-graph/samples/probe5_kernel.log`），0 个函数获得命名（331 个函数的批量反编译，前后 named=12 不变，`FUNC_LUMINA` 标志数=0）。

结论：**Lumina 对该 license 不可用**（服务器端鉴权拒绝，非网络或技术接入问题）。`ida_export.py` 里已预留 `LUMINA_ENABLED=1` 步骤（在 `auto_wait()` 后用 `decompile_many` 全量拉取一次，失败只记录不中断），默认关闭；换用带 Lumina 权限的 license 后将其置 1 即可。

## 2. FLIRT：机制完整跑通，且已在真实样本上命中

### 2.1 工具链位置

IDA 9.1 **自带 FLAIR**，无需单独下载：`/home/tankuku/ida-pro-9.1/tools/flair/`（`pelf`、`sigmake`、`dumpsig`、`pcf`、`plb`、`pmacho`、`zipsig` 等）。sig 安装目录 `<ida>/sig/<proc>/`（`mips`、`arm`、`pc`…）。

### 2.2 应用路径（IDAPython，probe 验证）

- `ida_funcs.plan_to_apply_idasgn("short_name.sig")`（短名，IDA 在 `sig/` 与 `sig/<proc>/` 解析）+ `ida_auto.auto_wait()` 即完成应用；`calc_idasgn_state(i)` 返回 2=IDASGN_APPLIED。
- 返回值是**累计**已排队 sig 数（IDB 会记住历史应用过的 sig，busybox-mips.i64 上调用前已为 2）。
- 探针脚本：`fwgraph/libc-sigs/apply_sig_probe.py`。

### 2.3 签名制作（`fwgraph/libc-sigs/build_sig.sh`）

流程：`funcs.txt`（66 个常用 libc 函数）→ 从 libc.a 提取对应 `.o/.os` → 重打包 `.a` → `pelf` 生成 `.pat` → `sigmake`（冲突自动消解：每组取第一个）→ `.sig` → 安装到 `sig/<proc>/`。三种模式：

| 模式 | 材料 | 结果 |
|---|---|---|
| `toolchain` | Bootlin 2024.05 工具链预建 libc.a（uClibc-ng 1.0.50, gcc 13.3, mips32/armv7） | 对**同工具链产物**命中良好（见 2.4），对真实样本 0 命中 |
| `src` | `build_uclibc.sh` 源码编译 uClibc-ng 1.0.50（mips 强制 `-march=mips1 -mfp32 -mnan=legacy` 匹配样本 ISA） | 对真实样本仍 0 命中 |
| `custom` | 任意预建 libc.a（env `LIBC_A`，可选 `SIG_NAME/SIG_TITLE/TEST_GCC`） | 用于 OpenWrt 12.09 SDK（年代匹配），见 2.5 |

### 2.4 阳性对照（机制证明，同工具链测试二进制）

`build_sig.sh` 顺带用同一工具链编译 `test_program.c` 为静态 stripped 测试二进制，应用 sig：

- mips：219 函数，named 4 → **40**（+36，FUNC_LIB 36）
- arm：271 函数，named 5 → **39**（+34，FUNC_LIB 35）

机制（制作→安装→无头应用→命名）完整可用。

### 2.5 关键发现：真实样本必须"年代匹配"

2013 年的样本（uClibc 0.9.33.x + gcc 4.x 时代产物）与现代 sig（uClibc-ng 1.0.50 + gcc 13.3）**字节级模式完全不同**，即使 ISA 级别对齐（src 模式强制 mips1）也 0 命中。FLIRT 匹配对编译器版本/flags/uClibc 配置高度敏感。

年代匹配来源：**OpenWrt 12.09 (attitude_adjustment, 2013) 官方 SDK**（uClibc 0.9.33.2 + gcc 4.6-linaro），`https://archive.openwrt.org/attitude_adjustment/12.09/`：

- armv7：`omap4/generic` SDK → `toolchain-arm_v7-a_gcc-4.6-linaro_uClibc-0.9.33.2_eabi/lib/libc.a` → `fwgraph_owrt1209_uclibc_arm.sig`（62 模块）
- mips1 BE：⚠️ **事后纠正——au1000 12.09 SDK 实为 mipsel**（`target-mipsel_uClibc-0.9.33.2`），不能做 BE 样本的匹配源；已就地利用产出 `fwgraph_owrt1209_uclibc_mipsel.sig`（mipsel 固件资产）。BE 改用 `ar71xx/generic` SDK（mips32r2 BE，`target-mips_r2_uClibc-0.9.33.2`）→ `fwgraph_owrt1209_uclibc_mipsbe.sig`。12.09 的 BE mips 目标只有 mips32r2 级（ar71xx/malta/lantiq），没有 mips1 BE，严格 ISA 匹配的老 mips1 BE 源仍需 §4 继续找（厂商 SDK/Buildroot 历史链）

### 2.6 真实样本命中结果

| sig | busybox-mips (3305) | busybox-armv7l (3329) |
|---|---|---|
| Bootlin 现代（toolchain 模式） | 0 | 0 |
| uClibc-ng 1.0.50 src 模式（mips1） | 0 | — |
| OpenWrt 12.09 omap4（armv7, 年代匹配） | — | **+2**（strlen 等，14→16） |
| OpenWrt 12.09 au1000（mips1 BE, 年代匹配） | 见 §3 最终数字 | — |

命中率低的残因：样本的精确 gcc 小版本/优化 flags/uClibc 补丁集与 OpenWrt 不完全一致，只有最短小稳定的函数（如 strlen）字节级相同。这正是 FLIRT 的固有特性——实用系统需要**多来源签名库**（见 §4）。

## 3. 最终数字（正式重跑导出，`FLIRT_SIGS=1`）

（见 `~/firmware-graph/samples/export_m2b/{mips,arm}/export_done.json`）

| 指标 | mips 基线 → M2b | arm 基线 → M2b |
|---|---|---|
| 命名函数 | 12 → 18（+6） | 14 → 16（+2） |
| sub_ 残留 | 3293 → 3287 | 3315 → 3313 |

应用的 sig：mips 侧 `fwgraph_owrt1209_uclibc_mipsbe`（ar71xx，mips32r2 BE）等全部 fwgraph_*.sig；arm 侧 `fwgraph_owrt1209_uclibc_arm` + `fwgraph_uclibc_arm`。
mips 样本是 mips1 而 ar71xx sig 是 mips32r2，ISA 差一代仍有 +6 命中（最短小稳定的函数字节级一致）；arm +2。再次验证 §2.5 结论：**FLIRT 命中强依赖"年代 × ISA × 字节序 × 配置"四元匹配**，单点 sig 对老样本收益有限，实用价值在 §4 的多来源矩阵；当前版本的主要命名恢复引擎是 M3 AI 漏斗（同一 busybox job 实证 +447 命名，数量级差异）。

## 4. 后续：全量 libc 签名库建设步骤

1. **按"年代 × ISA × 字节序 × libc 版本"矩阵收集 libc.a**：OpenWrt 各代 SDK（12.09/14.07/15.05…，uClibc 与 musl 时代）、Buildroot 历史工具链、厂商 SDK（Ralink/Realtek/Broadcom）、Bootlin 工具链（现代）。每个 libc.a 直接走 `build_sig.sh <arch> custom`（无需编译）。
2. **扩大函数清单**：`funcs.txt` 从 66 个扩到 uClibc 全导出符号（`ar t libc.a` 全量入档，pelf 一次处理整个 libc.a 亦可——FLIRT 本就支持整库，但全库 sig 需 sigmake 冲突消解策略更谨慎）。
3. **sig 命名/组织**：`fwgraph_<来源>_<libc版本>_<arch>.sig`，统一放 `sig/<proc>/`，`FLIRT_SIGS=1` 自动全量应用；应用成本与 sig 数线性相关，实测单 sig <0.2s，可承受数十个。
4. **效果回归**：以 `export_done.json` 的 `flirt.named_delta` / `naming` 字段为指标，每加一批 sig 在 busybox 双架构上回归。
5. 若换带 Lumina 的 license：置 `LUMINA_ENABLED=1`，一次 `decompile_many` 即可对比 Lumina 与 FLIRT 的覆盖率。

## 5. 使用方式速查

```bash
# 造 sig（VM 上）
cd ~/firmware-graph/fwgraph/libc-sigs
./build_sig.sh mips toolchain                 # Bootlin 现代（教学/对照）
./build_sig.sh mips src                       # uClibc-ng 源码 mips1（需先 build_uclibc.sh mips）
LIBC_A=/path/to/libc.a SIG_NAME=fwgraph_x_mips ./build_sig.sh mips custom

# 导出时应用（编排器 worker 继承 .env 环境，直接生效）
FLIRT_SIGS=1        # 应用 sig/<proc>/ 下全部 fwgraph_*.sig
FLIRT_SIGS=fwgraph_owrt1209_uclibc_arm.sig   # 或指定逗号列表
LUMINA_ENABLED=0    # 本 license 不可用，保持 0
```
