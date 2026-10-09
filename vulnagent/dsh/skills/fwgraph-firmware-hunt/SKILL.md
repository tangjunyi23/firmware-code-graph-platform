---
name: fwgraph-firmware-hunt
description: "Firmware vulnerability hunting against an already-prepared fwgraph job. Use for every mining turn: walk public inputs, attack paths, pseudo-C, and real dynamic traces into a finding with a call chain and PoC. Follow the user's hunt goal; do not narrate pipeline stages."
user-invocable: false
---

# 固件漏洞挖掘方法

用户消息是本次挖掘目标。先服从用户指令，再用下面的方法取证。不要向用户复述本方法。
对用户只说简体中文——包括所有中间过程消息，一条英文都不许出现。
一次最多两个工具，打完必须先用一两句中文向用户交代：刚才做了什么、
结果是什么、接下来要验证什么。长时间连续调用工具而一句话不说是违规。

## 第 0 步：先接经验，再开新账

动手前先做两件十分钟内完成的事，禁止跳过：

1. **查同平台历史**：`fw_findings` 看本 job 已登记的 finding（已证实/已否决
   都要看）；用 bash 检索旧挖掘会话的结论（`grep -l` 于 `~/*/*/sessions/*/workspace/attack-ledger.md`
   与各会话 `report.md` 摘要），同型号/同 httpd 的已知入口、已否决路径
   （空差分记录）直接带入本轮——已证伪的方向禁止重复打。
2. **建攻击链板**：在会话 workspace 写 `attack-ledger.md`（格式见下节），
   把历史结论与用户目标作为首批条目入账。

## 取证顺序

1. 盘点已经准备好的公网输入和攻击面，按用户目标筛选。
2. 沿输入到危险操作读伪代码（必须调用 fw_get_function_source），判断攻击者数据能否到达。
3. 动态验证必须真正跑工具，而且要尽早，不能口头盘点：
   - 识别到首选网络入口的 binary_md5 后立刻 fw_request_trace。网络入口：port + payload/payloads_hex。解析器/CLI/文件：via=stdin 或 input_path=/tmp/…（网络空差分就改走 stdin，不要死磕端口）。再 fw_get_trace 等到结束。
   - fw_list_traces 若为空，只说明还没跑过，不是“找不到动态资源”。
   - 需要时 fw_request_fuzz + fw_get_fuzz_run。要验证一条 PoC 会不会崩，用 fw_qemu_exec（stdin/stdin_hex 或 input_path=/tmp/…）。
   - md5 对不上路径时用 fw_list_binaries（硬链接/符号链接会共用 md5）。
4. 静态判定的最后一公里必须走完：鉴权开关、硬编码表项、动作函数指
   针等在 .data/.rodata 的决定性字节，用 `fw_read_bytes(vaddr=…)` 直读
   原始字节后写进证据——"工具链读不到数据段"不是可接受的结论。
5. 未进代码图的二进制（产线 daemon、被截断预算挤出图谱的 ELF）用
   `fw_decompile_single(path=…)` 单独反编译：先拉函数清单，再按可疑
   函数拉伪 C，配合 `fw_read_bytes` 补数据段证据。不需要、也不允许
   要求重跑全量分析。
6. 沙箱可写文件、用 bash 跑 PoC 草稿。固件进程必须走 fw_request_trace / fw_qemu_exec / fuzz，不要用 bash 假装 qemu。
7. 确认后记录漏洞：必须同时给出调用链（函数名+地址用 →）和可复现 PoC。缺一不可。自然语言用中文。

## 攻击链板（attack-ledger.md，全程维护）

多步利用链（如 外部输入→解析缺陷→凭据/提权）与并行线索全部记在
workspace 的 `attack-ledger.md` 里——上下文被压缩后，它是唯一的推进
状态；**每个 turn 开始必须先重读它再继续**。条目格式：

```
- [L1] <入口/二进制> <怀疑点> —— 状态: <伪代码?trace?字节?poc? 四格>
  依据: <本轮工具结果一句话 + trace_id/finding 引用>
  依赖: <如 L2 需要 L1 的凭据；无则留空>
  否决: <空差分/环境问题的记录：端口+payload+日期，禁止重打>
```

规则：
- 四格状态（伪代码/trace/字节/PoC）每完成一格立即更新；依赖满足的
  下一链步优先推进，不要东一榔头西一棒。
- **否决即封存**：空差分、启动即崩、认证挡死的入口写进否决记录，
  后续 turn 禁止重测（新 payload/新角度除外，须注明）。
- 血缘：finding 入库时在 `record_finding` 的 evidence 里引用链板条目
  编号（如 `attack-ledger L1`），让结论可回溯到派生它的观察。


## 把动态结果留作下一刀

fw_get_trace / fw_list_traces / fw_qemu_exec / fw_get_fuzz_run 返回的 `hunt_next` 是内部指令，必须立刻执行，禁止改写成给用户看的验收报告或 trace 表。

- 非空差分：立刻 `fw_get_function_source(kind=brief)` 读 diff 里的函数（优先 memcpy/strcpy/system/exec）。能到危险操作就 `record_finding`，`reachability=observed`，带上这个 `trace_id`、call_chain、poc。
- 网络空差分：不是漏洞。禁止 `record_finding`，禁止向用户写终态/能力验收。同一 port+payload 不要再打。`via=net` 不要带 `input_path`（会变成 file）。启动未通则只允许空 `fw_qemu_exec` 后再 `fw_request_trace via=net`；否则换入口或等新目标。
- stdin/文件空差分：换更像真实输入的 payload 或换 ELF，最多再跑一次。空差分不是漏洞。
- qemu_exec 启动即崩（没喂 payload / `crash_kind=startup`，含日志 SIGSEGV 后被看门狗 SIGKILL）：环境问题。禁止当漏洞，禁止放弃该 ELF。立刻 `fw_request_trace`（httpd 用 port 80，via=net，不要 input_path）；还崩再换 argv。:80 空差分经常就是服务没起来，先把启动跑通。
- fuzz crash / payload 触发的 `status=crash`：复现后记录，不要只把 crash 贴给用户，也不要换题。
- 不要向用户复述方法、hunt_next、平台修复、能力验收。

## 纪律

- 用户指定的漏洞类型、入口、范围优先；没有指定时再按高分路径与预认证面展开。
- 连通、空差分、socket accept 不是漏洞。
- 可达性只许静态 / 观测到 / 已验证，禁止拔高；后两档必须带真实动态记录（trace_id）。
- 结论必须来自本轮工具结果。没有对应工具输出时，禁止声称已查看 qemu / fuzz / 某函数实现。


## 终局：一次干到底，完成后询问模拟

"建议的下一步/后续可以做/留待模拟环境确认"这类话**禁止出现**——
所有"下一步"都必须由你自己在本轮内执行完：该读的字节读了
（fw_read_bytes）、该补反编译的补了（fw_decompile_single）、该跑的
动态验证跑了（trace/exec/fuzz）、该入库的入了（record_finding）。
每条发现都要走到你当前能力边界内的最后一格，不允许把决定性判定
（如是否预认证）留给"下一步"。

全部闭环后：

1. 调用一次 `fw_offer_emulation`（终局登记，返回收尾指令）。
2. 向用户输出**中文完整总结**：发现清单（等级/可达性/置信）、每条
   的调用链与 PoC、动态验证结果、覆盖盲区的如实披露。总结必须含
   **覆盖度对账表**：对照 `fw_get_identification` 的 IN-xxx 输入全清单，
   逐项标注 已测（证据引用 trace_id/finding）/ 跳过（理由）/ 盲区
   （如实披露）——禁止只报命中的入口，未测入口必须显式记账。
   **总结里不要出现"是否进行固件模拟"之类的询问句**——选择由界面
   上的选项卡片呈现，你只在总结末尾加一句："是否进行固件模拟真实
   测试，请在下方卡片选择。"即可。
3. 然后结束本轮输出，等待用户在卡片上选择。**不要自己调
   fw_emul_request**——用户选择"发起模拟测试"后编排会自动发起模拟
   请求并通知你。

（fw_emul_request / fw_emul_env / fw_emul_send 仅在用户明确要求
立即模拟、或模拟环境已由编排发起后使用。）
