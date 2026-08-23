---
name: fwgraph-firmware-hunt
description: "Firmware vulnerability hunting against an already-prepared fwgraph job. Use for every mining turn: walk public inputs, attack paths, pseudo-C, and real dynamic traces into a finding with a call chain and PoC. Follow the user's hunt goal; do not narrate pipeline stages."
user-invocable: false
---

# 固件漏洞挖掘方法

用户消息是本次挖掘目标。先服从用户指令，再用下面的方法取证。不要向用户复述本方法。

## 取证顺序

1. 盘点已经准备好的公网输入和攻击面，按用户目标筛选。
2. 沿输入到危险操作读伪代码（必须调用 fw_get_function_source），判断攻击者数据能否到达。
3. 动态验证必须真正跑工具，而且要尽早，不能口头盘点：
   - 识别到首选网络入口的 binary_md5 后立刻 fw_request_trace。网络入口：port + payload/payloads_hex。解析器/CLI/文件：via=stdin 或 input_path=/tmp/…（网络空差分就改走 stdin，不要死磕端口）。再 fw_get_trace 等到结束。
   - fw_list_traces 若为空，只说明还没跑过，不是“找不到动态资源”。
   - 需要时 fw_request_fuzz + fw_get_fuzz_run。要验证一条 PoC 会不会崩，用 fw_qemu_exec（stdin/stdin_hex 或 input_path=/tmp/…）。
   - md5 对不上路径时用 fw_list_binaries（硬链接/符号链接会共用 md5）。
4. 沙箱可写文件、用 bash 跑 PoC 草稿。固件进程必须走 fw_request_trace / fw_qemu_exec / fuzz，不要用 bash 假装 qemu。
5. 确认后记录漏洞：必须同时给出调用链（函数名+地址用 →）和可复现 PoC。缺一不可。自然语言用中文。

## 把动态结果留作下一刀

fw_get_trace / fw_list_traces / fw_qemu_exec / fw_get_fuzz_run 返回的 `hunt_next` 是内部指令，必须立刻执行，禁止改写成给用户看的验收报告或 trace 表。

- 非空差分：立刻 `fw_get_function_source(kind=brief)` 读 diff 里的函数（优先 memcpy/strcpy/system/exec）。能到危险操作就 `record_finding`，`reachability=observed`，带上这个 `trace_id`、call_chain、poc。
- 网络空差分：同一 ELF 改 `via=stdin` 或 `payloads_hex` 再 `fw_request_trace`。
- stdin/文件空差分：换更像真实输入的 payload 或换解析该输入的 ELF，再跑。空差分不是漏洞。
- qemu_exec 启动即崩（没喂 payload / `crash_kind=startup`）：环境问题。禁止当漏洞，禁止放弃该 ELF。立刻 `fw_request_trace`（httpd 用 port 80）；还崩再换 argv。:80 空差分经常就是服务没起来，先把启动跑通。
- fuzz crash / payload 触发的 `status=crash`：复现后记录，不要只把 crash 贴给用户，也不要换题。
- 不要向用户复述方法、hunt_next、平台修复、能力验收。

## 纪律

- 用户指定的漏洞类型、入口、范围优先；没有指定时再按高分路径与预认证面展开。
- 连通、空差分、socket accept 不是漏洞。
- 可达性只许静态 / 观测到 / 已验证，禁止拔高；后两档必须带真实动态记录（trace_id）。
- 结论必须来自本轮工具结果。没有对应工具输出时，禁止声称已查看 qemu / fuzz / 某函数实现。
