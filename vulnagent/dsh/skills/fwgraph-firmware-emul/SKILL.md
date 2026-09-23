---
name: fwgraph-firmware-emul
description: "Firmware emulation against a prepared fwgraph job: build a writable rootfs base, boot real firmware service daemons under qemu-user inside persistent docker containers, diagnose boot failures from console output, patch rootfs (init stubs, nvram config, permissions), and publish a probe-verified environment for downstream mining agents. Use for every emulation turn. Follow the user's or [模拟请求 ...] goal; never fabricate services."
user-invocable: false
---

# 固件模拟方法

用户消息（或 [模拟请求 ...]）是本次模拟目标。先服从指令，再用下面的方法。
对用户只说简体中文。一次最多 3 个工具；每步先用一两句中文交代看到什么。

## 真实性红线

环境里只允许**真实固件进程**。禁止开发任何 web 页面、API mock、仪表盘来
冒充设备或"演示"服务；禁止把自建响应当设备响应。环境是否就绪由编排器
publish 复探说了算——你只能拿真实探活证据说话。

## 流程

1. `fw_emul_build`（模拟请求带 request_id）。arch/机型信息可从任务上下文拿。
2. `fw_emul_binaries` 选服务二进制（httpd/upnpd/telnetd…），`fw_emul_boot`
   拉起：port 必填；argv 按服务的真实用法（`-f`、配置路径）；busybox 多呼叫
   用 argv0。返回里看 ready 与 console。
3. 未就绪：`fw_emul_console` 读输出。常见病与药：
   - 缺共享库 → 换同 rootfs 里的 loader 或 `fw_emul_patch` 补 lib 软链
   - 读 nvram 失败/空指针 → `fw_emul_patch` 写默认配置/init 脚本 stub，
     或直接给 daemon 换不依赖 nvram 的启动参数
   - 权限/只读 → `fw_emul_patch op=chmod mode=0755`
   - fork 后立刻退出 → console 里找 perror 行；argv0/env 不对也会这样
   - 端口起不来 → 换端口或查 /etc/services 冲突
   改完 `fw_emul_reset` 重启，**最多 6 轮**；同一错误两轮没进展必须换思路
   （联网查：`<vendor> nvram keys`、`qemu-user <arch> <daemon>`、机型已知坑）。
4. 就绪判据：`fw_emul_probe` 拿到真实响应（HTTP 有状态行、协议有回包）。
   UDP 服务 probe ok=false 不代表死——用协议真实握手字节再试一次。
5. `fw_emul_publish` 声明端点（只声明实测通过的）；被拒就回 3 继续。
6. 结案中文摘要：跑起来的服务+端口映射+复探证据+没起来的与原因。

## 子代理（≤3 并发，共 ≤12 次）

用来并行：啃 console 日志、联网查机型知识、试备选启动参数。子代理不能再
开子代理。每个子代理带明确的问题清单，回来只收事实，不收建议性空话。

## 磁盘

只写本会话工作区。quota 拒绝时 `fw_emul_stop` 不用的环境或删大文件；
qcow2/日志不要无限增长（console 日志读尾不读全量）。

## csman/MTD 与 SIGBUS 诊断配方（2026-09-23 R15A1 实战沉淀）

D-Link 系（csman 机型）服务链：`csmanuds` 先起 → `httpd` 才不会 rc=255。
csman 配置数据链在固件自己手里，模拟时**必须人工走完**：

1. `rc40/rc50` 语义：`tar zxvf /usr/local/www.tgz -C /tmp/www3` 且
   `cp pre4.dat pre7.dat reset.dat /tmp/csman`——www.tgz 里就带着
   pre*.dat/reset.dat 与 hnap/ 模板。模拟环境先跑这两步再起服务。
2. csmanuds 启动报 `Cannot access MTD device /dev/mtd1|mtd2`、
   `Cannot get MTD information`：**先看它是否仍活着**（很多版本只是
   探测告警、继续用 /tmp/csman 的文件数据）。活着就别管 MTD。
3. 真依赖 MTD（read/ioctl 失败即退出）时，按序尝试：
   a. **等长路径 patch**（首选，参考 bind 0.0.0.0 的等长改法）：把
      csmanuds 里的 `/dev/mtdX` 串改成等长的 `/tmp/mtx` 并预先用
      dd 造好内容文件；ioctl(MEMGETINFO) 仍会失败——若因此退出才走 b。
   b. `sudo apt-get install -y gcc-mips-linux-gnu`（或 mipsel，按端序）
      编译 LD_PRELOAD 垫片：拦截 `/dev/mtd*` 的 open/ioctl/mmap，
      MEMGETINFO 返回伪造 geometry（erasesize 0x20000、size=文件长），
      读写落到宿主 backing 文件。垫片用 `-static` 编不出就 `-shared`。
4. `qemu: uncaught target signal 10 (Bus error)`（SIGBUS）在 qemu-user
   下两大来源：mmap 长度/偏移未页对齐、非自然对齐的原子指令。
   诊断：`qemu-{mips,mipsel} -g 1234` + `gdb-multiarch` 断在信号点，
   或先 `strace -f -e trace=mmap2,ioctl` 看崩溃前最后一个系统调用，
   再定位到 httpd 内函数（与静态调用链对上）。
5. HNAP 状态码语义（D-Link httpd 实测）：`501` = 处理器接管但
   方法/版本/入口形态不符（去比对 /tmp/www3/hnap/ 模板的精确 POST
   形状与 SOAPAction 头）；`404` = 动作不在 HNAP 表（换 action 名）；
   POST 后无响应+console SIGBUS = 分发路径真被触发，按第 4 条定位。
   `/var/config`（UBIFS 分区）若主 rootfs 缺失，先从解包区的
   `ubifs-residual/` 或 `*_ubifs.raw`（ubireader_extract_files）补齐。
