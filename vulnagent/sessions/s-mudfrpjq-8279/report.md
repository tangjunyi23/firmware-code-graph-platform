# 漏洞挖掘报告

> 会话 `s-mudfrpjq-8279` · 固件任务 `9160aafaa095` · 2026-09-23T02:21:15Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 优先挖预认证 RCE |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 1 / 80 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **中危** | 1 |
| **低危** | 1 |
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

### 漏洞 1：httpd 登录处理存在硬编码凭据前缀旁路（受回环源地址限制）（`F-mudg21iv-008c`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 硬编码凭据 `CWE-798` |
| 危害等级 | **中危**（置信度 0.55） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `?` @ `-` |
| 可达性 | static-only |

**漏洞描述**：httpd 登录处理函数 sub_47B918（@0x47b918）内含一条硬编码凭据旁路分支：当请求参数 Action == "request" 时，取用户传入的 Username（v15），以 v19 = strlen(v15) 作为长度调用 strncmp(v15, "0A2326B60AB94BC", v19)。由于比较长度取自攻击者输入，该判定退化为"用户输入是硬编码常量 0A2326B60AB94BC 的前缀"，例如 Username 传 "0"、"0A"、"0A2326B6" 均可通过。通过后代码不再走常规口令校验，而是直接 read_csman 读取本机管理员凭据（键 65538/66435 等）并调用 sub_424384 生成有效会话、写入会话结构（strcpy(*(v23-27152)+285, v75)），等效于无口令获得管理员会话。\n\n影响限定：该分支外层带有源地址守卫 v74[0] = 2130706433 并比较 dword_4F0154 == 2130706433（127.0.0.1），即仅当请求源地址为本机回环时可用。因此这是"本机/回环可用的硬编码凭据后门"，不是远程预认证 RCE；远程利用需先取得回环源地址（本次未在固件中发现可组合的 SSRF/代理头伪造链）。\n\n同一函数另有常规校验路径做对照（strcasecmp 用户名 + strncmp 口令摘要），说明该硬编码分支是额外的旁路而非主流程。

**漏洞证据**：

1. sub_47B918 @ 0x47b918 伪 C 中的硬编码凭据分支：v19 = strlen(v15); if ( !strncmp(v15, "0A2326B60AB94BC", v19) ) { v74[0] = 2130706433; if ( dword_4F0154 == 2130706433 ) { ... read_csman(...,-2147466621, v73, 512, 4); read_csman(..., 66435, v75, 17, 4); goto LABEL_18; } return -401; }
2. 同一函数中的常规校验路径（对照）：if ( !strcasecmp(v15, v39 + 1) ) { v58 = strlen(v40 + 124); if ( !strncmp(v14, v40 + 124, v58) ) { *(_DWORD *)(v38 - 27148) = 1; ... } }，失败时 syslog(134, "UI login from [%s] failed")
3. strncmp 使用攻击者可控长度 v19 = strlen(用户输入 Username)，使比较退化为"用户输入是硬编码常量的前缀"即可成立（例如 Username 取 "0"、"0A"、"0A2326B6"）
4. GET_FROM_LOCALHOST 守卫：v74[0] = 2130706433 并被声明但后续仅比较 dword_4F0154（客户端源地址），即该分支仅在源地址为 127.0.0.1 时可用，限制了远程可利用性
5. httpd 未鉴权即可到达该登录处理（认证判定位于该函数内部），故属预认证面；但受源地址限制，非远程可用

**调用链**：

```
httpd 登录 CGI → sub_47B918 @0x47b918 登录处理 → strlen(v15) 取用户输入 Username 长度 → strncmp(v15, "0A2326B60AB94BC", v19) 前缀比较 → 校验 dword_4F0154 == 127.0.0.1 (2130706433) → read_csman 取凭据 → sub_424384 生成会话 → strcpy(session+285, v75)
```

**漏洞 PoC**：

```
在本机（或源地址被伪装为 127.0.0.1 的通道）向 httpd 登录接口提交：

POST /login.cgi HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

Username=0A2326B6&LoginPassword=x&Action=login

说明：Username 取硬编码常量前缀即可让 strncmp(v15, "0A2326B60AB94BC", strlen(v15)) 成立（v19 来自用户输入长度），随后进入 v74[0]==dword_4F0154 的回环判定。该 PoC 仅演示凭据判定缺陷，未在模拟环境中完成一次真实认证，故保持 static-only。
```

**修复建议**：1) 删除 sub_47B918 中针对 "0A2326B60AB94BC" 的硬编码凭据分支，改由统一的凭据校验路径与随机出厂密码/首次登录强制改密承担；2) 若该分支为产线/维修用途，应改为编译期开关并在量产固件中移除，而不是运行时后端字符串比较；3) 凭据比较必须使用固定长度比较（对两者取等长哈希后定长比较），杜绝长度由用户输入决定的 strncmp 前缀比较；4) 对回环专用维护接口增加独立鉴权（令牌/双向证书），不要只依赖源地址判定。


### 漏洞 2：httpd 预认证请求行解析存在无长度限制的 sscanf 栈写（未授权路径）（`F-mudg1lg1-1ad7`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 栈缓冲区溢出 `CWE-121` |
| 危害等级 | **低危**（置信度 0.5） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `handleIncoming` @ `0x408a0c` |
| 可达性 | static-only |

**漏洞描述**：httpd 的连接处理函数 handleIncoming（sub_408A0C @ 0x408a0c）在完成任何认证之前解析 HTTP 请求行：先用 strpbrk 截断方法名，再用 sscanf(v10, " %[^ ] HTTP/%d.%*d", v4, &v163) 把 URL 令牌写入栈上缓冲区 v4（位于 $fp+0x18 的低字节处）。该转换符 %[^ ] 没有宽度上限，写入长度完全由客户端 URL 长度决定，属于无界栈写入。\n\n重要限定（决定实际影响）：请求行由 sub_406074(@0x406074) 逐字节读入，其循环内以 (dword_4ED46C - 1) 做硬上限（asm 0x4060ec-0x4060f8 / 0x406180-0x40618c：lw dword_4ED46C; addiu -1; sltu $s1,$t8; beqz -> 停止）。dword_4ED46C 为 httpd 请求缓冲尺寸，配置见 etc/httpd.conf 的 buffer_size=4096，故读入上限约 4095 字节。\n\n帧内距离计算（asm 0x408a0c-0x408a38）：saved $ra 位于 $fp+0x32E4，sscanf 目标起点约 $fp+0x19，距离约 13003 字节；而最大写入仅约 4114 字节，最短缺口约 8889 字节。因此该无界写虽然真实存在且位于预认证路径，但在当前缓冲尺寸下无法触及任何控制流目标（$ra、saved $s0-$s7、v150 请求结构体），不构成可利用的 RCE。\n\n结论：真实缺陷、真实预认证可达，但受读取上限约束，实际影响为内存破坏类缺陷而非可武器化的预认证 RCE。建议按无界格式转换符缺陷修复。

**漏洞证据**：

1. httpd handleIncoming (sub_408A0C @ 0x408a0c) 伪 C：v9 = strpbrk(v4, " \t"); *v9 = 0; strcasecmp(v4,"GET")/"POST"; *v10 = 32; sscanf(v10, " %[^ ] HTTP/%d.%*d", v4, &v163) —— 该调用点在认证判定之前，且 %[^ ] 无宽度修饰符
2. assembly 0x408c2c-0x408c38 确认调用点：li $a1, " %[^ ] HTTP/%d.%*d"; move $a2, $s2; jal sscanf; addiu $a3, $fp, 0x3308+var_34（$v163）
3. 栈帧布局 asm 0x408a0c-0x408a70：addiu $sp,-0x3330；saved $ra 存于 0x3308+var_s24 = $fp+0x32E4；sscanf 目标 v4 = &v149 = $fp+0x19
4. 读取上限 asm 0x4060ec-0x4060f8（明文）与 0x406180-0x40618c（TLS 分支）：lw $t8, dword_4ED46C; addiu $t8,-1; sltu $t8,$s1,$t8; beqz -> 停止读入，即最多 dword_4ED46C-1 字节
5. 配置 etc/httpd.conf 内容为 buffer_size=4096 / thread_num=32 / uir_thread_count=40，故读入上限约 4095 字节
6. 长度校验位置在 sscanf 之后：strlen(v4) 与 dword_4ED46C-100 比较（伪 C 中 "Incoming buf size maybe cause overflow, skip"），无法阻止先发生的无界写
7. fw_request_trace 尝试静态确认动态可达：trace a36c86d9208b (via=stdin) 与既有 trace 2f583960149b (via=net, port 80) 均为 failed，未取得覆盖差分，故本结论保持 static-only

**调用链**：

```
httpd 监听 80/tcp（AS-003 路由：sub_40D690 sys_start_thread accept → sub_408A0C handleIncoming）→ sub_406074 @0x406074 逐字节读取请求行（上限 dword_4ED46C-1）→ strpbrk @0x408bc8 截断方法名 → sscanf(" %[^ ] HTTP/%d.%*d") @0x408c34 无界写入栈缓冲 v4（$fp+0x18/$fp+0x19）
```

**漏洞 PoC**：

```
GET /AAAA...(长度接近 4095 字节的 URL 令牌) HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n

说明：该请求会使 %[^ ] 向栈缓冲 v4 写入整个 URL 令牌（无宽度限制）。但在 buffer_size=4096 的读取上限下，写入仅约 4114 字节，距 saved $ra（$fp+0x32E4，约 13003 字节）尚差约 8889 字节，因此该 PoC 不会造成控制流劫持；它演示的是无界写缺陷本身。若要观察崩溃需 dword_4ED46C 被配置为远大于 13003 的值。

static-only：未取得 qemu 覆盖差分（trace a36c86d9208b / 2f583960149b 均 failed），未做动态崩溃确认。
```

**修复建议**：1) 给格式转换符加宽度上限并把目标缓冲区尺寸传入：sscanf(v10, " %4095[^ ] HTTP/%d.%*d", v4, &v163)，同时确保 v4 目标缓冲不小于该宽度；2) 把"URL 长度 <= dword_4ED46C-100"的现有校验前移到 strpbrk/sscanf 之前，使其真正起到防护作用；3) 更彻底的做法是改用有长度语义的解析（先定位 ' ' 与 CRLF 边界，再按已知长度拷贝），避免使用无界 %[。4) 编译侧启用 -fstack-protector-all 作为纵深防御。

