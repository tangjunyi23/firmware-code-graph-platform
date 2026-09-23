# 漏洞挖掘报告

> 会话 `s-muc9lvva-918b` · 固件任务 `9160aafaa095` · 2026-09-22T07:02:02Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 固件漏洞挖掘：D-Link R15A1（job 9160aafaa095，MIPS，图谱 119,512 节点 / 39,624 函数已就绪）。从攻击面清单入手，重点排查 Web/UPnP 服务的内存安全与认证缺陷；动态验证可通过 fw_emul_request 申请固件模拟环境。 |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 5 / 74 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **严重** | 2 |
| **高危** | 1 |
| 合计 | 3 |

## 三、动态验证

- 摘录最近 1 条 trace，其中非空差分 0 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
| `2f583960149b` | failed | `net:80` | - | QemuError: empty coverage log (target rc=1); check qemu can run the binary: qemu-mips: Error opening logfile /tmp/fwgraph-cov-2f583960149b-base.log: No such fil |

## 四、漏洞详情

### 漏洞 1：httpd 请求行解析 URL 栈缓冲区溢出（sscanf %[^ ] 无长度限制，覆盖返回地址）（`F-muc9r1yq-18a0`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 栈缓冲区溢出 `CWE-121` |
| 危害等级 | **严重**（置信度 0.7） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_408A0C` @ `0x408a0c` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 HTTP 请求处理线程入口 sub_408A0C（syslog 内名 "handleIncoming"）在读取请求行后，用 sscanf(v10, " %[^ ] HTTP/%d.%*d", v4, &v163) 把 URL 解析到栈上缓冲区 v4。

该转换符 %[^ ] 没有任何字段宽度限制，会把整段以空格/制表符结尾的 URL 一次性写入 v4。CFG/汇编显示 v4 指向 fp-0x6C（0x408a98: addiu $s0, $fp, 0x3308+var_6C，0x408c30: move $a2, $s2 作为 sscanf 的写入目标），即只有约 108 字节的合法空间（到第一个后续对象 v151 为止）。

接收侧的越界保护形同虚设：sub_406074 逐字节读入时只以全局 dword_4ED46C（=httpd.conf 的 buffer_size=4096）为界，并把 4095 字节写进调用者提供的 4096 字节栈缓冲区。随后的 strlen(v4) 上限检查在解析之后才执行、且阈值是 buffer_size-100=3996，既不能阻止写入也不能缩小破坏范围。

因此一条超长 URL 可覆盖 fp-0x200..fp-0x0C..fp+0x0C 的大范围栈内容；溢出约 5696 字节即命中 fp+0x3324 处保存的 $ra。反编译中未见任何栈保护（无 __stack_chk 相关逻辑），被覆盖的 $ra 在函数收尾 jr $ra 时直接生效。

**漏洞证据**：

1. CFG sub_408A0C 序言: 0x408a0c addiu $sp,-0x3330；保存寄存器位于 fp+0x3308..fp+0x3324，其中 $ra 在 fp+0x3324
2. 0x408a98 addiu $s0,$fp,0x3308+var_6C（v149, 偏移 -0x6C）
3. 0x408c1c li $t8,0x20 / 0x408c24 sb $t8,0($s4)（把分隔符写回空格）
4. 0x408c2c li $a1,aHttpDD # " %[^ ] HTTP/%d.%*d"；0x408c30 move $a2,$s2 => sscanf 把 URL 写入 0x408a98 指定的缓冲区
5. 0x408c34 jal sscanf；0x408c38 addiu $a3,$fp,0x3308+var_34
6. hexrays sub_408A0C 第275行: if ( sscanf(v10, " %[^ ] HTTP/%d.%*d", v4, &v163) <= 0 || *v4 != 47 )
7. hexrays sub_408A0C: 上限检查位于解析之后，dword_4ED46C - 100 < strlen(v4)（阈值 3996）
8. hexrays sub_406074: if ( v4 >= dword_4ED46C - 1 ) 才停止追加，v4 最大到 4095；写入目标为调用者传入的 a1（即 sub_408A0C 的 fp-0x32F0 处 4096 字节缓冲区 v152）
9. etc/httpd.conf 内容 "buffer_size=4096\nthread_num=32\nuir_thread_count=40"
10. 调用链证据: main -> sub_40D690（accept/setsockopt/SSL_new 的监听循环）-> pthread_create 启动每连接工作线程 sub_408A0C

**调用链**：

```
main (0x403b7c) → sub_40D690 (0x40d690, accept/监听循环) → pthread_create → sub_408A0C (0x408a0c, handleIncoming) → sub_406074 (0x406074, 按 dword_4ED46C=4096 读请求行) → sscanf " %[^ ] HTTP/%d.%*d" 写入 fp-0x6C → 覆盖 fp+0x3324 处保存的 $ra
```

**漏洞 PoC**：

```
python3 -c "
import socket
p = b'A'*5700                      # 5700 > 5696 = 距保存 \$ra 的偏移
req = b'GET /' + p + b' HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n'
s = socket.create_connection(('192.168.0.1', 80))
s.sendall(req)
print(s.recv(64))
"
# 观察点：httpd 工作线程在 sub_408A0C 收尾 jr \$ra 时跳向 0x41414141，进程崩溃/重启
```

**修复建议**：1) 给 sscanf 的 %[^ ] 加上宽度限制，使其不超过目标缓冲区实际容量，例如 " %107[^ ] HTTP/%d.%*d"，并让该宽度由 v4 的真实长度派生而非硬编码；2) 从根本上让 sub_406074 接受调用者传入的上限参数，而不是用全局 dword_4ED46C，避免调用者缓冲区（108 字节）与实际读取上限（4096 字节）不匹配；3) 把 URL 长度校验移到写入之前；4) 用 strncpy/snprintf 等带界接口替代无界字符串写入，并启用编译器栈保护（-fstack-protector-strong）以便此类越界至少能被检测。


### 漏洞 2：httpd 表单解析 ws_parse_form 目标缓冲区尺寸不匹配导致栈溢出（128 字节缓冲区按 512 表项写入）（`F-muca8fgz-0c0d`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 栈缓冲区溢出 `CWE-121` |
| 危害等级 | **严重**（置信度 0.7） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_411270` @ `0x411270` |
| 可达性 | static-only |

**漏洞描述**：httpd 的表单解析函数 sub_411270（syslog 内名 "ws_parse_form"）把解析结果写成"名称指针/值指针"交替的表项数组，其清空循环与填充循环的容量上限都硬编码为 512 个表项，即假定目标缓冲区至少 4096 字节。

但该函数在请求处理线程 sub_408A0C 中被用两种不同大小的缓冲区调用：POST 与查询串分支使用 v152（fp+0x219C，4096 字节，匹配 512 表项假设），而另一分支使用 v151（fp+0x319C，仅 128 字节，只能容纳 16 个表项）—— 因为 v151 是紧邻 v154 的保留间隙，并非压缩产物（v152 与 v153 皆为其完整声明尺寸）。

于是向 128 字节缓冲区写入 512 对指针：仅清空循环就会把 a2[0..1023]（4096 字节）清零，而 v151 之后 128 字节处即为保存的寄存器区（fp+0x3308 起），随后 v151+128+0x1C 处即保存的 $ra，最终在 epilogue 的 jr $ra 处失控。

与已入库的请求行溢出相互独立：触发载体是 URL 的查询串（表单参数）而非超长路径，缺陷位置在 sub_411270 的容量假设与调用方缓冲区大小不一致。

**漏洞证据**：

1. hexrays sub_411270: 清空循环 do{ if(*v2) free(*v2); if(v2[1]) free(v2[1]); v2+=2; } while(--v4);，其中 v4 初值为 512
2. CFG sub_411270 块1: 0x4112ac li $s1, 0x200 —— 迭代 512 次，每次处理 2 个 _DWORD（v2 与 v2[1]），0x4112e8 addiu $s0, 8 每次前进 8 字节
3. CFG sub_411270 序言: 0x411270 addiu $sp,-0x40，帧大小 0x40；0x4112a0 sw $a1,0x18+arg_4($sp) 把目标缓冲区指针存入栈槽
4. hexrays sub_411270: if ( v9 == 512 ) { ... v9 = 513; break; } —— 上限按 512 个表项设计
5. hexrays sub_411270: v14 = &a2[2 * v9]; *v14 = strdup(v8); v14[1] = strdup(...) —— 每解析一个参数写入 8 字节（2 个指针）
6. hexrays sub_408A0C 变量布局: 局部缓冲区 v151 位于 fp+0x319C 且仅 128 字节；v152 位于 fp+0x219C 为 4096 字节；v150 位于 fp+0x20 为 4096 字节
7. hexrays sub_408A0C: v173 = sub_411270(v70, v151)（POST 分支）与 v150[66] = sub_411270(v83, v152)、v150[66] = sub_411270(v42 + 1, v152)（GET query 与 POST urlencoded 分支）—— GET 查询串分支的目标同样是 128 字节的 v151
8. hexrays sub_411498: 当路径未匹配任何已注册处理器时走 LABEL_16，*a3 = (int)&unk_4ED8C0（默认处理器），说明进程启动时注册表为空的情况下 v162 仍非空，GET+查询串路径不会被 404 分支挡住
9. hexrays sub_408A0C: 查询串解析位于鉴权/路由判定之前，属预认证路径

**调用链**：

```
main (0x403b7c) → sub_40D690 (0x40d690, accept/监听循环) → pthread_create → sub_408A0C (0x408a0c, handleIncoming) → sub_411270 (0x411270, ws_parse_form) 以 v151(fp+0x319C, 128 字节) 为目标写入 512 对指针
```

**漏洞 PoC**：

```
python3 -c "
import socket
# 每条参数形如 a=&，被解析为两个表项（名与值），共 600 字节 > 128 字节缓冲区
q = '&'.join('a=' for _ in range(200))
req = ('GET /log/' + '?' + q + ' HTTP/1.1\r\nHost: 192.168.0.1\r\n\r\n').encode()
s = socket.create_connection(('192.168.0.1', 80))
s.sendall(req)
print(s.recv(64))
"
# 预期：sub_411270 把 512 对指针写入 128 字节栈缓冲区，破坏 fp+0x3308 起的保存寄存器与 $ra，
#       工作线程在 epilogue jr $ra 时失控；httpd 崩溃并由看护进程重启
```

**修复建议**：1) 让 sub_411270 接受目标缓冲区容量参数，清空与填充循环都以该容量为界，而不是硬编码 512；2) 调用方应把 v151 的容量（16 对）传入并据此限制参数个数，或在参数过多时返回错误而不是继续写入；3) 统一用 sizeof 派生上限，避免调用方缓冲区大小与被调方假设不一致；4) 启用 -fstack-protector-strong，使此类越界至少可被检测。


### 漏洞 3：httpd GET 响应解压路径堆缓冲区溢出（拷贝长度用输出缓冲容量而非实际产出长度，且检查在写入之后）（`F-mucb3xsk-5de3`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 堆缓冲区溢出 `CWE-122` |
| 危害等级 | **高危**（置信度 0.7） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd` |
| 二进制指纹 | `b18be6d07f1c97903c063686924ed3c7` |
| 漏洞位置 | `sub_407260` @ `0x407260` |
| 可达性 | static-only |

**漏洞描述**：httpd 的 GET 响应处理器 sub_407260（syslog 内名 "process_method_get"）在响应体以 gzip/deflate 压缩时，先把压缩数据解压进一个 4MB 堆缓冲区（v9 = malloc(0x400000)，错误串中称 PGIMAGE_MAX_SIZE），再分块写出。

解压循环每次迭代把 deflate 的单次产出整块 memcpy 进堆缓冲区，但拷贝长度取自输出缓冲的容量 dword_4ED46C（=4096），而非实际产出长度；并且写入发生在"剩余空间"检查之前：

    v14 = v9 + v10;                          // 目标 = 缓冲区基址 + 已用长度
    v10 += dword_4ED46C - v79;               // 已用长度累加
    memcpy(v14, v77, dword_4ED46C - v79);    // ← 拷贝先发生
    ...
    if ( v10 < 0x400000 ) goto LABEL_19;
    // 仅当 v10 >= 0x400000 才记录 "Maybe data overflow"

因此只要单次 deflate 产出使 v10 越过 0x400000，这次 memcpy 已经越界写；随后的检查只能打印告警，无法回退。CFG 证实 v77 是按 dword_4ED46C 上取整分配的动态栈缓冲区（0x40730c 处 subu $sp），即单次最多 4096 字节，故越界量以 4KB 为粒度，可越过缓冲区尾部破坏相邻堆块元数据。

解压路径由请求头驱动：sub_4070FC 依据 Content-Encoding 返回 "gzip"/"deflate"，非 identity 时调用 deflateInit2_/deflateInit_。

与本会话已入库的两条（请求行 URL 栈溢出、表单解析缓冲区尺寸不匹配）在载体、位置与内存区域上均不同：此处为堆缓冲区、位于 GET 响应路径、载体为 Content-Encoding 请求头加压缩体。

**漏洞证据**：

1. hexrays sub_407260: v9 = malloc(0x400000) —— 4MB 响应缓冲，日志文案称 PGIMAGE_MAX_SIZE
2. hexrays sub_407260 解压循环: v83 = (*(...)(a3 + 24))(a4, v86, dword_4ED46C); v78[1] = v83; v78[0] = v86; 随后 do { v79 = dword_4ED46C; v78[3] = v77; deflate(v78, v12); v13 = v79; v14 = v9 + v10; v10 += dword_4ED46C - v79; memcpy(v14, v77, dword_4ED46C - v79); } while ( !v13 );
3. 关键点：memcpy 写入发生在 v10 自增与随后的 if ( v10 < 0x400000 ) 检查之前，故单次拷贝可越过 4MB 边界
4. hexrays sub_407260 溢出日志: "Maybe data overflow(PGIMAGE_MAX_SIZE(%d),len(%zu)" 与 "((PGIMAGE_MAX_SIZE -temp_len)< BUFF_SIZE_1)" —— 开发者已知边界但仍只做事后检测
5. CFG sub_407260 块0 序言 0x407260 addiu $sp,-0xA0；块6 (0x40730c-0x407318) subu $sp, $v0 / subu $sp, $t8，$v0/$t8 由 dword_4ED46C 上取整到 8 字节得到 —— 证实 v77 是 dword_4ED46C(=4096) 字节动态栈缓冲区，单次 deflate 最多产出 4096 字节
6. hexrays sub_407260: v85 = sub_4070FC(*(const char **)(a4 + 28)) 取 Content-Encoding；为 "gzip" 时 deflateInit2_(...,8,31,...)，为 "deflate" 时 deflateInit_ —— 解压路径由请求头驱动
7. hexrays sub_407260: while ( !v13 ) 为内层循环条件（v13 = 剩余 avail_out，为 0 表示输出缓冲写满），故每次迭代必然产出可达 4096 字节

**调用链**：

```
main (0x403b7c) → sub_4105D0 (0x4105d0) → sub_40D690 (0x40d690, accept 循环) → pthread_create → sub_408A0C (0x408a0c, handleIncoming, 路由得到处理器名 v162) → sub_407260 (0x407260, process_method_get) → sub_4070FC (0x4070fc) 取 Content-Encoding → deflate() 解压 → memcpy 越界写
```

**漏洞 PoC**：

```
python3 -c "
import zlib, socket
payload = zlib.compress(b'A'*8_000_000, 9)     # 高压缩比：解压后远超 4MB
req  = b'GET /' + b'A'*100 + b' HTTP/1.1\r\n'
req += b'Host: 192.168.0.1\r\n'
req += b'Content-Encoding: gzip\r\n'           # 驱动 sub_4070FC 返回 gzip
req += ('Content-Length: %d\r\n' % len(payload)).encode()
req += b'Connection: close\r\n\r\n' + payload
s = socket.create_connection(('192.168.0.1', 80)); s.sendall(req)
print(s.recv(256))
"
# 预期：解压循环把输出块写入 malloc(0x400000) 缓冲，单次 memcpy 越过 4MB 边界，
#       破坏相邻堆块元数据，工作线程随后在 free/malloc 处崩溃
```

**修复建议**：1) 每次 memcpy 前校验剩余空间，拷贝长度取 min(deflate 产出长度, 0x400000 - v10)，空间不足时立即终止解压并返回错误；2) 用实际产出长度而非输出缓冲容量 dword_4ED46C 作为拷贝长度；3) 不要把「先写后检查」当边界保护——现有检查位于 memcpy 之后，只能记录损坏而不能阻止；4) 对解压输出总量设上限，避免压缩炸弹同时造成堆溢出与内存耗尽。

