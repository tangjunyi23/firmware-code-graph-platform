# 漏洞挖掘报告

> 会话 `s-mtcpho81-22b3` · 固件任务 `fda120d447c3` · 2026-09-22T08:05:26Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 用户希望挖到：命令注入、内存破坏、认证绕过、任意文件读写、信息泄露、预认证 RCE。前置分析完成后立刻沿高分攻击路径做动静结合挖掘。确认漏洞必须同时给出调用链和可复现 PoC。空差分、连通、启动崩溃不是漏洞。对用户只说简体中文；一次最多两个工具，打完先交代结果。 |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 1 / 80 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **高危** | 1 |
| 合计 | 1 |

## 三、动态验证

- 摘录最近 6 条 trace，其中非空差分 0 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
| `daa1eb773e0d` | ok_empty_diff | `net:90` | 0 | - |
| `ead258596c35` | ok_empty_diff | `net:53` | 0 | - |
| `ebe96e60e581` | ok_empty_diff | `net:80` | 0 | - |
| `a7cdb1f753ce` | ok_empty_diff | `net:80` | 0 | - |
| `4cf87467f890` | ok_empty_diff | `net:80` | 0 | - |
| `5fb6f3470768` | ok_empty_diff | `net:80` | 0 | - |

## 四、漏洞详情

### 漏洞 1：minidlnad UPnP HTTP 请求解析 chunked 传输长度无界 memmove 导致堆缓冲区溢出（预认证）（`F-mtcpruzk-6b35`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | heap-overflow `CWE-122` |
| 危害等级 | **高危**（置信度 0.55） |
| 影响组件 | `firmware/binwalk_extracted/firmware.extracted/0/squashfs-root/bin/minidlnad` |
| 二进制指纹 | `3e3258c907b4b461c90472e1fcd6cddb` |
| 漏洞位置 | `sub_40D1FC` @ `0x40d1fc` |
| 可达性 | static-only |

**漏洞描述**：minidlnad 的 UPnP HTTP 请求解析函数 sub_40D1FC 在处理 Transfer-Encoding: chunked 的请求体时，用 strtol 以十六进制解析攻击者声明的 chunk 长度（写入 a1+112），随后直接执行 memmove(dest, src, a1+112) 并把 dest 累加该长度，全程没有任何对目标缓冲区剩余容量的边界检查。攻击者可声明任意大的 chunk 长度，导致向堆缓冲区越界写入（CWE-122）。该解析逻辑位于 UPnP HTTP 处理链路（Process_upnphttp 接收网络连接后调用），无需认证即可从 LAN 预认证触发。in，固件为 TP-Link Archer C7v2。

**漏洞证据**：

1. sub_40D1FC @ 0x40d1fc (minidlnad md5=3e3258c907b4b461c90472e1fcd6cddb): 当 (a1+116 & 0x100) 标志位(Transfer-Encoding: chunked)置位时: dest = a1+32 + a1+44; 循环: a1+112 = strtol(nptr, &src, 16); 若长度非零则 while(*src!=13||*(src+1)!=10) src++; src+=2; memmove(dest, src, a1+112); dest += a1+112; 无边界校验
2. 调用链: Process_upnphttp(accept) -> sub_40D1FC HTTP 请求解析 -> memmove 无界拷贝
3. qemu 动态验证受环境限制(需真实网卡 IP, 进程在 'No IP address automatically detected' 处 fatal 退出), 故为 static-only

**调用链**：

```
Process_upnphttp(accept) → sub_40D1FC(0x40d1fc, HTTP请求解析) → memmove(dest, src, chunklen) 无界堆拷贝
```

**漏洞 PoC**：

```
POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\nAAAA... AAAA\r\n0\r\n\r\n  (chunk-size=0xffffffff 使 strtol 返回 0xffffffff, memmove 以该长度越界写入)
```

**修复建议**：在 chunked 解码循环中加入目标缓冲区剩余空间校验, 拒绝超过接收缓冲区长度的 chunk 长度; 使用固定上限并校验 a1+112 < (buffer_end - dest)

