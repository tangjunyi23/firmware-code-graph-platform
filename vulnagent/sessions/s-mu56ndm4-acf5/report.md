# 漏洞挖掘报告

> 会话 `s-mu56ndm4-acf5` · 固件任务 `6df0ba4135c9` · 2026-09-17T07:23:44Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 盘点当前固件的公网输入与攻击面清单，只做静态盘点，不要跑动态验证 |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 1 / 40 |

## 二、发现统计

- 本轮没有入库漏洞。空差分、连通、启动崩溃不是漏洞，未做投机记录。

## 三、动态验证

- 摘录最近 24 条 trace，其中非空差分 1 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
| `b005801df6eb` | ok_empty_diff | `net:22` | 0 | - |
| `8c63ea55bc36` | ok_empty_diff | `net:53` | 0 | - |
| `2f710d6679fc` | ok_empty_diff | `net:80` | 0 | - |
| `8776daee6949` | ok_empty_diff | `net:80` | 0 | - |
| `14f10c62246d` | ok_empty_diff | `net:80` | 0 | - |
| `de871d6a4af2` | failed | `net:1701` | - | QemuError: target exited before port 1701 was ready (rc=1) |
| `a45d0aafbb20` | ok_empty_diff | `net:80` | 0 | - |
| `0c8c60f1b2a6` | ok | `stdin` | 11 | - |
| `df1ff2318542` | ok_empty_diff | `stdin` | 0 | - |
| `d8f7a96cc692` | ok_empty_diff | `stdin` | 0 | - |
| `2fc37b2a498d` | ok_empty_diff | `net:80` | 0 | - |
| `1eac263b6bd4` | ok_empty_diff | `net:8200` | 0 | - |
| `bfd4beb3bd62` | ok_empty_diff | `net:21` | 0 | - |
| `d1567f7d0a62` | ok_empty_diff | `net:80` | 0 | - |
| `c4d01f80fa3e` | ok_empty_diff | `net:80` | 0 | - |
| `2ccab5a12559` | failed | `stdin` | - | QemuError: trace worker lost after 192s (orchestrator restart or hung qemu); retry fw_request_trace |
| `bc24dcec32f2` | ok_empty_diff | `stdin` | 0 | - |
| `4ce30998de6e` | ok_empty_diff | `stdin` | 0 | - |
| `418ab2d96eb0` | ok_empty_diff | `net:80` | 0 | - |
| `1e105688dad2` | ok_empty_diff | `net:80` | 0 | - |
| `a9e13ec83d5b` | ok_empty_diff | `file` | 0 | - |
| `7b4e92c8e24d` | ok_empty_diff | `net:445` | 0 | - |
| `4fee31d8b0dc` | ok_empty_diff | `net:51237` | 0 | - |
| `2e531d6df254` | ok_empty_diff | `net:51237` | 0 | - |

## 四、漏洞详情

（无入库条目）
