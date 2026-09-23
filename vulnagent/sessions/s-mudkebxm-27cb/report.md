# 漏洞挖掘报告

> 会话 `s-mudkebxm-27cb` · 固件任务 `9160aafaa095` · 2026-09-23T03:59:17Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 挖掘未授权RCE |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 1 / 80 |

## 二、发现统计

- 本轮没有入库漏洞。空差分、连通、启动崩溃不是漏洞，未做投机记录。

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

（无入库条目）
