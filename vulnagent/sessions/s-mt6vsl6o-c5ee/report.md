# 漏洞挖掘报告

## 一、任务信息

- 会话：s-mt6vsl6o-c5ee
- 任务：开始挖掘
- 引擎：dsh（模式：dynamic）
- 固件任务：6df0ba4135c9
- 轮次：1/80
- 报告时间：2026-08-24T08:04:46Z

## 二、发现统计

- 本轮没有入库漏洞。空差分、连通、启动崩溃不是漏洞，未做投机记录。

## 三、动态验证

- 摘录最近 24 条 trace，其中非空差分 1 条。

- `b005801df6eb` ok_empty_diff via=net:22 差分函数 0
- `8c63ea55bc36` ok_empty_diff via=net:53 差分函数 0
- `2f710d6679fc` ok_empty_diff via=net:80 差分函数 0
- `8776daee6949` ok_empty_diff via=net:80 差分函数 0
- `14f10c62246d` ok_empty_diff via=net:80 差分函数 0
- `de871d6a4af2` failed via=net:1701 差分函数 - — QemuError: target exited before port 1701 was ready (rc=1)
- `a45d0aafbb20` ok_empty_diff via=net:80 差分函数 0
- `0c8c60f1b2a6` ok via=stdin 差分函数 11
- `df1ff2318542` ok_empty_diff via=stdin 差分函数 0
- `d8f7a96cc692` ok_empty_diff via=stdin 差分函数 0
- `2fc37b2a498d` ok_empty_diff via=net:80 差分函数 0
- `1eac263b6bd4` ok_empty_diff via=net:8200 差分函数 0
- `bfd4beb3bd62` ok_empty_diff via=net:21 差分函数 0
- `d1567f7d0a62` ok_empty_diff via=net:80 差分函数 0
- `c4d01f80fa3e` ok_empty_diff via=net:80 差分函数 0
- `2ccab5a12559` failed via=stdin 差分函数 - — QemuError: trace worker lost after 192s (orchestrator restart or hung qemu); retry fw_request_trace
- `bc24dcec32f2` ok_empty_diff via=stdin 差分函数 0
- `4ce30998de6e` ok_empty_diff via=stdin 差分函数 0
- `418ab2d96eb0` ok_empty_diff via=net:80 差分函数 0
- `1e105688dad2` ok_empty_diff via=net:80 差分函数 0
- `a9e13ec83d5b` ok_empty_diff via=file 差分函数 0
- `7b4e92c8e24d` ok_empty_diff via=net:445 差分函数 0
- `4fee31d8b0dc` ok_empty_diff via=net:51237 差分函数 0
- `2e531d6df254` ok_empty_diff via=net:51237 差分函数 0

## 四、漏洞详情

（无入库条目）
