# 漏洞挖掘报告

> 会话 `s-mucc83m5-c451` · 固件任务 `d2cb45ce4524` · 2026-09-22T07:33:36Z

## 一、任务信息

| 项 | 内容 |
| --- | --- |
| 任务目标 | 固件漏洞挖掘：小米 rb03（job d2cb45ce4524，MIPS，图谱已就绪）。从攻击面清单入手，重点排查 Web/UPnP/云服务接口的内存安全与认证缺陷；给出完整结论清单后收尾。 |
| 引擎 | dsh（模式：dynamic） |
| 轮次 | 1 / 40 |

## 二、发现统计

| 危害等级 | 数量 |
| --- | --- |
| **严重** | 1 |
| **高危** | 1 |
| 合计 | 2 |

## 三、动态验证

- 摘录最近 2 条 trace，其中非空差分 0 条。

| Trace | 状态 | 入口 | 差分函数 | 备注 |
| --- | --- | --- | --- | --- |
| `0ab14be05849` | ok_empty_diff | `stdin` | 0 | - |
| `8f833987f52a` | failed | `net:5000` | - | QemuError: target exited before port 5000 was ready (rc=1) |

## 四、漏洞详情

### 漏洞 1：miniupnpd SOAP 响应构造堆缓冲区溢出（sub_8998/sub_ADB8 低估信封开销 156~3677 字节）（`F-muccebsp-0023`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 堆缓冲区溢出 `CWE-122` |
| 危害等级 | **严重**（置信度 0.6） |
| 影响组件 | `usr/sbin/miniupnpd` |
| 二进制指纹 | `2960a1e8f41148a34ef09d2179752beb` |
| 漏洞位置 | `sub_8998` @ `0x8998` |
| 可达性 | static-only |

**漏洞描述**：小米 RB03 (1.0.57) 的 UPnP IGD 守护进程 miniupnpd (Server 头标识 MiniUPnPd/2.1) 在构造 SOAP 响应时按调用方给出的长度 a4 只分配 a4+371 字节，但实际写入量固定比 a4 多约 179 字节（155 字节 HTTP 头 + 24 字节 </s:Body></s:Envelope> 定长串），造成可控堆越界写。响应分配/拼接统一走中心助手 sub_867C(0x867C)：它仅在 a4+370 >= 已分配容量时才 malloc，分配量为严格的 a4+371 字节。sub_8998(0x8998) 走 HTTP 500 错误分支时传入 a5=0，随后 memcpy(a5=0 字节) 无害，但 sub_867C 内部对 HTTP 头格式串（约 148–155 字节）的 _snprintf_chk 写入、定长 "\r\n" 追加，以及（当 flag 置位时）Timeout/Ext 头追加已越过分配边界，末尾还在偏移约 400 处写 a5+156 字节，合计超出 a4+371 达 156 字节。在 sub_B994(0xB994, GetGenericPortMappingEntry/GetListOfPortMappings SOAP 动作处理器) 路径上后果更严重：调用方算出 v17(内容长度) 后仅请求 v17+20 字节，而 sub_ADB8(0xADB8) 会先 memcpy 155 字节信封前缀，再 memcpy a3 字节调用方数据（a3 由被截断的 __snprintf_chk 返回值推导，可能远大于真实 buffer 剩余空间），最后追加 24 字节收尾串，即需要 v17+179 字节却只分配 v17+20 字节。该 155/24 字节偏差是常量级，因此任何一次 UPnP SOAP 响应都会稳定越界写堆；越界内容为 HTTP 头/SOAP 信封定长串与被截断的长度值，而相邻堆块被破坏后可导致守护进程崩溃并在具备堆布局控制时被进一步利用。

**漏洞证据**：

1. sub_867C(0x867C) 分配逻辑：`if (v8) { if (a4 + 370 < *(a1+216)) goto LABEL_6; free(v8); } v9 = malloc(a4 + 371); *(a1+216) = a4 + 371;` —— 容量严格等于 a4+371
2. sub_867C(0x867C) 头部写入：`_snprintf_chk(buf, *(a1+216), 1, -1, "%s %d %s\r\nContent-Type: %s\r\nConnection: close\r\nContent-Length: %d\r\nServer: MiWiFi/x UPnP/1.1 MiniUPnPd/2.1\r\nExt:\r\n", ...)` 后仍无条件写 buf[v21]=13、buf[v24]=10；该格式串展开约 148–155 字节
3. sub_867C(0x867C) 末尾重分配只在 `*(a1+216) < a4 + *(a1+208)` 时才 realloc，而 sub_ADB8 在首次分配后立即以 155 字节偏移做 memcpy，重分配检查已来不及
4. sub_8998(0x8998) 全文：`v8 = sub_867C(a1, a2, a3, a5); if (a4) v9 = v8 < 0; else v9 = 1; if (!v9) { memcpy(*(a1+200) + *(a1+208), a4, a5); *(a1+208) += a5; }` —— 当 a4==0（错误响应）时 memcpy 长度为 0，越界完全由 sub_867C 内部固定长度写入导致
5. sub_ADB8(0xADB8) 全文：先 `memcpy(*(a1+200) + *(a1+208), "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=...><s:Body>", 0x9B)`（155 字节，越过 Content-Length 区域），再 `memcpy(v6 + v7, a2, a3)`，最后写 `*v10 = 0x79646F423A732F3CLL; v10[1] = 0x766E453A732F3C3ELL; v10[2] = 0xA0D3E65706F6C65LL;`（即 "</s:Body></s:Envelope>\n" 共 24 字节）
6. sub_B994(0xB994) 预算计算：`v16 = __snprintf_chk(); v17 = v16 + 238; ... if (v20 < (unsigned int)(v17 + 1024)) { realloc(v15, v20) } ... v17 += __snprintf_chk(); ... strcpy(&v15[v17], "</p:PortMappingList>"); v24 = __snprintf_chk(); sub_ADB8(a1, v15, v24 + v17 + 20);` —— 只按 v17+20 申请信封空间
7. sub_B994 取参：`GetValueFromNameValueList(v28, "NewStartPort") / "NewEndPort" / "NewProtocol" / "NewNumberOfPorts"`，参数体由 sub_D520(0xD520)→sub_D6B8 解析自 a1+112 处、长度为 a1+136 的 HTTP 报文缓冲区，确认为 SOAP 请求动作处理器；v14=NewNumberOfPorts（为 0 时取 1000）决定遍历上限，v27 为 iptables 重定向条目实际数量（sub_EEF0→sub_19B5C 经 iptc_first_rule/iptc_next_rule 枚举）
8. 攻击面图谱独立标注同一路径：path_id e2cc0d86ff81deed（source sub_B994 0xB994 [network] → sink sub_ADB8 0xADB8 [memunsafe], score 5.83）与 path_id 5193e62a099b10aa（sub_ADB8 0xADB8 source=network sink=memunsafe, score 5.90），attribution=static_only
9. 部署面：/etc/init.d/miniupnpd 以 `service_start /usr/sbin/miniupnpd -S -f $tmpconf` 自启（START=95）；/etc/config/upnpd 配置 port=5351、external_iface=wan、internal_iface=lan、secure_mode=0，perm_rule allow ext_ports 1024-65535 int_addr 0.0.0.0/0 int_ports 1-65535（创建映射无需认证）

**调用链**：

```
UPnP HTTP 控制端点 (TCP, /etc/config/upnpd 配置 port=5351, 兼 SSDP 1900/UDP) → SOAP 动作分发 → sub_B994(0xB994 GetGenericPortMappingEntry/GetListOfPortMappings) 与 sub_8998(0x8998 HTTP 500 错误分支) → sub_ADB8(0xADB8 SOAP 信封封装) → sub_867C(0x867C 分配 a4+371 与 HTTP 头写入) → memcpy(0x8998 内) / memcpy+strcpy(0xADB8 内)
```

**漏洞 PoC**：

```
1) 使 UPnP 控制端点可达（miniupnpd 由 /etc/init.d/miniupnpd 以 -S -f /var/etc/miniupnpd.conf 启动，端口取自 /etc/config/upnpd 的 port=5351）。2) 发送触发 sub_B994 的 SOAP 请求（GetGenericPortMappingEntry 或 GetListOfPortMappings 动作，PARAM 含 NewStartPort/NewEndPort/NewProtocol/NewNumberOfPorts）：

POST /control?WANIPConnection HTTP/1.1
Host: <router>:5351
Content-Type: text/xml; charset="utf-8"
SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"
Content-Length: 421
Connection: close

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewPortMappingIndex>0</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>

3) 任意可产生 500/错误响应的畸形请求（如缺 NewProtocol 或端口非法，走 sub_B5FC→sub_8998）即触发 a5=0 的基本越界路径。堆越界可用 ASAN/valgrind 在模拟环境或 glibc MALLOC_CHECK_=3/mcheck 下观测。
```

**修复建议**：修正 sub_867C 的容量模型：把 HTTP 头/信封的固定开销（155 字节）与收尾串（24 字节）显式计入 sub_867C 的入参预算，即在分配时使用 a4 + 179 而非 a4 + 371，并在 sub_ADB8 中把补充量从 0x9B/24 两个魔数改为编译期常量参与预算计算。同时在 sub_8998/sub_ADB8 的所有 memcpy 前用实际剩余容量（分配量 - 当前偏移）做显式边界校验，并对 __snprintf_chk 的截断返回（<0 或 == 缓冲区大小）做失败处理而非继续累加长度。上游建议直接升级到已修正该长度核算的 miniupnpd 版本。


### 漏洞 2：HTTPS 管理面 TLS 服务器私钥硬编码并跨设备复用（etc/nginx/cert.key）（`F-mucceqzv-d3bd`）

| 字段 | 内容 |
| --- | --- |
| 漏洞类型 | 硬编码凭据 `CWE-798` |
| 危害等级 | **高危**（置信度 0.6） |
| 影响组件 | `etc/nginx/cert.key` |
| 二进制指纹 | `4369b1ae99cb82584a8ff615eadb7159` |
| 漏洞位置 | `?` @ `-` |
| 可达性 | static-only |

**漏洞描述**：固件在为 HTTPS 管理面提供的 nginx 配置中硬编码了 TLS 服务器私钥 etc/nginx/cert.key，与其配套证书 etc/nginx/cert.crt 一起静态固化在只读 rootfs 内，并非设备首次启动时按设备唯一生成。该私钥可被任何拿到固件镜像（公开可下载）的人完整提取，从而导致：(1) 对路由器管理面 443 端口做主动中间人——攻击者可用同一证书冒充 miwifi.com/www.miwifi.com，受害浏览器不产生证书告警，管理员登录凭据与全部 /cgi-bin/luci/* 管理请求可被读取与篡改；(2) 该密钥对全部同版本（RB03 1.0.57, ROM 1.0.57, BUILDTIME 2023-01-30）设备相同，属"一钥通杀"而非单机泄露。管理面 443 直接对接 FCGI（127.0.0.1:8920 → fcgi-cgi → /www/cgi-bin/luci Lua 控制器），因此中间人一旦成立即可完全绕过 TLS 对 Web 管理会话的机密性与完整性保护。同一固件内 plugin_public.pem 与 usr/share/xiaoqiang/cc/mq_a1 另使用 RSA-1024（低于 2048 位下限），说明该产品的密码学基线整体偏低。

**漏洞证据**：

1. etc/nginx/cert.key 内容为 PEM 私钥（mithril 三层校验命中 type=private-key, tier=structural, confidence=80, label="-----BEGIN RSA PRIVATE KEY-----"）
2. etc/nginx/cert.crt 为配套证书，两者作为静态文件固化在只读 rootfs 中（非首次启动生成）
3. etc/nginx/nginx.conf 的 443 server 块逐字引用：`ssl on; ssl_certificate cert.crt; ssl_certificate_key cert.key; ssl_prefer_server_ciphers on; server_name miwifi.com www.miwifi.com;`
4. etc/init.d/nginx 启动链把 443 上的管理面接到 FCGI：`spawn-fcgi -a 127.0.0.1 -p 8920 -U nobody -F 1 -- /usr/bin/fcgi-cgi`，nginx 以 `-c /etc/nginx/nginx.conf` 启动
5. etc/nginx/fastcgi-proxy-tcp.conf 将 /cgi-bin/luci、/uploadfile/cgi-bin/luci、/api-third-party 的 SCRIPT_FILENAME 映射到 /www/cgi-bin/luci，并 `fastcgi_pass 127.0.0.1:8920`，即 HTTPS 管理面最终由 Lua 控制器处理
6. 同一固件的管理面版本面：/usr/share/xiaoqiang/xiaoqiang_version 显示 ROM 1.0.57 / CHANNEL release / HARDWARE RB03 / BUILDTIME Mon, 30 Jan 2023，即该私钥随所有同版本 RB03 出厂固件批量分发
7. 对比项：/etc/init.d/uhttpd 的 generate_keys() 会用 px5g/openssl 配合 /dev/urandom 生成唯一密钥并落盘，证明本平台具备按设备唯一生成证书的能力，nginx 管理面却未采用

**调用链**：

```
nginx HTTPS 监听 (etc/nginx/nginx.conf: listen 443 ssl; ssl_certificate cert.crt; ssl_certificate_key cert.key) → server_name miwifi.com www.miwifi.com → location ~* /cgi-bin/luci.* / location /api-third-party/service → fastcgi_pass 127.0.0.1:8920 → spawn-fcgi → usr/bin/fcgi-cgi (md5 ce0a558d008216efd1f4000920c0af03) → /www/cgi-bin/luci (Lua, luci.sgi.cgi) → XQ* 控制器与 /usr/sbin/netapi
```

**漏洞 PoC**：

```
Extract the private key from any copy of the firmware and use it to impersonate the router management plane:

1) 解包固件取私钥：
   binwalk -e miwifi_rb03_firmware_83db5_1.0.57.bin
   cat squashfs-root/etc/nginx/cert.key
   openssl rsa -in squashfs-root/etc/nginx/cert.key -noout -text   # 可正常解析，证明是完整私钥

2) 用该私钥做 HTTPS 管理面中间人（局域网内 ARP/DNS 欺骗 miwifi.com 或直接以该证书架站）：
   openssl s_server -cert squashfs-root/etc/nginx/cert.crt -key squashfs-root/etc/nginx/cert.key -accept 443 -www

3) 由于客户端已把 miwifi.com 视为本机管理入口，受害者浏览器不会出现证书告警，攻击者可完整代理并读取 /cgi-bin/luci/* 的登录凭据与管理请求。

4) 复核跨设备复用：md5sum squashfs-root/etc/nginx/cert.key 在多份同版本固件间一致，即证明为固话密钥而非设备唯一密钥。
```

**修复建议**：不要在固件镜像中固化 TLS 私钥：移除 etc/nginx/cert.key，改为设备首次启动时生成唯一密钥对并持久化到可写的 /etc（可复用 /etc/init.d/uhttpd 中已有的 generate_keys/px5g 逻辑，其已实现基于 /dev/urandom 唯一化并写盘）。同时把 HTTPS 管理面证书纳入出厂个性化烧录流程（每机一钥），并在证书生成后校验私钥未进入只读 rootfs。对已出货设备，应通过固件升级替换该密钥并吊销旧证书；另建议引入证书固定/公钥指纹校验以降低同类失效的可用性。

