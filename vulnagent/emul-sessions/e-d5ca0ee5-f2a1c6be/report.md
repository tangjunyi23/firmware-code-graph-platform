# 固件模拟会话 e-d5ca0ee5-f2a1c6be

- 任务：[模拟请求 emulreq-d2cb45ce4524-6a21]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）
目标：围绕本次挖掘已入库的漏洞发现搭建固件模拟环境，完成关键攻击路径的动态验证：
1) miniupnpd SOAP 响应构造堆缓冲区溢出（sub_8998/sub_ADB8 低估信封开销 156~3677 字节）（usr/sbin/miniupnpd）
2) HTTPS 管理面 TLS 服务器私钥硬编码并跨设备复用（etc/nginx/cert.key）（etc/nginx/cert.key）
目标服务与入口以发现记录为准；探活通过后 publish（编排器复探）。
要求：
0. 全程使用简体中文（含思考过程与最终汇报），禁止整段英文。
1. fw_emul_build 建环境时带 request_id=emulreq-d2cb45ce4524-6a21。
2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-patch-reset 迭代，最多 6 轮。
3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。
4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。
- 固件任务：d2cb45ce4524
- 状态：running

## 环境 emul-d2cb45ce4524-d7fd（stopped）
- 服务：[{"name": "nginx", "container": "fwgraph-emul-emul-d2cb45ce4524-d7fd-nginx", "binary_md5": "4369b1ae99cb82584a8ff615eadb7159", "binary_path": "/usr/sbin/nginx", "argv": ["-p", "/etc/nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"], "argv0": null, "guest_port": 443, "host_port": 10443, "status": "degraded", "boot_attempts": 4, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-d2cb45ce4524-2928（stopped）
- 服务：[{"name": "nginx", "container": "fwgraph-emul-emul-d2cb45ce4524-2928-nginx", "binary_md5": "", "binary_path": "/usr/sbin/nginx", "argv": ["-p", "/etc/nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"], "argv0": null, "guest_port": 443, "host_port": 10443, "status": "ok", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]
