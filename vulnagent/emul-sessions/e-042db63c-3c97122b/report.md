# 固件模拟会话 e-042db63c-3c97122b

- 任务：[模拟请求 emulreq-6df0ba4135c9-26e1]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）
目标：拉起 /usr/bin/httpd(80) 供动态验证 httpd 栈缓冲区溢出（F-mu6cebwm-c6a9）：ipAddrDispose(0x4b57d0) 对 HTTP 参数 ping_addr 做无界栈写入 char s[52]；请起 httpd 监听 80 并保留 /userRpm/PingIframeRpm.htm 路由可达，供发真实 GET 取证
结构化上下文：{"binaries": ["9582aa23b0bc2de099b9997b09457d01"], "ports": [80], "findings": ["F-mu6cebwm-c6a9"], "paths": ["/usr/bin/httpd"], "seeds": ["GET /userRpm/PingIframeRpm.htm?ping_addr=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&doType=ping&isNew=new&sendNum=1&pSize=64&overTime=1", "GET /"], "notes": "静态结论：sub_42DFC0(0x42dfc0)→httpDispatcher(0x425d08)→sub_48E0F4(0x48e0f4)→httpGetEnv(ping_addr)→ipAddrDispose(0x4b57d0) 越界写 s[52]；需真实 HTTP 响应/崩溃取证"}
要求：
1. fw_emul_build 建环境时带 request_id=emulreq-6df0ba4135c9-26e1。
2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-patch-reset 迭代，最多 6 轮。
3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。
4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。
- 固件任务：6df0ba4135c9
- 状态：done

## 环境 emul-6df0ba4135c9-b6fe（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-6df0ba4135c9-b6fe-httpd", "binary_md5": "", "binary_path": "/usr/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "stopped", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-6df0ba4135c9-7e4f（stopped）
- 服务：[{"name": "diag", "container": "fwgraph-emul-emul-6df0ba4135c9-7e4f-diag", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["-c", "echo '### /'; ls -la /; echo '### /dev'; ls -la /dev; echo '### /var'; ls -la /var; echo '### /tmp'; ls -la /tmp; echo '### mounts'; cat /proc/mounts; echo '### version'; cat /proc/version; echo '### httpd foreground'; /usr/bin/httpd; echo EXIT=$?; echo '### done'; sleep 600"], "argv0": "sh", "guest_port": 80, "host_port": 11000, "status": "stopped", "boot_attempts": 1, "ready": "container exited"}, {"name": "diag2", "container": "fwgraph-emul-emul-6df0ba4135c9-7e4f-diag2", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["-c", "echo retiring-diagnostic-helper"], "argv0": "sh", "guest_port": 80, "host_port": 10080, "status": "stopped", "boot_a
- 复探端点：[]
