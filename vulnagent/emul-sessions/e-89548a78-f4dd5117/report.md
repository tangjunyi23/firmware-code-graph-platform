# 固件模拟会话 e-89548a78-f4dd5117

- 任务：[模拟请求 emulreq-60ca28d897cf-667d]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）
目标：围绕本次挖掘已入库的漏洞发现搭建固件模拟环境，完成关键攻击路径的动态验证：
1) httpd 预认证路径穿越任意文件读取（/help/ URL 经 httpRpmFsA 无 ".." 检查直读）（firmware/binwalk_extracted/firmware.extracted/0/squashfs-root/usr/bin/httpd）
2) httpd 预认证 Host 头堆溢出（LoginRpmHtm→getWholeHostAddr 无界 sprintf 进 0x800 堆块）（firmware/binwalk_extracted/firmware.extracted/0/squashfs-root/usr/bin/httpd）
目标服务与入口以发现记录为准；探活通过后 publish（编排器复探）。
要求：
0. 全程使用简体中文（含思考过程与最终汇报），禁止整段英文。
1. fw_emul_build 建环境时带 request_id=emulreq-60ca28d897cf-667d。
2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-patch-reset 迭代，最多 6 轮。
3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。
4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。
- 固件任务：60ca28d897cf
- 状态：error

## 环境 emul-60ca28d897cf-4191（stopped）
- 服务：[{"name": "uclited", "container": "fwgraph-emul-emul-60ca28d897cf-4191-uclited", "binary_md5": "d61e67ed20163b7fee8bd3c606fb0331", "binary_path": "/usr/bin/uclited", "argv": [], "argv0": null, "guest_port": 9997, "host_port": 9997, "status": "ok", "boot_attempts": 4, "ready": "port open"}, {"name": "httpd", "container": "fwgraph-emul-emul-60ca28d897cf-4191-httpd", "binary_md5": "9582aa23b0bc2de099b9997b09457d01", "binary_path": "/usr/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "ok", "boot_attempts": 3, "ready": "port open"}, {"name": "runner", "container": "fwgraph-emul-emul-60ca28d897cf-4191-runner", "binary_md5": "aa3d98e20b0f5904d08b51eed6a9536a", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "busybox sh /tmp/run.sh"], "argv0": null, "gue
- 复探端点：[]

## 环境 emul-60ca28d897cf-08a7（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-60ca28d897cf-08a7-httpd", "binary_md5": "", "binary_path": "/usr/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "stopped", "boot_attempts": 2, "ready": "port open"}, {"name": "runner", "container": "fwgraph-emul-emul-60ca28d897cf-08a7-runner", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "busybox sh /tmp/run.sh"], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "ok", "boot_attempts": 8, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-60ca28d897cf-1f93（stopped）
- 服务：[{"name": "strings-httpd", "container": "fwgraph-emul-emul-60ca28d897cf-1f93-strings-httpd", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "strings /usr/bin/httpd > /tmp/httpd.strings 2>/dev/null; [ -s /tmp/httpd.strings ] || grep -a -o '[ -~]\\{4,\\}' /usr/bin/httpd > /tmp/httpd.strings; grep -i -E 'version|mtd|flash|csman|pre4|www|\\.dat|\\.tgz|/dev/|/etc/|/tmp/' /tmp/httpd.strings > /tmp/httpd.grep 2>&1; wc -l /tmp/httpd.grep"], "argv0": null, "guest_port": 9998, "host_port": 9998, "status": "ok", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-60ca28d897cf-9ef5（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-60ca28d897cf-9ef5-httpd", "binary_md5": "", "binary_path": "/usr/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "stopped", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]
