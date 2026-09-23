# 固件模拟会话 e-114d3a2f-baabf214

- 任务：[模拟请求 emulreq-9160aafaa095-2033]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）
目标：围绕本次挖掘已入库的漏洞发现搭建固件模拟环境，完成关键攻击路径的动态验证：
1) D-Link R15 httpd HNAP SetDeviceSettings 未授权命令注入（TZLocation 拼入 fota 命令串）（firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd）
2) httpd HNAP Login 硬编码后门用户名 0A2326B60AB94BC 免密登录取会话（限 127.0.0.1 来源）（firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd）
3) httpd SetSysEmailSettings 邮件告警 shell 命令拼接（mailtool -v %s 单引号内注入点）（firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd）
4) httpd 日志格式串明文输出 auth_pass / sess_prikey / dec_pass（firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd）
目标服务与入口以发现记录为准；探活通过后 publish（编排器复探）。
要求：
0. 全程使用简体中文（含思考过程与最终汇报），禁止整段英文。
1. fw_emul_build 建环境时带 request_id=emulreq-9160aafaa095-2033。
2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-patch-reset 迭代，最多 6 轮。
3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。
4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。
- 固件任务：9160aafaa095
- 状态：running

## 环境 emul-9160aafaa095-1d98（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-1d98-httpd", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/run_rce.sh"], "argv0": "sh", "guest_port": 80, "host_port": 11006, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "mibprobe", "container": "fwgraph-emul-emul-9160aafaa095-1d98-mibprobe", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/run_mib.sh"], "argv0": "sh", "guest_port": 80, "host_port": 11007, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "portal", "container": "fwgraph-emul-emul-9160aafaa095-1d98-portal", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/run_portal.sh"], "argv0": "sh", "guest_port": 85, "host_port": 11008, "status": "ok", "boot_att
- 复探端点：[]

## 环境 emul-9160aafaa095-f2d2（stopped）
- 服务：[{"name": "httpd80", "container": "fwgraph-emul-emul-9160aafaa095-f2d2-httpd80", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/run_hnap2.sh"], "argv0": "sh", "guest_port": 80, "host_port": 11001, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "hnaptest", "container": "fwgraph-emul-emul-9160aafaa095-f2d2-hnaptest", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/hnap_probe.sh"], "argv0": "sh", "guest_port": 80, "host_port": 11002, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "portscan", "container": "fwgraph-emul-emul-9160aafaa095-f2d2-portscan", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/port_scan.sh"], "argv0": "sh", "guest_port": 80, "host_port": 11003, "status": "ok
- 复探端点：[]

## 环境 emul-9160aafaa095-0fac（stopped）
- 服务：[{"name": "httpd-probe", "container": "fwgraph-emul-emul-9160aafaa095-0fac-httpd-probe", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/run_httpd_probe.sh"], "argv0": "sh", "guest_port": 80, "host_port": 11001, "status": "stopped", "boot_attempts": 1, "ready": "port open"}, {"name": "diag", "container": "fwgraph-emul-emul-9160aafaa095-0fac-diag", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/diag4.sh"], "argv0": "sh", "guest_port": 80, "host_port": 11002, "status": "stopped", "boot_attempts": 4, "ready": "port open"}, {"name": "diag6", "container": "fwgraph-emul-emul-9160aafaa095-0fac-diag6", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["/etc/scripts/diag6.sh"], "argv0": "sh", "guest_port": 85, "host_port": 10085, "status": "o
- 复探端点：[]

## 环境 emul-9160aafaa095-c909（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-c909-httpd", "binary_md5": "", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 11001, "status": "degraded", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]
