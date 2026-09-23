# 固件模拟会话 e-397912f8-8766dbf2

- 任务：[模拟请求 emulreq-9160aafaa095-77f1]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）
目标：在固件模拟环境中启动 Web 管理服务（httpd）并完成探活与发布验证
要求：
0. 全程使用简体中文（含思考过程与最终汇报），禁止整段英文。
1. fw_emul_build 建环境时带 request_id=emulreq-9160aafaa095-77f1。
2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-patch-reset 迭代，最多 6 轮。
3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。
4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。
- 固件任务：9160aafaa095
- 状态：running

## 环境 emul-9160aafaa095-1807（stopped）
- 服务：[{"name": "init", "container": "fwgraph-emul-emul-9160aafaa095-1807-init", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["init"], "argv0": null, "guest_port": 8190, "host_port": 11003, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "keepalive", "container": "fwgraph-emul-emul-9160aafaa095-1807-keepalive", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "printf '::respawn:/etc/prep_httpd.sh\\n' > /etc/inittab; init"], "argv0": null, "guest_port": 8190, "host_port": 11000, "status": "stopped", "boot_attempts": 2, "ready": "container exited"}, {"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-1807-httpd", "binary_md5": "", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": 
- 复探端点：[]

## 环境 emul-9160aafaa095-e154（stopped）
- 服务：[{"name": "keepalive", "container": "fwgraph-emul-emul-9160aafaa095-e154-keepalive", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["init"], "argv0": null, "guest_port": 8190, "host_port": 11001, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "initsvc", "container": "fwgraph-emul-emul-9160aafaa095-e154-initsvc", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "cp /etc/inittab.new /etc/inittab; /bin/busybox init >> /etc/init.log 2>&1 & sleep 25; echo probe-done >> /etc/init.log; cat /etc/prep.log >> /etc/init.log 2>&1; ps | grep -E 'httpd|init' >> /etc/init.log 2>&1; echo TAIL >> /etc/init.log"], "argv0": null, "guest_port": 8191, "host_port": 8191, "status": "stopped", "boot_attempts": 1, "ready": "port open"}, {"name": "init", "contain
- 复探端点：[]

## 环境 emul-9160aafaa095-2155（stopped）
- 服务：[{"name": "init", "container": "fwgraph-emul-emul-9160aafaa095-2155-init", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["init"], "argv0": null, "guest_port": 8190, "host_port": 8190, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-2155-httpd", "binary_md5": "", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "degraded", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-f53b（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-f53b-httpd", "binary_md5": "b18be6d07f1c97903c063686924ed3c7", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "degraded", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-2212（stopped）
- 服务：[{"name": "keepalive", "container": "fwgraph-emul-emul-9160aafaa095-2212-keepalive", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sleep", "900"], "argv0": null, "guest_port": 8194, "host_port": 11000, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "str", "container": "fwgraph-emul-emul-9160aafaa095-2212-str", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "strings /bin/httpd > /etc/s.txt 2>&1; wc -l /etc/s.txt >> /etc/s.txt"], "argv0": null, "guest_port": 8195, "host_port": 8195, "status": "stopped", "boot_attempts": 1, "ready": "container exited"}, {"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-2212-httpd", "binary_md5": "b18be6d07f1c97903c063686924ed3c7", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "gue
- 复探端点：[]

## 环境 emul-9160aafaa095-7f3e（stopped）
- 服务：[{"name": "keepalive", "container": "fwgraph-emul-emul-9160aafaa095-7f3e-keepalive", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sleep", "900"], "argv0": null, "guest_port": 8194, "host_port": 8194, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "diag", "container": "fwgraph-emul-emul-9160aafaa095-7f3e-diag", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "echo begin > /etc/diag.txt; ls -l /lib >> /etc/diag.txt 2>&1; echo '--httpd--' >> /etc/diag.txt; /bin/httpd >> /etc/diag.txt 2>&1; echo exit=$? >> /etc/diag.txt; echo end >> /etc/diag.txt"], "argv0": null, "guest_port": 8195, "host_port": 8195, "status": "stopped", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-0dde（stopped）
- 服务：[{"name": "diag", "container": "fwgraph-emul-emul-9160aafaa095-0dde-diag", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sh", "-c", "mkdir -p /tmp/www3 /var/config /var/run; ls -l /lib/ | head -20 > /var/diag.txt 2>&1; echo '--- httpd run ---' >> /var/diag.txt; /bin/httpd -p 8080 >> /var/diag.txt 2>&1; echo \"exit=$?\" >> /var/diag.txt"], "argv0": null, "guest_port": 8195, "host_port": 8195, "status": "degraded", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-b673（stopped）
- 服务：[{"name": "keepalive", "container": "fwgraph-emul-emul-9160aafaa095-b673-keepalive", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sleep", "900"], "argv0": null, "guest_port": 8197, "host_port": 8197, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "telnetd", "container": "fwgraph-emul-emul-9160aafaa095-b673-telnetd", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["telnetd", "-F", "-p", "2323", "-l", "/bin/sh"], "argv0": null, "guest_port": 2323, "host_port": 2323, "status": "stopped", "boot_attempts": 1, "ready": "port open"}, {"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-b673-httpd", "binary_md5": "b18be6d07f1c97903c063686924ed3c7", "binary_path": "/bin/httpd", "argv": ["-d", "-p", "8080", "-h", "/etc"], "argv0": null, "guest_p
- 复探端点：[]

## 环境 emul-9160aafaa095-4d98（stopped）
- 服务：[{"name": "bbsleep", "container": "fwgraph-emul-emul-9160aafaa095-4d98-bbsleep", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["sleep", "600"], "argv0": null, "guest_port": 8199, "host_port": 8199, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "bb-list", "container": "fwgraph-emul-emul-9160aafaa095-4d98-bb-list", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["--list"], "argv0": null, "guest_port": 8198, "host_port": 8198, "status": "stopped", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-6c57（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-6c57-httpd", "binary_md5": "b18be6d07f1c97903c063686924ed3c7", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "ok", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-d08a（stopped）
- 服务：[{"name": "bbhttpd", "container": "fwgraph-emul-emul-9160aafaa095-d08a-bbhttpd", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["httpd", "-p", "8181", "-h", "/etc"], "argv0": null, "guest_port": 8181, "host_port": 8181, "status": "ok", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-59e5（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-59e5-httpd", "binary_md5": "b18be6d07f1c97903c063686924ed3c7", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "degraded", "boot_attempts": 4, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-467b（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-467b-httpd", "binary_md5": "b18be6d07f1c97903c063686924ed3c7", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "degraded", "boot_attempts": 4, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-4604（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-4604-httpd", "binary_md5": "", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "degraded", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]
