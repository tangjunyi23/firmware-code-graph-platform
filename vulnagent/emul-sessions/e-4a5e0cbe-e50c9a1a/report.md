# 固件模拟会话 e-4a5e0cbe-e50c9a1a

- 任务：[模拟请求 emulreq-9160aafaa095-b8bd]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）
目标：围绕本次挖掘已入库的漏洞发现搭建固件模拟环境，完成关键攻击路径的动态验证：
1) httpd 预认证请求行解析存在无长度限制的 sscanf 栈写（未授权路径）（firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd）
2) httpd 登录处理存在硬编码凭据前缀旁路（受回环源地址限制）（firmware/binwalk_extracted/firmware.extracted/0/decrypted.bin.extracted/56CD97/squashfs-root/bin/httpd）
目标服务与入口以发现记录为准；探活通过后 publish（编排器复探）。
要求：
0. 全程使用简体中文（含思考过程与最终汇报），禁止整段英文。
1. fw_emul_build 建环境时带 request_id=emulreq-9160aafaa095-b8bd。
2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-patch-reset 迭代，最多 6 轮。
3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。
4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。
- 固件任务：9160aafaa095
- 状态：running

## 环境 emul-9160aafaa095-82fe（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-82fe-httpd", "binary_md5": "2476b288487c26e69f4656b150a41e38", "binary_path": "/bin/busybox", "argv": ["-c", "mkdir -p /var/tmp /var/run /var/log /var/config /var/storage /var/usb /var/app; mkdir -p /tmp/csman; /usr/sbin/csmanuds > /etc/csmanuds.log 2>&1 & sleep 5; { echo MKDEV; ls -l /dev/null; echo CSMAN_LOG; cat /etc/csmanuds.log; echo LS_TMP_CSMAN; ls -l /tmp/csman; } > /etc/diag24.txt 2>&1; echo start > /etc/httpd_loop.log; while true; do /bin/httpd >> /etc/httpd_loop.log 2>&1; echo \"HTTPD_EXIT=$?\" >> /etc/httpd_loop.log; sleep 1; done & sleep 15; cat /proc/net/tcp > /etc/diag25.txt 2>&1; sleep 86400"], "argv0": "sh", "guest_port": 80, "host_port": 11000, "status": "ok", "boot_attempts": 5, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-1a9b（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-1a9b-httpd", "binary_md5": "", "binary_path": "/bin/busybox", "argv": ["-c", "mkdir -p /var/tmp /var/run /var/log /var/config /var/storage; mkdir -p /tmp/csman; /usr/sbin/csmanuds >/dev/null 2>&1 & sleep 3; echo start > /etc/httpd_loop.log; while true; do /bin/httpd >> /etc/httpd_loop.log 2>&1; echo \"HTTPD_EXIT=$?\" >> /etc/httpd_loop.log; sleep 1; done & sleep 86400"], "argv0": "sh", "guest_port": 80, "host_port": 10080, "status": "ok", "boot_attempts": 22, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-cab5（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-cab5-httpd", "binary_md5": "b18be6d07f1c97903c063686924ed3c7", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "degraded", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]

## 环境 emul-9160aafaa095-272a（stopped）
- 服务：[{"name": "httpd", "container": "fwgraph-emul-emul-9160aafaa095-272a-httpd", "binary_md5": "", "binary_path": "/bin/httpd", "argv": [], "argv0": null, "guest_port": 80, "host_port": 10080, "status": "degraded", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]
