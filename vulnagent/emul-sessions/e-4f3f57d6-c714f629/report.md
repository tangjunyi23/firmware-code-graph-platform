# 固件模拟会话 e-4f3f57d6-c714f629

- 任务：[模拟请求 emulreq-fda120d447c3-499c]（来自漏洞挖掘 agent，请围绕它的结论搭建环境）
目标：围绕本次挖掘已入库的漏洞发现搭建固件模拟环境，完成关键攻击路径的动态验证：
1) minidlnad UPnP HTTP 请求解析 chunked 传输长度无界 memmove 导致堆缓冲区溢出（预认证）（firmware/binwalk_extracted/firmware.extracted/0/squashfs-root/bin/minidlnad）
目标服务与入口以发现记录为准；探活通过后 publish（编排器复探）。
要求：
0. 全程使用简体中文（含思考过程与最终汇报），禁止整段英文。
1. fw_emul_build 建环境时带 request_id=emulreq-fda120d447c3-499c。
2. 只把上下文里点名的服务和端口拉起来；起不来按 console 诊断-patch-reset 迭代，最多 6 轮。
3. 全部端点 fw_emul_probe 实测通过后 fw_emul_publish（编排器会复探）。
4. 禁止自建任何 web 页面/仪表盘冒充设备；环境只由真实固件进程构成。
- 固件任务：fda120d447c3
- 状态：running

## 环境 emul-fda120d447c3-382a（stopped）
- 服务：[{"name": "minidlnad", "container": "fwgraph-emul-emul-fda120d447c3-382a-minidlnad", "binary_md5": "", "binary_path": "/bin/minidlnad", "argv": ["-d", "-f", "/tmp/minidlna.conf"], "argv0": null, "guest_port": 8200, "host_port": 8200, "status": "ok", "boot_attempts": 1, "ready": "port open"}]
- 复探端点：[]

## 环境 emul-fda120d447c3-2f0d（stopped）
- 服务：[{"name": "minidlnad", "container": "fwgraph-emul-emul-fda120d447c3-2f0d-minidlnad", "binary_md5": "", "binary_path": "/bin/minidlnad", "argv": ["-d", "-f", "/tmp/minidlna.conf"], "argv0": null, "guest_port": 8200, "host_port": 8200, "status": "ok", "boot_attempts": 1, "ready": "port open"}, {"name": "bbx", "container": "fwgraph-emul-emul-fda120d447c3-2f0d-bbx", "binary_md5": "aa3d98e20b0f5904d08b51eed6a9536a", "binary_path": "/bin/busybox", "argv": ["-c", "ls -la /bin/busybox; /bin/busybox --list 2>/dev/null | tr '\\n' ' '"], "argv0": "/bin/busybox", "guest_port": 12345, "host_port": 12345, "status": "degraded", "boot_attempts": 2, "ready": "container exited"}, {"name": "bbxsh", "container": "fwgraph-emul-emul-fda120d447c3-2f0d-bbxsh", "binary_md5": "aa3d98e20b0f5904d08b51eed6a9536a", "bi
- 复探端点：[]

## 环境 emul-fda120d447c3-29c6（stopped）
- 服务：[{"name": "minidlnad", "container": "fwgraph-emul-emul-fda120d447c3-29c6-minidlnad", "binary_md5": "", "binary_path": "/bin/minidlnad", "argv": ["-S"], "argv0": null, "guest_port": 8200, "host_port": 8200, "status": "stopped", "boot_attempts": 1, "ready": "container exited"}]
- 复探端点：[]
