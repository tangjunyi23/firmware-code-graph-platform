# ArcherC7v2_en_us_3_15_4_up(260427).bin 综合安全分析报告

## 一、执行摘要

本报告针对固件 ArcherC7v2_en_us_3_15_4_up(260427).bin（任务 6df0ba4135c9，状态 routed，分析时间 2026-08-21T08:57:06.722366+00:00）。固件包含 133 个二进制，识别出 25 个公网输入、0 个攻击面、0 条授权链、50 条攻击路径；AI 挖掘发现 0 个（无）。最高风险点为攻击路径 ff_udp_set_remote_url @ 0x7590c → ff_udp_set_remote_url @ 0x7590c（score 6.05）。

## 二、固件清单统计

提取文件 1091 个，其中可执行二进制 133 个。

| 架构 | 二进制数 |
| --- | --- |
| mips | 133 |

文件类型分布：可执行程序 46 个，共享库 87 个。

### 二进制加固（checksec）汇总

共 133 个二进制参与 checksec 检测：

| 防护项 | 开启 | 未开启 |
| --- | --- | --- |
| NX（堆栈不可执行） | 0 | 133 |
| Stack Canary | 0 | 133 |
| PIE（地址无关） | 87 | 46 |
| RELRO（完全） | 4 | 129 |
| RELRO（部分） | 0 | 133 |
| FORTIFY_SOURCE | 0 | 133 |

## 三、外部输入识别

| ID | 服务 | 协议 | 地址:端口 | 输入类型 | 处理链库 |
| --- | --- | --- | --- | --- | --- |
| IN-001 | athadhoc | udp | None:None | UDP datagram payload | libm.so.0, libgcc_s.so.1, libc.so.0 |
| IN-002 | athadhoc_0_elf.raw | udp | None:None | UDP datagram payload | libm.so.0, libgcc_s.so.1, libc.so.0 |
| IN-003 | bpalogin | udp | None:None | UDP datagram payload | libnsl.so.0, libmsglog.so, libgcc_s.so.1, libc.so.0 |
| IN-004 | bpalogin_0_elf.raw | udp | None:None | UDP datagram payload | libnsl.so.0, libmsglog.so, libgcc_s.so.1, libc.so.0 |
| IN-005 | busybox_0_elf.raw | udp | None:None | UDP datagram payload | libmsglog.so, libcrypt.so.0, libgcc_s.so.1, libc.so.0 |
| IN-006 | dhcp6c | tcp | None:None | TCP request payload | libmsglog.so, libgcc_s.so.1, libc.so.0 |
| IN-007 | dhcp6c_0_elf.raw | tcp | None:None | TCP request payload | libmsglog.so, libgcc_s.so.1, libc.so.0 |
| IN-008 | dhcp6s | tcp | None:None | TCP request payload | libmsglog.so, libgcc_s.so.1, libc.so.0 |
| IN-009 | dhcp6s_0_elf.raw | tcp | None:None | TCP request payload | libmsglog.so, libgcc_s.so.1, libc.so.0 |
| IN-010 | dnsproxy | udp | None:None | UDP datagram payload | libgcc_s.so.1, libc.so.0 |
| IN-011 | dnsproxy_0_elf.raw | udp | None:None | UDP datagram payload | libgcc_s.so.1, libc.so.0 |
| IN-012 | dropbearkey | tcp | None:None | TCP request payload | libcrypt.so.0, libutil.so.0, libgcc_s.so.1, libc.so.0 |
| IN-013 | ip_0_elf.raw | udp | None:None | UDP datagram payload | libresolv.so.0, libdl.so.0, libgcc_s.so.1, libc.so.0 |
| IN-014 | ipcserver | tcp | None:None | TCP request payload | libgcc_s.so.1, libc.so.0 |
| IN-015 | ipcserver_0_elf.raw | tcp | None:None | TCP request payload | libgcc_s.so.1, libc.so.0 |
| IN-016 | minidlnad | tcp | None:None | TCP request payload | libjpeg.so.9, libid3tag.so.0, libsqlite3.so.0, libavformat.so.54, libavutil.so.51, libexif.so.12, libiconv.so.2, libFLAC.so.8, libogg.so.0, libvorbis.so.0, libtiff.so.5, libpthread.so.0, libgcc_s.so.1, libc.so.0 |
| IN-017 | scp | tcp | None:None | TCP request payload | libcrypt.so.0, libutil.so.0, libgcc_s.so.1, libc.so.0 |
| IN-018 | smbpasswd | tcp | None:None | TCP request payload | librt.so.0, libcrypt.so.0, libresolv.so.0, libdl.so.0, libgcc_s.so.1, libc.so.0 |
| IN-019 | tc_0_elf.raw | udp | None:None | UDP datagram payload | libresolv.so.0, libm.so.0, libdl.so.0, libgcc_s.so.1, libc.so.0 |
| IN-020 | uclited | tcp | None:None | TCP request payload | libpthread.so.0, libc.so.0, librt.so.0, libmsglog.so, libutil.so.0, libdl.so.0, libm.so.0, libgcc_s.so.1 |
| IN-021 | uclited_0_elf.raw | tcp | None:None | TCP request payload | libpthread.so.0, libc.so.0, librt.so.0, libmsglog.so, libutil.so.0, libdl.so.0, libm.so.0, libgcc_s.so.1 |
| IN-022 | vsftpd | ftp | None:21 | FTP commands (USER/PASS/RETR/STOR/...); file paths; PASV/PORT data connection | libcrypt.so.0, libdl.so.0, libnsl.so.0, libresolv.so.0, libutil.so.0, libgcc_s.so.1, libc.so.0 |
| IN-023 | dropbear | ssh | None:22 | SSH handshake/KEX; auth credentials; SSH channel requests (exec/sftp/port-forward) | libcrypt.so.0, libutil.so.0, libgcc_s.so.1, libc.so.0 |
| IN-024 | httpd | http | None:80 | URL path; query string parameters; HTTP headers; cookies; POST body; multipart form data | libpthread.so.0, libc.so.0, librt.so.0, libmsglog.so, libutil.so.0, libwpa_ctrl.so, libgcc_s.so.1 |
| IN-025 | samba_multicall | SMB/CIFS | None:445 | SMB2/SMB3 requests (negotiate/session/tree/IOCTL); SMB1AndX commands; named pipe RPC (srvsvc/wkssvc); file paths and ACLs | librt.so.0, libcrypt.so.0, libresolv.so.0, libdl.so.0, libgcc_s.so.1, libc.so.0 |

**IN-005（busybox_0_elf.raw）分发链：**

- login：executable path referenced in busybox_0_elf.raw strings (spawn/exec candidate)
- reboot：executable path referenced in busybox_0_elf.raw strings (spawn/exec candidate)
- umount：executable path referenced in busybox_0_elf.raw strings (spawn/exec candidate)
- init：executable path referenced in busybox_0_elf.raw strings (spawn/exec candidate)
- sh：executable path referenced in busybox_0_elf.raw strings (spawn/exec candidate)

**IN-012（dropbearkey）分发链：**

- sh：executable path referenced in dropbearkey strings (spawn/exec candidate)

**IN-017（scp）分发链：**

- sh：executable path referenced in scp strings (spawn/exec candidate)

**IN-018（smbpasswd）分发链：**

- argv[0] multicall dispatch → samba_multicall：smbpasswd is a symlink to usr/sbin/samba_multicall; applet selected via argv[0]
- sh：executable path referenced in smbpasswd strings (spawn/exec candidate)
- false：executable path referenced in smbpasswd strings (spawn/exec candidate)

**IN-020（uclited）分发链：**

- dnsproxy：executable path referenced in uclited strings (spawn/exec candidate)
- udhcpd：executable path referenced in uclited strings (spawn/exec candidate)
- udhcpc：executable path referenced in uclited strings (spawn/exec candidate)
- sh：executable path referenced in uclited strings (spawn/exec candidate)
- dhcp6s：executable path referenced in uclited strings (spawn/exec candidate)
- dhcp6ctl：executable path referenced in uclited strings (spawn/exec candidate)
- radvd：executable path referenced in uclited strings (spawn/exec candidate)
- tphotplug：executable path referenced in uclited strings (spawn/exec candidate)

**IN-021（uclited_0_elf.raw）分发链：**

- dnsproxy：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)
- udhcpd：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)
- udhcpc：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)
- sh：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)
- dhcp6s：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)
- dhcp6ctl：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)
- radvd：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)
- tphotplug：executable path referenced in uclited_0_elf.raw strings (spawn/exec candidate)

**IN-023（dropbear）分发链：**

- sh：executable path referenced in dropbear strings (spawn/exec candidate)

**IN-024（httpd）分发链：**

- lld2d：executable path referenced in httpd strings (spawn/exec candidate)
- dnsproxy：executable path referenced in httpd strings (spawn/exec candidate)
- dhcp6ctl：executable path referenced in httpd strings (spawn/exec candidate)
- sh：executable path referenced in httpd strings (spawn/exec candidate)
- udhcpd：executable path referenced in httpd strings (spawn/exec candidate)
- udhcpc：executable path referenced in httpd strings (spawn/exec candidate)
- dhcp6c：executable path referenced in httpd strings (spawn/exec candidate)
- dhcp6s：executable path referenced in httpd strings (spawn/exec candidate)

**IN-025（samba_multicall）分发链：**

- sh：executable path referenced in samba_multicall strings (spawn/exec candidate)
- false：executable path referenced in samba_multicall strings (spawn/exec candidate)

excluded（非公网面，31 个）；unreadable（0 个）。明细见附录。

## 四、攻击面详情

（无数据）

## 五、攻击路径 Top20

候选路径 5000 条，source 874 个，sink 3597 个；以下按 score 排序取前 20 条。

| # | score | 二进制 | source | sink | 危险操作 | 路径经过函数 | 可达性 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 6.05 | libavformat.so.54.6.100 | ff_udp_set_remote_url @ 0x7590c | ff_udp_set_remote_url @ 0x7590c | memunsafe | - | 静态 |
| 2 | 6.05 | libavformat.so.54.6.100 | udp_open @ 0x75b20 | udp_open @ 0x75b20 | memunsafe | - | 静态 |
| 3 | 6.05 | libavformat.so.54.6.100 | ff_rtsp_connect @ 0x6d968 | ff_rtsp_connect @ 0x6d968 | memunsafe | - | 静态 |
| 4 | 6.05 | xl2tpd | network_thread @ 0x4114d0 | network_thread @ 0x4114d0 | memunsafe | - | 静态 |
| 5 | 6.0 | xl2tpd | sub_403AF8 @ 0x403af8 | sub_403AF8 @ 0x403af8 | memunsafe | - | 静态 |
| 6 | 5.98 | dhcp6ctl | main @ 0x40190c | sub_4010F0 @ 0x4010f0 | memunsafe | main @ 0x40190c → sub_4010F0 @ 0x4010f0 | 静态 |
| 7 | 5.98 | dhcp6ctl | main @ 0x40190c | sub_400C40 @ 0x400c40 | memunsafe | main @ 0x40190c → sub_400C40 @ 0x400c40 | 静态 |
| 8 | 5.98 | libavformat.so.54.6.100 | udp_open @ 0x75b20 | ff_udp_set_remote_url @ 0x7590c | memunsafe | udp_open @ 0x75b20 → ff_udp_set_remote_url @ 0x7590c | 静态 |
| 9 | 5.98 | libavformat.so.54.6.100 | ff_rtsp_connect @ 0x6d968 | ff_http_init_auth_state @ 0x23a0c | memunsafe | ff_rtsp_connect @ 0x6d968 → ff_http_init_auth_state @ 0x23a0c | 静态 |
| 10 | 5.98 | libavformat.so.54.6.100 | ff_rtsp_connect @ 0x6d968 | ffurl_alloc @ 0x15abc | memunsafe | ff_rtsp_connect @ 0x6d968 → ffurl_alloc @ 0x15abc | 静态 |
| 11 | 5.98 | xl2tpd | network_thread @ 0x4114d0 | do_control @ 0x4041b4 | memunsafe | network_thread @ 0x4114d0 → do_control @ 0x4041b4 | 静态 |
| 12 | 5.98 | xl2tpd | network_thread @ 0x4114d0 | get_call @ 0x40f9e8 | memunsafe | network_thread @ 0x4114d0 → get_call @ 0x40f9e8 | 静态 |
| 13 | 5.93 | xl2tpd | sub_403AF8 @ 0x403af8 | get_call @ 0x40f9e8 | memunsafe | sub_403AF8 @ 0x403af8 → get_call @ 0x40f9e8 | 静态 |
| 14 | 5.91 | dhcp6ctl | main @ 0x40190c | base64_decodestring @ 0x401f50 | memunsafe | main @ 0x40190c → sub_400C40 @ 0x400c40 → base64_decodestring @ 0x401f50 | 静态 |
| 15 | 5.91 | xl2tpd | network_thread @ 0x4114d0 | sub_403668 @ 0x403668 | memunsafe | network_thread @ 0x4114d0 → do_control @ 0x4041b4 → sub_403668 @ 0x403668 | 静态 |
| 16 | 5.91 | xl2tpd | network_thread @ 0x4114d0 | sub_403124 @ 0x403124 | memunsafe | network_thread @ 0x4114d0 → do_control @ 0x4041b4 → sub_403124 @ 0x403124 | 静态 |
| 17 | 5.91 | xl2tpd | network_thread @ 0x4114d0 | sub_403AF8 @ 0x403af8 | memunsafe | network_thread @ 0x4114d0 → do_control @ 0x4041b4 → sub_403AF8 @ 0x403af8 | 静态 |
| 18 | 5.91 | xl2tpd | network_thread @ 0x4114d0 | sub_403520 @ 0x403520 | memunsafe | network_thread @ 0x4114d0 → do_control @ 0x4041b4 → sub_403520 @ 0x403520 | 静态 |
| 19 | 5.85 | libavformat.so.54.6.100 | get_sockaddr @ 0x6aa5c | get_sockaddr @ 0x6aa5c | memunsafe | - | 静态 |
| 20 | 5.84 | xl2tpd | network_thread @ 0x4114d0 | get_call @ 0x40f9e8 | memunsafe | network_thread @ 0x4114d0 → do_control @ 0x4041b4 → sub_403AF8 @ 0x403af8 → get_call @ 0x40f9e8 | 静态 |

## 六、动态分析结果

（无数据）

## 七、AI 挖掘发现

（无数据）

## 八、结论与加固建议

1. 攻击路径分析显示外部输入可直达危险 sink，建议在解析层与危险函数调用前统一加长度/格式校验，并对命令执行类 sink 改用参数化接口。
2. 编译加固不足：133/133 个二进制未启用 Stack Canary，46/133 个未启用 PIE；建议统一开启 NX/ASLR/Stack Canary/RELRO 编译选项后重新构建固件。

## 九、附录

- 分析工具链：EMBA（固件提取）、IDA Pro（反编译/调用图）、CBM（代码索引）、AFL++ QEMU（模糊测试）、frida（动态插桩）、dsh vulnagent（AI 漏洞挖掘）
- AI 模型：deepseek-v4-flash
- 报告生成方式：确定性规则汇总（未调用 LLM）
- 报告生成时间:2026-08-21T08:58:27.570131+00:00
- 平台：FWGraph 固件安全分析平台

### 输入识别 excluded/unreadable 明细

- EXCLUDED(not-promoted): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/syslogd (syslog: busybox applet 'syslogd' is a client/non-listen…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd (802.11: infrastructure/control daemon — not part of the p…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_0_elf.raw (802.11: infrastructure/control daemon — not par…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_564706_copyright.raw (802.11: infrastructure/control daemo…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_564772_unknown.raw (802.11: infrastructure/control daemon …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_664448_aes_forward_table.raw (802.11: infrastructure/contr…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_665472_aes_reverse_table.raw (802.11: infrastructure/contr…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_666496_aes_sbox.raw (802.11: infrastructure/control daemon…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_666752_aes_rcon.raw (802.11: infrastructure/control daemon…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_666800_sha256.raw (802.11: infrastructure/control daemon —…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/hostapd_666816_unknown.raw (802.11: infrastructure/control daemon …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant (802.11: infrastructure/control daemon — not part o…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_0_elf.raw (802.11: infrastructure/control daemon — …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_546144_aes_forward_table.raw (802.11: infrastructur…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_547168_aes_reverse_table.raw (802.11: infrastructur…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_548192_aes_sbox.raw (802.11: infrastructure/control…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_548448_aes_rcon.raw (802.11: infrastructure/control…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_548464_sha256.raw (802.11: infrastructure/control d…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_548480_unknown.raw (802.11: infrastructure/control …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_563654_copyright.raw (802.11: infrastructure/contro…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_563719_unknown.raw (802.11: infrastructure/control …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_564092_copyright.raw (802.11: infrastructure/contro…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_564381_unknown.raw (802.11: infrastructure/control …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_564427_copyright.raw (802.11: infrastructure/contro…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/sbin/wpa_supplicant_564874_unknown.raw (802.11: infrastructure/control …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/sbin/pppd (pptp/ppp: infrastructure/control daemon — not part of th…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/sbin/pppd_0_elf.raw (pptp/ppp: infrastructure/control daemon — not …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/sbin/xl2tpd (l2tp: infrastructure/control daemon — not part of the …
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/sbin/xl2tpd_0_elf.raw (l2tp: infrastructure/control daemon — not pa…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/sbin/xl2tpd_100733_copyright.raw (l2tp: infrastructure/control daem…
- EXCLUDED(not-public): firmware/binwalk_extracted/firmware.extracted/100000/squashfs-root/usr/sbin/xl2tpd_100766_unknown.raw (l2tp: infrastructure/control daemon…
