"""Tests for pipeline.inputs (external-input identification, M6a)."""

import json
from pathlib import Path

from pipeline.inputs import discover, runner, services


def _mk_rootfs(tmp_path: Path) -> Path:
    root = tmp_path / "rootfs"
    (root / "etc/lighttpd").mkdir(parents=True)
    (root / "etc/init.d").mkdir(parents=True)
    (root / "etc/ssh").mkdir(parents=True)
    (root / "usr/sbin").mkdir(parents=True)
    (root / "sbin").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir(parents=True)
    return root


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_lighttpd_config_drives_port(tmp_path):
    root = _mk_rootfs(tmp_path)
    _write(root / "etc/lighttpd/lighttpd.conf",
           'server.port = 8080\nserver.bind = "0.0.0.0"\n')
    _write(root / "etc/init.d/S50lighttpd",
           '#!/bin/sh\n/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf\n')
    _write(root / "usr/sbin/lighttpd", "\x7fELF fake")
    cands = discover.discover(root)
    by_name = {c.name: c for c in cands}
    assert "lighttpd" in by_name
    c = by_name["lighttpd"]
    assert c.port == 8080
    assert c.address == "0.0.0.0"
    assert c.autostart
    # port parsed from the config -> highest evidence grade
    assert c.port_source == "observed"
    assert c.evidence_grade == "observed"
    assert not c.needs_confirmation


def test_kb_default_grading_and_null_address(tmp_path):
    # binary present, no config/startup evidence -> kb_default, no invented
    # 0.0.0.0 bind address, needs_confirmation set
    root = _mk_rootfs(tmp_path)
    _write(root / "usr/sbin/vsftpd", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    errors, _ = runner.validate(doc)
    assert errors == []
    assert len(doc["inputs"]) == 1
    ent = doc["inputs"][0]
    assert ent["evidence_grade"] == "kb_default"
    assert ent["port_source"] == "default"
    assert ent["needs_confirmation"] is True
    assert ent["address"] is None
    assert ent["autostart"] is False


def test_loopback_bind_excluded_by_gate1(tmp_path):
    root = _mk_rootfs(tmp_path)
    _write(root / "etc/ssh/sshd_config",
           "Port 22\nListenAddress 127.0.0.1\n")
    _write(root / "usr/sbin/sshd", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    assert doc["inputs"] == []
    assert any("sshd" in e for e in doc["metadata"]["excluded"])
    assert runner.validate(doc) == ([], [])


def test_loopback_only_and_infra_services_excluded(tmp_path):
    root = _mk_rootfs(tmp_path)
    for name in ("redis-server", "hostapd", "openvpn"):
        _write(root / f"usr/sbin/{name}", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    excluded = " ".join(doc["metadata"]["excluded"])
    assert "redis-server" in excluded      # loopback_only
    assert "hostapd" in excluded           # not_public (Wi-Fi AP)
    assert "openvpn" in excluded           # not_public (VPN server)
    assert doc["inputs"] == []
    assert runner.validate(doc) == ([], [])


def test_public_input_schema_complete(tmp_path):
    root = _mk_rootfs(tmp_path)
    _write(root / "etc/vsftpd.conf", "listen=YES\nanonymous_enable=YES\n")
    _write(root / "etc/init.d/S60vsftpd", "#!/bin/sh\n/usr/sbin/vsftpd &\n")
    _write(root / "usr/sbin/vsftpd", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    errors, _ = runner.validate(doc)
    assert errors == []
    assert len(doc["inputs"]) == 1
    ent = doc["inputs"][0]
    assert ent["id"] == "IN-001"
    assert ent["port"] == 21 and ent["transport"] == "tcp"
    assert ent["public"] is True
    # init.d start + config present but no port directive -> config grade,
    # no bind directive -> address stays null
    assert ent["address"] is None
    assert ent["evidence_grade"] == "config"
    assert ent["autostart"] is True
    assert any("anonymous_enable=YES" in p for p in ent["auth_posture"])
    assert ent["entry_files"] == ["usr/sbin/vsftpd"]
    assert ent["processing_chain"][0]["file"] == "usr/sbin/vsftpd"
    assert "libs" in ent["processing_chain"][0]
    assert "FTP" in " ".join(ent["input_types"])
    assert ent["evidence"]


def test_config_disabled_cancels_candidate(tmp_path):
    root = _mk_rootfs(tmp_path)
    _write(root / "etc/vsftpd.conf", "listen=NO\n")
    _write(root / "etc/init.d/S60vsftpd", "#!/bin/sh\n/usr/sbin/vsftpd &\n")
    _write(root / "usr/sbin/vsftpd", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    assert doc["inputs"] == []
    assert any("vsftpd" in e and "disabled" in e
               for e in doc["metadata"]["excluded"])
    assert runner.validate(doc) == ([], [])


def test_unknown_daemon_without_socket_evidence_excluded_not_dropped(tmp_path):
    # gate 2: a referenced daemon that cannot be promoted must appear in
    # excluded with a machine reason, never vanish silently
    root = _mk_rootfs(tmp_path)
    _write(root / "etc/init.d/S99foo", "#!/bin/sh\n/usr/sbin/food --daemon\n")
    _write(root / "usr/sbin/food", "plain text, not an ELF")
    cands = discover.discover(root)
    food = [c for c in cands if c.name == "food"]
    assert food and food[0].drop_reason
    doc = runner.build_document(root, target="t")
    assert doc["inputs"] == []
    assert any("food" in e for e in doc["metadata"]["excluded"])
    assert runner.validate(doc) == ([], [])


def test_inetd_and_xinetd(tmp_path):
    root = _mk_rootfs(tmp_path)
    _write(root / "etc/inetd.conf",
           "telnet stream tcp nowait root /usr/sbin/telnetd telnetd\n")
    _write(root / "usr/sbin/telnetd", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    errors, _ = runner.validate(doc)
    assert errors == []
    assert any(e["service"] == "telnetd" and e["port"] == 23
               and e["autostart"] is True
               for e in doc["inputs"])


def test_xinetd_disable_cancels(tmp_path):
    root = _mk_rootfs(tmp_path)
    _write(root / "etc/xinetd.d/telnet",
           "service telnet\n{\n\tserver = /usr/sbin/telnetd\n"
           "\tdisable = yes\n}\n")
    _write(root / "usr/sbin/telnetd", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    assert all(e["service"] != "telnetd" for e in doc["inputs"])
    assert any("telnetd" in e and "disabled" in e
               for e in doc["metadata"]["excluded"])


def test_initd_merges_all_etc_variants(tmp_path):
    # first-match on etc/init.d must not hide etc_ro/init.d (router
    # firmwares keep the real rcS there)
    root = _mk_rootfs(tmp_path)
    (root / "etc_ro/init.d").mkdir(parents=True)
    _write(root / "etc/init.d/S50vsftpd", "#!/bin/sh\n/usr/sbin/vsftpd &\n")
    _write(root / "etc_ro/init.d/S51dnsmasq", "#!/bin/sh\n/bin/dnsmasq &\n")
    _write(root / "usr/sbin/vsftpd", "\x7fELF fake")
    _write(root / "bin/dnsmasq", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    services_seen = {e["service"] for e in doc["inputs"]}
    assert {"vsftpd", "dnsmasq"} <= services_seen
    dns = next(e for e in doc["inputs"] if e["service"] == "dnsmasq")
    assert dns["autostart"] is True


def test_inittab_sysinit_and_script_recursion(tmp_path):
    # inittab sysinit -> rcS -> helper script -> bare daemon name + explicit
    # listen address (the MX12 dnrd_monitor.sh pattern)
    root = _mk_rootfs(tmp_path)
    _write(root / "etc_ro/inittab", "::sysinit:/etc_ro/init.d/rcS\n"
                                    "ttyAMA0::respawn:/sbin/sulogin\n")
    _write(root / "etc_ro/init.d/rcS",
           "#!/bin/sh\n/usr/sbin/config_script/dnrd_monitor.sh &\n")
    _write(root / "usr/sbin/config_script/dnrd_monitor.sh",
           "#!/bin/sh\nrecv_q=$(netstat -nlp | grep 0.0.0.0:53 -w)\n"
           "killall -11 dnrd\n")
    _write(root / "bin/dnrd", "\x7fELF fake")
    doc = runner.build_document(root, target="t")
    errors, _ = runner.validate(doc)
    assert errors == []
    dnrd = [e for e in doc["inputs"] if e["service"] == "dnrd"]
    assert dnrd, "dnrd must be discovered through rcS script recursion"
    ent = dnrd[0]
    assert ent["port"] == 53 and ent["transport"] == "udp"
    assert ent["autostart"] is True
    assert ent["evidence_grade"] == "observed"
    assert ent["needs_confirmation"] is False
    # console login helper on the respawn line is never an input
    assert all("sulogin" not in e["service"] for e in doc["inputs"])


def test_busybox_phantom_applet_rejected(tmp_path):
    # sbin/syslogd -> busybox whose build lacks the syslogd applet:
    # a phantom public input must not be emitted
    root = _mk_rootfs(tmp_path)
    (root / "bin/busybox").write_bytes(b"\x7fELF fake telnetd\x00sh\x00")
    (root / "sbin/syslogd").symlink_to("../bin/busybox")
    (root / "usr/sbin/telnetd").symlink_to("../../bin/busybox")
    doc = runner.build_document(root, target="t")
    assert all(e["service"] != "syslogd" for e in doc["inputs"])
    assert any("syslogd" in e and "dangling multicall symlink" in e
               for e in doc["metadata"]["excluded"])
    # telnetd applet exists in the busybox build -> kept, but as an
    # annotated kb_default multicall entry
    tel = [e for e in doc["inputs"] if e["service"] == "telnetd"]
    assert tel and tel[0]["evidence_grade"] == "kb_default"
    assert "multicall" in tel[0]["evidence"]


def test_busybox_nonlistening_applet_rejected(tmp_path):
    # applet present in the busybox build but client/non-listening by
    # default (busybox syslogd only reads /dev/log) -> no default promotion
    root = _mk_rootfs(tmp_path)
    (root / "bin/busybox").write_bytes(b"\x7fELF fake syslogd\x00telnetd\x00")
    (root / "sbin/syslogd").symlink_to("../bin/busybox")
    doc = runner.build_document(root, target="t")
    assert all(e["service"] != "syslogd" for e in doc["inputs"])
    assert any("syslogd" in e and "non-listener" in e
               for e in doc["metadata"]["excluded"])


def test_services_lookup_underscore_variants():
    assert services.lookup("dnrd_monitor") is not None
    assert services.lookup("dnrd_monitor")["protocol"] == "dns"
    assert services.lookup("miniupnpd_dbg") is not None
    assert services.lookup("totally_unknown_thing") is None


def test_gate2_recount_can_fail():
    # the completeness gate must actually fail when accounting breaks
    doc = {"metadata": {"total_inputs": 1, "candidates_found": 3,
                        "excluded": []},
           "inputs": [{"id": "IN-001", "protocol": "http",
                       "service": "lighttpd", "address": None, "port": 80,
                       "transport": "tcp", "public": True,
                       "input_types": ["URL path"],
                       "evidence_grade": "observed",
                       "needs_confirmation": False}]}
    errors, _ = runner.validate(doc)
    assert any("accounting" in e for e in errors)


def test_run_job_writes_artifacts(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    ext = data_dir / "extracted" / "job1"
    root = _mk_rootfs(ext / "firmware" / "squashfs-root")
    _write(root / "usr/sbin/dnsmasq", "\x7fELF fake")
    _write(ext / "manifest.json",
           json.dumps({"firmware": "fw.bin", "job_id": "job1",
                       "binaries": [], "stats": {}}))
    summary = runner.run_job("job1", data_dir)
    assert summary["status"] == "ok"
    assert "gate_warnings" in summary
    assert summary["candidates_found"] == \
        summary["total_inputs"] + summary["excluded"]
    doc = json.loads((data_dir / "inputs/job1/identification.json")
                     .read_text(encoding="utf-8"))
    assert doc["metadata"]["target"] == "fw.bin"
    assert any(e["service"] == "dnsmasq" and e["port"] == 53
               for e in doc["inputs"])


def test_is_public_address():
    assert not services.is_public_address("127.0.0.1")
    assert not services.is_public_address("::1")
    assert not services.is_public_address("localhost")
    assert services.is_public_address("0.0.0.0")
    assert services.is_public_address("192.168.1.1")
    assert services.is_public_address(None)


def test_locate_rootfs_nested(tmp_path):
    base = tmp_path / "extracted"
    deep = base / "firmware" / "binwalk" / "0"
    (deep / "etc").mkdir(parents=True)
    (deep / "bin").mkdir(parents=True)
    found = discover.locate_rootfs(base)
    assert found == deep
