"""Discover external network inputs by scanning an extracted rootfs.

Pure filesystem analysis — no IDA, no LLM, deterministic. Evidence sources,
strongest first:

  1. service manager definitions (systemd units / init.d / inittab / inetd),
     with one-level recursion into scripts those definitions invoke
  2. daemon configuration files (listen/bind/port directives, enable
     semantics, auth posture)
  3. web endpoint expansion (cgi dirs, webapi libs, vhost conf.d entries)
     behind discovered web frontends
  4. known-daemon binaries present in the rootfs (services.py table)
  5. server-socket import promotion over *every* ELF in the rootfs bin
     dirs — unknown daemons become `candidate`-grade inputs

Every candidate carries an evidence grade:
  observed    config/startup evidence AND a port parsed from that evidence
  config      config file present but its port not parsed (port fell back
              to the knowledge base)
  kb_default  knowledge-base entry only (binary present, nothing else)
  candidate   unknown daemon promoted from server-socket imports

Grading rules: no bind evidence -> `address` stays null (never defaulted to
0.0.0.0); `kb_default` and `candidate` entries carry needs_confirmation.
Busybox multicall symlinks are special-cased: the whole-binary socket-import
union never counts as applet evidence, client/non-listening applets are
never promoted by default, and a symlink whose applet is absent from the
busybox build is treated as phantom.

Every discovered listener ends up either in `inputs` (public) or in
`excluded` with a machine reason — including candidates whose promotion
failed (gate 2: completeness — nothing found may silently vanish).
"""

import re
from pathlib import Path

from pipeline.inputs import elfchain, services

ROOTFS_MARKERS = ("bin", "sbin", "usr", "etc", "lib", "www", "cgi-bin",
                  "var", "opt")

# directories we never descend into when globbing for configs
_SKIP_DIRS = {"proc", "sys", "dev", "run", "tmp", "lost+found"}

# binwalk recursive carve sitting next to the original ELF inside the
# extracted squashfs, e.g. httpd_0_elf.raw / httpd_1493456_crc32.raw.
# These are signature hits, not daemons. The underscore prefix fallback
# in services.lookup would otherwise treat httpd_0_elf.raw as httpd.
_CARVE_RX = re.compile(
    r".+_\d+_[A-Za-z][A-Za-z0-9_]{0,40}\.raw$", re.IGNORECASE)


def is_carve_artifact(name: str) -> bool:
    """True for binwalk-carved siblings of a real firmware binary."""
    base = str(name or "").rsplit("/", 1)[-1]
    return bool(_CARVE_RX.match(base))

# superservers / client tools that must never become inputs themselves
_SKIP_NAMES = {"inetd", "xinetd", "tcpd", "start-stop-daemon", "daemon",
               "logger", "sh", "bash", "busybox", "killall", "pidof",
               "sleep", "mount", "modprobe", "insmod", "sysctl",
               "systemctl", "journalctl", "udevadm", "systemd-tmpfiles",
               "ssh-keygen", "agetty", "sssd", "exportfs", "dhclient",
               "syslog-ng-ctl", "avahi-browse", "avahi-publish", "rsync",
               "usbip", "klogd", "smbclient", "nfsstat", "rpcinfo",
               # console login helpers (inittab respawn lines) — not network
               "sulogin", "login", "getty",
               # well-known client/inspection tools whose socket imports
               # (often NETLINK) never make them network listeners
               "ip", "ifconfig", "netstat", "ss", "route", "brctl", "tc",
               "ethtool", "iw", "iwconfig", "nvram", "curl", "mcurl",
               "wget", "nc", "openssl", "nslookup", "ping", "ping6",
               "traceroute", "wpa_cli", "hostapd_cli", "ebtables",
               "iptables", "ip6tables", "telnet", "ftpget", "ftpput",
               # device managers use NETLINK sockets (bind/listen imports)
               # but are not network listeners
               "mdev", "udevd", "systemd-udevd", "hald", "hotplug"}

# server-side socket symbols — an unknown daemon must import `bind` plus a
# receive/accept call before we promote it to a candidate (gate 2 recall
# without client-tool false positives)
_SERVER_SYMS = {"listen", "accept", "accept4", "recvfrom", "recvmsg"}

# ---------------------------------------------------------------------------
# config-file location table: daemon basename -> candidate config paths
# ---------------------------------------------------------------------------
CONFIG_CANDIDATES = {
    "lighttpd": ["etc/lighttpd/lighttpd.conf", "etc/lighttpd.conf"],
    "nginx": ["etc/nginx/nginx.conf", "etc/nginx.conf",
              "etc.defaults/nginx/nginx.conf.default",
              "etc.defaults/nginx/nginx.conf"],
    "apache": ["etc/apache2/httpd.conf", "etc/httpd/conf/httpd.conf",
               "etc/httpd.conf"],
    "httpd": ["etc/httpd.conf", "etc/httpd/httpd.conf"],
    "uhttpd": ["etc/config/uhttpd", "etc/uhttpd.conf"],
    "sshd": ["etc/ssh/sshd_config", "etc/sshd_config"],
    "dropbear": ["etc/default/dropbear", "etc/config/dropbear"],
    "vsftpd": ["etc/vsftpd.conf", "etc/vsftpd/vsftpd.conf"],
    "proftpd": ["etc/proftpd.conf", "etc/proftpd/proftpd.conf"],
    "pure-ftpd": ["etc/pure-ftpd/pure-ftpd.conf", "etc/default/pure-ftpd"],
    "smbd": ["etc/samba/smb.conf", "etc/smb.conf"],
    "avahi-daemon": ["etc/avahi/avahi-daemon.conf",
                     "etc.defaults/avahi/avahi-daemon.conf"],
    "miniupnpd": ["etc/miniupnpd/miniupnpd.conf", "etc/miniupnpd.conf"],
    "minissdpd": ["etc/miniupnpd/minissdpd.conf", "etc/default/minissdpd"],
    "dnsmasq": ["etc/dnsmasq.conf", "etc/dnsmasq.d"],
    "named": ["etc/named.conf", "etc/bind/named.conf"],
    "snmpd": ["etc/snmp/snmpd.conf", "etc/snmpd.conf"],
    "ntpd": ["etc/ntp.conf", "etc/ntpd.conf"],
    "chronyd": ["etc/chrony.conf", "etc/chrony/chrony.conf"],
    "cupsd": ["etc/cups/cupsd.conf"],
    "slapd": ["etc/openldap/slapd.conf", "etc/ldap/slapd.conf"],
    "upsd": ["etc/nut/upsd.conf", "etc/ups/upsd.conf"],
    "rsyncd": ["etc/rsyncd.conf"],
    "tftpd": ["etc/default/tftpd-hpa", "etc/xinetd.d/tftp"],
    "opentftp": ["etc/opentftp.ini", "etc/default/opentftp"],
    "rpcbind": ["etc/default/rpcbind", "etc/sysconfig/rpcbind"],
    "syslogd": ["etc/syslog.conf", "etc/rsyslog.conf"],
    "syslog-ng": ["etc/syslog-ng/syslog-ng.conf"],
    "redis-server": ["etc/redis/redis.conf", "etc/redis.conf"],
    "postgres": ["etc/postgresql", "var/lib/pgsql/data/postgresql.conf"],
    "mysqld": ["etc/my.cnf", "etc/mysql/my.cnf"],
    "mosquitto": ["etc/mosquitto/mosquitto.conf", "etc/mosquitto.conf"],
    "usbipd": ["etc/default/usbipd"],
    "telnetd": ["etc/xinetd.d/telnet", "etc/inetd.conf"],
}

# web roots searched for cgi / webapi endpoints (relative to each root)
WEB_DIRS = ("www", "htdocs", "cgi-bin", "www/cgi-bin", "var/www",
            "webroot", "webroot_ro", "var/webroot",
            "usr/syno/synoman", "usr/syno/web", "web", "webroot",
            "usr/share/www", "usr/www", "opt/www")

# ---------------------------------------------------------------------------
# directive regexes (address / port extraction from config text)
# ---------------------------------------------------------------------------
_RE_PORT_KV = [
    re.compile(r"(?im)^\s*server\.port\s*=\s*(\d+)"),                    # lighttpd
    re.compile(r"(?im)^\s*Port\s+(\d+)\s*$"),                            # sshd
    re.compile(r"(?im)^\s*listen_port\s*=\s*(\d+)"),                     # vsftpd
    re.compile(r"(?im)^\s*port\s*=\s*(\d+)\s*$"),                        # generic ini
    re.compile(r"(?im)^\s*port\s+(\d+)\s*;"),                            # named
    re.compile(r"(?im)^\s*agentaddress\s+(\S+)"),                        # snmpd
    re.compile(r"(?im)^\s*Listen\s+(?:\S+:)?(\d+)"),                     # cups/apache
]
_RE_NGINX_LISTEN = re.compile(
    r"(?im)^\s*listen\s+(?:\[[0-9a-fA-F:]+\]|[\w.]+:)?(\d+)"
    r"(?:\s+(ssl))?[\s;]")
_RE_ADDR_KV = [
    re.compile(r"(?im)^\s*server\.bind\s*=\s*\"?([\w.:]+)\"?"),          # lighttpd
    re.compile(r"(?im)^\s*ListenAddress\s+(\S+)"),                       # sshd
    re.compile(r"(?im)^\s*listen_address(?:6)?\s*=\s*([\w.:]+)"),        # vsftpd
    re.compile(r"(?im)^\s*bind\b[^=\n]*=\s*\"?([\w.:]+)\"?"),            # generic
    re.compile(r"(?im)^\s*listen-address\s*=\s*([\w.:,]+)"),             # dnsmasq
    re.compile(r"(?im)^\s*listening_ip\s*=\s*([\w.:/]+)"),               # miniupnpd
    re.compile(r"(?im)^\s*listen-on\s*\{\s*([^;}]+)"),                   # named
    re.compile(r"(?im)^\s*interfaces\s*=\s*(.+)"),                       # smb.conf
    re.compile(r"(?im)^\s*address\s*=\s*([\w.:]+)"),                     # rsyncd
    re.compile(r"(?im)^\s*SLAPD_LISTEN\s*=\s*\"?([^\"\n]+)\"?"),         # slapd env
]
# agentaddress udp:127.0.0.1:161 style values
_RE_SNMP_ADDR = re.compile(r"(?:(udp|tcp):)?(\[[\w:]+\]|[\w.]+)?:(\d+)$")
# daemon flags in init scripts:  lighttpd -f conf -p 8080, utelnetd -p 23
_RE_FLAG_PORT = re.compile(r"(?:^|\s)-p\s*=?(\d{1,5})\b")
# absolute daemon paths (multi-component: /usr/sbin/config_script/x.sh)
_RE_DAEMON_PATH = re.compile(
    r"((?:/(?:usr/)?s?bin|/usr/local/s?bin|/usr/syno/(?:s?bin|sbin)|"
    r"/opt/\S{1,32}?/s?bin)/[A-Za-z0-9_.+@-]{2,64}"
    r"(?:/[A-Za-z0-9_.+@-]{1,64}){0,4})")
_RE_LISTEN_SOCKET = re.compile(r"(?im)^\s*ListenStream\s*=\s*(\S+)")
_RE_NGINX_INCLUDE = re.compile(r"(?im)^\s*include\s+(\S*conf\.d/\*?\.?\w*)\s*;")
# explicit listen-address mentions inside scripts (netstat greps, firewall
# helper output): 0.0.0.0:53 / 127.0.0.1:53 / :::53
_RE_SCRIPT_LISTEN = re.compile(
    r"(?<![\w.])(?:0\.0\.0\.0|127\.0\.0\.1|\[?::\]?|\*):(\d{1,5})\b")
# daemon enable semantics in config files
_RE_DISABLE = [
    re.compile(r"(?im)^\s*listen\s*=\s*NO\b"),                        # vsftpd
    re.compile(r"(?im)^\s*disable\s*=\s*yes\b"),                      # xinetd
    re.compile(r"(?im)^\s*disabled\s*=\s*yes\b"),
    re.compile(r"(?im)^\s*enabled?\s*=\s*(?:no|false|0)\s*$"),
]
_RE_ENABLE = [
    re.compile(r"(?im)^\s*listen\s*=\s*YES\b"),                       # vsftpd
    re.compile(r"(?im)^\s*disable\s*=\s*no\b"),
    re.compile(r"(?im)^\s*enabled?\s*=\s*(?:yes|true|1)\s*$"),
]
# auth-posture directives worth surfacing (regex -> note template)
_RE_AUTH_POSTURE = [
    (re.compile(r"(?im)^\s*anonymous_enable\s*=\s*(YES|NO)"),
     "anonymous_enable={0} — anonymous FTP login {1}"),
    (re.compile(r"(?im)^\s*local_enable\s*=\s*(YES|NO)"),
     "local_enable={0} — local-account FTP login {1}"),
    (re.compile(r"(?im)^\s*PermitRootLogin\s+(\w+)"),
     "PermitRootLogin {0}"),
    (re.compile(r"(?im)^\s*PasswordAuthentication\s+(\w+)"),
     "PasswordAuthentication {0}"),
    (re.compile(r"(?im)^\s*PermitEmptyPasswords\s+(\w+)"),
     "PermitEmptyPasswords {0}"),
    (re.compile(r"(?im)^\s*auth\.require\b"),
     "lighttpd auth.require present — HTTP auth realm configured"),
]


def _auth_posture(text, rel_used):
    """Extract authentication-posture directives from a daemon config."""
    out = []
    for rx, template in _RE_AUTH_POSTURE:
        m = rx.search(text)
        if not m:
            continue
        if "{1}" in template:
            val = m.group(1)
            note = template.format(
                val, "permitted" if val.lower() in ("yes", "true", "1")
                else "disabled")
        elif m.lastindex:
            note = template.format(m.group(1))
        else:
            note = template
        out.append(f"{rel_used}: {note}")
    return out


def _config_disabled(text):
    """True when a config explicitly disables the daemon (listen=NO,
    disable=yes, enabled=0 ...)."""
    if any(rx.search(text) for rx in _RE_ENABLE):
        return False   # explicit enable wins over a commented/disable stray
    return any(rx.search(text) for rx in _RE_DISABLE)


def _read_text(path, limit=512 * 1024):
    try:
        data = Path(path).read_bytes()[:limit]
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


def locate_rootfs(base):
    """Find the primary rootfs directory under `base` (or base itself)."""
    roots = locate_roots(base)
    return roots[0][0] if roots else None


def _looks_root(p):
    try:
        children = {c.name for c in Path(p).iterdir() if c.is_dir()}
    except OSError:
        return False
    # a real rootfs always has an etc variant plus at least one executable/
    # library dir. etc_ro / etc.defaults cover router firmwares whose /etc
    # is a runtime symlink; the executable-dir requirement deliberately
    # rejects EMBA log dirs (etc/ + firmware/ + csv_logs/) so the walk
    # descends to the actual firmware tree
    return bool(children & {"etc", "etc_ro", "etc.defaults"}) and \
        bool(children & {"bin", "sbin", "usr", "lib"})


# etc path variants on different firmware layouts
_ETC_VARIANTS = ("etc", "etc_ro", "etc.defaults")


def _etc_paths(rootfs, rel):
    """Yield rootfs paths for a config-relative path, expanding the etc/
    prefix across firmware layouts (etc / etc_ro / etc.defaults)."""
    rootfs = Path(rootfs)
    if rel.startswith("etc/"):
        for v in _ETC_VARIANTS:
            yield rootfs / v / rel[4:]
    elif rel == "etc":
        for v in _ETC_VARIANTS:
            yield rootfs / v
    else:
        yield rootfs / rel


def _all_dirs(rootfs, rel):
    """All existing directories for a config-relative path across every etc
    variant (etc/ + etc_ro/ + etc.defaults/). Firmwares routinely split init
    content across variants (e.g. an empty var-backed etc/ beside the real
    etc_ro/init.d/rcS) — first-match would silently drop the rest."""
    return [p for p in _etc_paths(rootfs, rel) if p.is_dir()]


def _first_dir(rootfs, rel):
    for p in _etc_paths(rootfs, rel):
        if p.is_dir():
            return p
    return None


def _first_file(rootfs, rel):
    for p in _etc_paths(rootfs, rel):
        if p.is_file():
            return p
    return None


def locate_roots(base, notes=None):
    """Find all scannable roots under `base`.

    Returns a list of (root_path, entry_file_prefix). A firmware extraction
    may contain several partitions (main rootfs, initrd/rd_root, package
    containers like DSM's packages/<name>.spk/pkg) — every one can host
    listeners. `prefix` is prepended to entry file paths so results stay
    attributable (DSM gold format: packages/X.spk#pkg/app/foo.cgi).

    Encrypted Synology packages (magic 01adbeef/5badbeef) cannot be read
    without the vendor keys; they are reported through `notes` so the
    omission is auditable instead of silent."""
    base = Path(base)
    roots = []

    def add(root, prefix):
        root = Path(root)
        if root not in [r for r, _ in roots]:
            roots.append((root, prefix))

    def handle_packages(pkgdir):
        import tarfile
        for spk in sorted(pkgdir.iterdir()):
            if spk.is_dir():
                pkg = spk / "pkg"
                if pkg.is_dir():
                    add(pkg, f"packages/{spk.name}#pkg/")
                elif _looks_root(spk):
                    add(spk, f"packages/{spk.name}/")
            elif spk.suffix == ".spk" and spk.is_file():
                if tarfile.is_tarfile(spk):
                    # unsigned SPK: outer tar holds package.tgz + scripts/conf
                    cache = base / ".fwgraph_pkgcache" / spk.stem
                    pkgdir_out = cache / "pkg"
                    if not pkgdir_out.is_dir():
                        try:
                            cache.mkdir(parents=True, exist_ok=True)
                            with tarfile.open(spk) as tf:
                                tf.extractall(cache, filter="data")
                            inner = cache / "package.tgz"
                            if inner.is_file():
                                pkgdir_out.mkdir(exist_ok=True)
                                with tarfile.open(inner) as tf:
                                    tf.extractall(pkgdir_out,
                                                  filter="data")
                        except (OSError, tarfile.TarError) as exc:
                            if notes is not None:
                                notes.append(f"UNREADABLE package {spk.name}: "
                                             f"{exc}")
                    if pkgdir_out.is_dir():
                        add(pkgdir_out, f"packages/{spk.name}#pkg/")
                        # SPK scripts/conf live beside package.tgz
                        if (cache / "scripts").is_dir():
                            add(cache, f"packages/{spk.name}#")
                else:
                    try:
                        magic = spk.read_bytes()[:4].hex()
                    except OSError:
                        magic = "?"
                    if notes is not None:
                        notes.append(
                            f"ENCRYPTED package {spk.name}: Synology signed/"
                            f"encrypted SPK (magic {magic}) — contents not "
                            f"statically extractable; package binaries "
                            f"absent from this scan")

    if _looks_root(base):
        add(base, "")
    queue = [base]
    seen = 0
    while queue and seen < 4000:
        node = queue.pop(0)
        seen += 1
        try:
            kids = [c for c in sorted(node.iterdir()) if c.is_dir()]
        except OSError:
            continue
        for kid in kids:
            if kid.name in _SKIP_DIRS:
                continue
            rel = kid.relative_to(base)
            # package containers: packages/<pkg>/pkg is a root
            if kid.name == "packages":
                handle_packages(kid)
                continue
            if _looks_root(kid):
                # do not treat usr/ etc. inside an already-found root as new
                if not any(kid == r or r in kid.parents for r, _ in roots):
                    prefix = "" if kid == base else \
                        str(rel).replace("\\", "/") + "/"
                    add(kid, prefix)
                continue
            # don't descend into found roots (their subtrees are scanned by
            # the root's own pass), but do descend elsewhere
            if not any(kid == r or r in kid.parents for r, _ in roots):
                queue.append(kid)
    return roots


def _rel(rootfs, path):
    return str(Path(path).relative_to(rootfs)).replace("\\", "/")


def _parse_address_port(text):
    """Parse listen directives from one daemon's config text.

    Returns (address, port, ports) — any may be None/empty. All matching
    port directives are collected into `ports` (first hit remains the
    primary `port`); previously a first-hit stop silently dropped the rest.

    Only line-anchored key/value directives are considered here. The
    `-p N` daemon-flag form is deliberately NOT matched against a whole
    script — that cross-links ports between unrelated processes sharing
    the file. Flag ports are extracted per command line by
    `_flag_port_on_line`."""
    address = None
    port = None
    ports = []
    for rx in _RE_ADDR_KV:
        m = rx.search(text)
        if m:
            val = m.group(1).strip().strip(";")
            if re.fullmatch(r"[\w.:,\s]+", val):
                first = re.split(r"[,\s]+", val)[0]
                if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|"
                                r"[0-9a-fA-F:]*:[0-9a-fA-F:]+|localhost|any|\*",
                                first):
                    address = first.strip("[]")
    for rx in _RE_PORT_KV:
        for m in rx.finditer(text):
            val = m.group(1)
            if rx is _RE_PORT_KV[5]:  # snmpd agentaddress token
                am = _RE_SNMP_ADDR.search(val)
                if am:
                    if am.group(2):
                        address = am.group(2).strip("[]") or address
                    if int(am.group(3)) not in ports:
                        ports.append(int(am.group(3)))
                continue
            try:
                p = int(val)
            except ValueError:
                continue
            if p not in ports:
                ports.append(p)
    if ports:
        port = ports[0]
    return address, port, ports


def _flag_port_on_line(line, path):
    """`-p N` port flag on the single command line that invokes `path`.

    Per-command parsing only — binding a port found anywhere in a script to
    an unrelated daemon was a cross-process port-contamination bug."""
    if path not in line:
        return None
    m = _RE_FLAG_PORT.search(line)
    if m:
        return int(m.group(1))
    return None


def _nginx_listens(text):
    """All (port, ssl) pairs from nginx-style listen directives."""
    out = []
    for m in _RE_NGINX_LISTEN.finditer(text):
        pair = (int(m.group(1)), bool(m.group(2)))
        if pair not in out:
            out.append(pair)
    return out


class _Candidate:
    __slots__ = ("name", "path", "svc", "address", "port", "ports_ssl",
                 "transport", "protocol", "evidence", "autostart", "kind",
                 "endpoints", "extra_ports", "has_config", "config_disabled",
                 "auth_posture", "port_source", "evidence_grade",
                 "needs_confirmation", "multicall", "drop_reason")

    def __init__(self, name, path, svc, kind="daemon"):
        self.name = name
        self.path = path            # rootfs-relative binary path or None
        self.svc = svc              # services table entry or None
        self.address = None
        self.port = None
        self.ports_ssl = []         # [(port, ssl)] for web frontends
        self.transport = None
        self.protocol = None
        self.evidence = []
        self.autostart = False
        self.kind = kind            # daemon | web_endpoint
        self.endpoints = []         # entry files for web_endpoint groups
        self.extra_ports = []       # additional ports seen in config
        self.has_config = False     # a config file for this daemon exists
        self.config_disabled = False  # config explicitly disables it
        self.auth_posture = []      # auth-relevant config directives
        self.port_source = None     # observed | default | None
        self.evidence_grade = None  # observed|config|kb_default|candidate
        self.needs_confirmation = False
        self.multicall = False      # resolves to a busybox-style binary
        self.drop_reason = None     # set -> excluded, never silently dropped


def _key(name):
    return name.lower()


def _cand(cands, name, svc, kind="daemon"):
    k = (_key(name), kind)
    if k not in cands:
        cands[k] = _Candidate(name, None, svc, kind)
    return cands[k]


def _scan_systemd(rootfs, cands):
    for base in ("etc/systemd/system", "lib/systemd/system",
                 "usr/lib/systemd/system", "conf/systemd"):
        for d in _all_dirs(rootfs, base):
            for unit in sorted(d.rglob("*")):
                if not unit.is_file() or unit.suffix not in (
                        ".service", ".socket"):
                    continue
                text = _read_text(unit)
                if unit.suffix == ".socket":
                    m = _RE_LISTEN_SOCKET.search(text)
                    if m:
                        addr, _, prt = m.group(1).rpartition(":")
                        name = unit.stem
                        if name in _SKIP_NAMES:
                            continue
                        svc = services.lookup(name)
                        c = _cand(cands, name, svc)
                        if prt.isdigit():
                            c.port = int(prt)
                            c.port_source = "observed"
                        if addr:
                            c.address = addr
                        c.autostart = True
                        c.evidence.append(
                            f"{_rel(rootfs, unit)} socket unit "
                            f"ListenStream={m.group(1)}")
                    continue
                if "ExecStart" not in text:
                    continue
                for line in text.splitlines():
                    if not line.lstrip().startswith("ExecStart"):
                        continue
                    for m in _RE_DAEMON_PATH.finditer(line):
                        path = m.group(1)
                        name = path.rsplit("/", 1)[-1]
                        if name in _SKIP_NAMES:
                            break
                        svc = services.lookup(name)
                        c = _cand(cands, name, svc)
                        if (rootfs / path.lstrip("/")).exists():
                            c.path = path.lstrip("/")
                        c.autostart = True
                        c.evidence.append(
                            f"{_rel(rootfs, unit)} ExecStart -> {path}")
                        fport = _flag_port_on_line(line, path)
                        if fport and c.port is None:
                            c.port = fport
                            c.port_source = "observed"
                        break


def _is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _looks_script(path):
    """Shell scripts we recurse into (rcS-style helpers often lack .sh)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError:
        return False
    if head.startswith(b"#!"):
        return True
    if Path(path).suffix in (".sh", ".rc"):
        return True
    return False


def _find_binary(rootfs, name):
    for sub in ("sbin", "bin", "usr/sbin", "usr/bin", "usr/local/sbin",
                "usr/local/bin", "usr/syno/sbin", "usr/syno/bin"):
        p = rootfs / sub / name
        if p.is_file():
            return f"{sub}/{name}"
    return None


_NAME_TOKEN_RX = re.compile(r"[A-Za-z][A-Za-z0-9_.+@-]{2,32}")


def _note_bare_daemons(rootfs, lines, cands, via, subject=None):
    """Bare daemon-name mentions inside a script (killall dnrd, pidof x...)
    count as startup evidence for a *known* service whose binary exists.

    `subject` is the daemon the script itself is about (derived from the
    script filename, e.g. dnrd_monitor.sh -> dnrd): an explicit listen
    address anywhere in such a single-purpose script (netstat -nlp | grep
    0.0.0.0:53) is port evidence for the subject even when the mentioning
    line does not name it."""
    subject_c = None
    if subject:
        svc = services.lookup(subject)
        if svc is not None:
            # a helper named <daemon>_monitor / <daemon>_ctl stands for the
            # canonical daemon binary, not for itself
            for alt in svc["names"]:
                path = _find_binary(rootfs, alt)
                if path:
                    subject_c = _cand(cands, alt, svc)
                    if not subject_c.path:
                        subject_c.path = path
                    break
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        line_hit = None
        for tok in _NAME_TOKEN_RX.findall(line):
            if tok in _SKIP_NAMES:
                continue
            svc = services.lookup(tok)
            if svc is None:
                continue
            path = _find_binary(rootfs, tok)
            if path is None:
                continue
            c = _cand(cands, tok, svc)
            if not c.path:
                c.path = path
            ev = f"{via}:{i} references {tok}"
            if ev not in c.evidence:
                c.evidence.append(ev)
            c.autostart = True
            line_hit = c
        m = _RE_SCRIPT_LISTEN.search(line)
        if m:
            target = line_hit or subject_c
            if target is not None and target.port_source != "observed":
                target.port = target.port or int(m.group(1))
                target.port_source = "observed"
                target.evidence.append(f"{via}:{i} listen address mention "
                                       f"port {m.group(1)}")
                target.autostart = True


def _scan_script(rootfs, rel, text, cands, depth=0, _seen=None):
    """Scan one init/rcS-style script for daemon invocations.

    Per command line: a `-p N` flag only ever binds to the daemon invoked on
    that same line. Non-ELF daemon-path arguments (helper scripts such as
    /usr/sbin/config_script/dnrd_monitor.sh) are recursed into one level —
    that is where router firmwares hide the actual service launches."""
    if _seen is None:
        _seen = set()
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue
        for m in _RE_DAEMON_PATH.finditer(line):
            path = m.group(1)
            name = path.rsplit("/", 1)[-1]
            if name in _SKIP_NAMES:
                continue
            full = rootfs / path.lstrip("/")
            if not full.exists():
                continue
            if not _is_elf(full):
                if depth < 1 and path not in _seen and _looks_script(full):
                    _seen.add(path)
                    child_rel = path.lstrip("/")
                    child_text = _read_text(full)
                    _scan_script(rootfs, child_rel, child_text,
                                 cands, depth + 1, _seen)
                    subject = services._norm_name(
                        child_rel.rsplit("/", 1)[-1])
                    _note_bare_daemons(rootfs, child_text.splitlines(),
                                       cands, child_rel, subject=subject)
                else:
                    # referenced as a daemon but not an ELF and not a
                    # script we can follow — keep as a dropped candidate so
                    # gate 2 can account for it
                    svc = services.lookup(services._norm_name(name))
                    c = _cand(cands, services._norm_name(name), svc)
                    if not c.path:
                        c.path = path.lstrip("/")
                    c.evidence.append(f"{rel}:{i} references {path}")
                    if c.drop_reason is None:
                        c.drop_reason = ("referenced by init scripts but not "
                                         "an ELF binary (script/config?)")
                continue
            svc = services.lookup(name)
            c = _cand(cands, name, svc)
            if not c.path:
                c.path = path.lstrip("/")
            c.autostart = True
            ev = f"{rel}:{i} invokes {path}"
            if ev not in c.evidence:
                c.evidence.append(ev)
            if c.port_source != "observed":
                fport = _flag_port_on_line(line, path)
                if fport:
                    c.port = c.port or fport
                    c.port_source = "observed"


_INITTAB_RX = re.compile(r"^[^#\s][^:]*:[^:]*:(sysinit|respawn|wait|once|boot)"
                         r":\s*(\S+)")


def _scan_inittab(rootfs, cands, seen_scripts):
    """inittab sysinit/respawn/... lines are autostart evidence; script
    targets (rcS) are followed one level like init.d scripts."""
    for base in ("etc/inittab",):
        for p in _etc_paths(rootfs, base):
            if not p.is_file():
                continue
            rel = _rel(rootfs, p)
            for i, line in enumerate(_read_text(p).splitlines(), 1):
                m = _INITTAB_RX.match(line.strip())
                if not m:
                    continue
                action, cmd = m.group(1), m.group(2)
                name = cmd.rsplit("/", 1)[-1]
                if name in _SKIP_NAMES:
                    continue
                full = rootfs / cmd.lstrip("/")
                if not full.exists():
                    continue
                if not _is_elf(full):
                    if cmd not in seen_scripts and _looks_script(full):
                        seen_scripts.add(cmd)
                        child = cmd.lstrip("/")
                        child_text = _read_text(full)
                        _scan_script(rootfs, child, child_text,
                                     cands, 0, seen_scripts)
                        subject = services._norm_name(
                            child.rsplit("/", 1)[-1])
                        _note_bare_daemons(rootfs, child_text.splitlines(),
                                           cands, child, subject=subject)
                    continue
                svc = services.lookup(name)
                c = _cand(cands, name, svc)
                if not c.path:
                    c.path = cmd.lstrip("/")
                c.autostart = True
                c.evidence.append(f"{rel}:{i} inittab {action} -> {cmd}")


def _scan_initd(rootfs, cands):
    seen_scripts = set()
    dirs = []
    for base in ("etc/init.d", "etc/rc.d/init.d", "etc.defaults/init.d",
                 "scripts"):
        dirs.extend(_all_dirs(rootfs, base))
    scanned = set()
    for d in dirs:
        if d in scanned:
            continue
        scanned.add(d)
        for script in sorted(d.iterdir()):
            if not script.is_file() or script.suffix in (".md", ".txt"):
                continue
            _scan_script(rootfs, _rel(rootfs, script), _read_text(script),
                         cands, 0, seen_scripts)
    _scan_inittab(rootfs, cands, seen_scripts)


def _scan_inetd(rootfs, cands):
    inetd = _first_file(rootfs, "etc/inetd.conf")
    if inetd is not None:
        for line in _read_text(inetd).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 7:
                continue
            service, sock_type, proto = parts[0], parts[1], parts[2]
            server = parts[6]
            name = server.rsplit("/", 1)[-1]
            if name in _SKIP_NAMES or name == "internal":
                continue
            svc = services.lookup(name)
            c = _cand(cands, name, svc)
            if (rootfs / server.lstrip("/")).exists():
                c.path = server.lstrip("/")
            c.autostart = True
            c.transport = "udp" if "dgram" in sock_type else "tcp"
            c.evidence.append(f"etc/inetd.conf: {service} {sock_type} {proto}"
                              f" -> {server}")
    for xinetd in _all_dirs(rootfs, "etc/xinetd.d"):
        for f in sorted(xinetd.iterdir()):
            text = _read_text(f)
            m = re.search(r"(?m)^\s*server\s*=\s*(\S+)", text)
            if not m:
                continue
            server = m.group(1)
            name = server.rsplit("/", 1)[-1]
            if name in _SKIP_NAMES:
                continue
            svc = services.lookup(name)
            c = _cand(cands, name, svc)
            if (rootfs / server.lstrip("/")).exists():
                c.path = server.lstrip("/")
            c.autostart = True
            pm = re.search(r"(?m)^\s*port\s*=\s*(\d+)", text)
            if pm:
                c.port = int(pm.group(1))
                c.port_source = "observed"
            tm = re.search(r"(?m)^\s*socket_type\s*=\s*(\w+)", text)
            if tm:
                c.transport = "udp" if tm.group(1) == "dgram" else "tcp"
            dis = re.search(r"(?im)^\s*disable\s*=\s*(\w+)", text)
            if dis and dis.group(1).lower() == "yes":
                # xinetd disable=yes cancels the candidate outright
                c.autostart = False
                c.config_disabled = True
                c.evidence.append(f"{_rel(rootfs, f)}: DISABLED "
                                  f"(disable=yes)")
            else:
                c.evidence.append(f"{_rel(rootfs, f)} -> {server}")


def _scan_configs(rootfs, cands):
    for name, paths in CONFIG_CANDIDATES.items():
        svc = services.lookup(name)
        for rel in paths:
            for conf in (p for p in _etc_paths(rootfs, rel)
                         if p.is_dir() or p.is_file()):
                rel_used = _rel(rootfs, conf)
                if conf.is_dir():
                    texts = [_read_text(p)
                             for p in sorted(conf.rglob("*.conf"))]
                    text = "\n".join(t for t in texts if t)
                else:
                    text = _read_text(conf)
                if not text.strip():
                    continue
                c = _cand(cands, name, svc)
                c.has_config = True
                addr, port, ports = _parse_address_port(text)
                c.address = c.address or addr
                if port and c.port_source != "observed":
                    c.port = c.port or port
                    c.port_source = "observed"
                for p_ in ports[1:]:
                    if p_ not in c.extra_ports and p_ != c.port:
                        c.extra_ports.append(p_)
                listens = _nginx_listens(text)
                if listens:
                    c.ports_ssl = listens
                    if c.port is None:
                        c.port = listens[0][0]
                        c.port_source = "observed"
                if _config_disabled(text):
                    c.config_disabled = True
                    c.autostart = False
                for note in _auth_posture(text, rel_used):
                    if note not in c.auth_posture:
                        c.auth_posture.append(note)
                c.evidence.append(
                    f"config {rel_used} present"
                    + (f" (port={port})" if port else "")
                    + (f" (extra ports={ports[1:]})" if len(ports) > 1 else "")
                    + (f" (bind={addr})" if addr else "")
                    + (" (DISABLED in config)" if c.config_disabled else ""))
                # collect every config variant instead of stopping at the
                # first hit — later variants may carry extra evidence


_BIN_DIRS = ("sbin", "bin", "usr/sbin", "usr/bin", "usr/local/sbin",
             "usr/local/bin", "usr/syno/bin", "usr/syno/sbin")


def _scan_binaries(rootfs, cands):
    """Known daemon binaries present on disk (may not autostart)."""
    for sub in _BIN_DIRS:
        d = rootfs / sub
        if not d.is_dir():
            continue
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for f in entries:
            if not f.is_file() or f.name in _SKIP_NAMES:
                continue
            if is_carve_artifact(f.name):
                continue
            svc = services.lookup(f.name)
            if svc is None:
                continue
            c = _cand(cands, f.name, svc)
            if not c.path:
                c.path = _rel(rootfs, f)
            ev = f"binary {_rel(rootfs, f)} present"
            if ev not in c.evidence:
                c.evidence.append(ev)


def _scan_elf_promotion(rootfs, cands):
    """Server-socket import promotion over *every* ELF in the bin dirs.

    Recall pass for daemons the knowledge base does not know (dnrd, vendor
    mesh agents, factory-test listeners...). Unknowns with `bind` plus a
    receive/accept import become `candidate`-grade inputs; unknowns without
    that evidence are not created here at all (they were never discovered).
    Multicall symlinks (busybox applets) are skipped — the whole-binary
    import union says nothing about a single applet."""
    for sub in _BIN_DIRS:
        d = rootfs / sub
        if not d.is_dir():
            continue
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for f in entries:
            if not f.is_file() or f.name in _SKIP_NAMES:
                continue
            if is_carve_artifact(f.name):
                continue
            if services.lookup(f.name) is not None:
                continue  # known daemons are handled by _scan_binaries
            if not _is_elf(f):
                continue
            real, real_rel, multicall = elfchain.resolve_real(
                rootfs, _rel(rootfs, f))
            if multicall:
                continue  # applet-level evidence handled in discover()
            _, undef = elfchain.elf_facts(real)
            if "bind" not in undef or not (set(undef) & _SERVER_SYMS):
                continue
            c = _cand(cands, f.name, None)
            if not c.path:
                c.path = _rel(rootfs, f)
            sock = sorted(set(undef) & elfchain.SOCKET_SYMS)
            c.evidence.append("unknown daemon with server socket imports: "
                              + ",".join(sock))
            # transport heuristic: a listen/accept import means TCP, a bare
            # recvfrom/recvmsg without listen is typically UDP
            if set(undef) & {"listen", "accept", "accept4"}:
                c.transport = "tcp"
            else:
                c.transport = "udp"


def _scan_web_endpoints(rootfs, cands):
    """Expand web frontends into logical endpoint inputs.

    A firmware web server usually fronts many logical services (CGI dirs,
    webapi libraries, vhost conf snippets). Each becomes its own input
    entry sharing the frontend listener address/ports."""
    frontends = [c for (n, kind), c in cands.items()
                 if kind == "daemon" and c.svc
                 and c.svc.get("protocol") in ("http", "https")
                 and c.name in ("nginx", "lighttpd", "httpd", "uhttpd",
                                "apache", "goahead", "webs")]
    if not frontends:
        return
    fe = frontends[0]
    ports = fe.ports_ssl or [(fe.port or 80, fe.svc["protocol"] == "https")]
    proto = "https" if any(ssl for _, ssl in ports) else "http"
    # no bind evidence -> address stays null (never invent 0.0.0.0)
    addr = fe.address
    fe_grade = ("observed" if fe.port_source == "observed"
                else "config" if fe.has_config else "kb_default")

    def _mk_endpoint(name):
        c = _cand(cands, name, None, "web_endpoint")
        c.protocol, c.address, c.transport = proto, addr, "tcp"
        c.port = ports[0][0]
        c.ports_ssl = ports
        c.port_source = fe.port_source
        c.evidence_grade = fe_grade
        c.needs_confirmation = fe_grade in ("kb_default", "candidate")
        return c

    # 1) vhost conf.d snippets -> one input per conf file
    for confd in ("etc/nginx/conf.d", "usr/syno/share/nginx/conf.d",
                  "etc/lighttpd/conf.d", "etc/httpd/conf.d"):
        d = rootfs / confd
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.conf")):
            text = _read_text(f)
            backends = sorted(set(re.findall(
                r"rewrite\s+\S+\s+/([A-Za-z0-9_.-]+\.cgi)", text)))
            c = _mk_endpoint(f"vhost:{f.stem}")
            c.endpoints.extend(b for b in backends if b not in c.endpoints)
            c.evidence.append(f"{_rel(rootfs, f)} location blocks -> "
                              f"{', '.join(backends) or 'static/proxy'}")

    # 2) cgi directories -> one input per app directory
    for wd in WEB_DIRS:
        d = rootfs / wd
        if not d.is_dir():
            continue
        try:
            cgis = sorted(d.rglob("*.cgi"))
        except OSError:
            continue
        if not cgis:
            continue
        groups = {}
        for cgi in cgis:
            try:
                rel = cgi.relative_to(d)
            except ValueError:
                continue
            top = rel.parts[0] if len(rel.parts) > 1 else "(root)"
            groups.setdefault(top, []).append(_rel(rootfs, cgi))
        for top, files in sorted(groups.items()):
            label = top if top != "(root)" else Path(wd).name
            c = _mk_endpoint(f"cgi:{wd}:{label}")
            c.endpoints.extend(files[:40])
            c.evidence.append(f"{len(files)} .cgi endpoints under {wd}/{top}"
                              if top != "(root)" else
                              f"{len(files)} .cgi endpoints under {wd}")

    # 3) webapi libraries -> one input per webapi directory (SYNO-style
    #    API module collections; per-file would drown the report)
    for wd in WEB_DIRS:
        d = rootfs / wd
        if not d.is_dir():
            continue
        try:
            libs = sorted(d.rglob("*.lib"))
        except OSError:
            continue
        groups = {}
        for lib in libs:
            try:
                rel = lib.relative_to(d)
            except ValueError:
                continue
            parent = str(rel.parent).replace("\\", "/")
            label = rel.parts[0] if len(rel.parts) > 1 else Path(wd).name
            groups.setdefault((parent, label), []).append(_rel(rootfs, lib))
        for (parent, label), files in sorted(groups.items()):
            c = _mk_endpoint(f"webapi:{wd}:{parent}")
            c.endpoints.extend(files[:40])
            c.evidence.append(f"{len(files)} webapi modules under "
                              f"{wd}/{parent}")


def discover(rootfs):
    """Scan one rootfs -> resolved candidates (daemons first, then web endpoints)."""
    rootfs = Path(rootfs)
    cands = {}
    _scan_systemd(rootfs, cands)
    _scan_initd(rootfs, cands)
    _scan_inetd(rootfs, cands)
    _scan_configs(rootfs, cands)
    _scan_binaries(rootfs, cands)
    _scan_web_endpoints(rootfs, cands)
    _scan_elf_promotion(rootfs, cands)

    out = []
    for c in cands.values():
        svc = c.svc or {}
        # config can explicitly take a daemon off the air
        if c.config_disabled:
            c.drop_reason = "disabled in configuration " \
                              "(listen=NO / disable=yes / enabled=0)"
        # multicall (busybox) rules: the shared binary's socket-import union
        # is never applet evidence; client/non-listening applets and
        # dangling applet symlinks are phantom inputs
        if c.kind == "daemon" and c.path and c.drop_reason is None:
            real, real_rel, multicall = elfchain.resolve_real(rootfs,
                                                              c.path)
            if multicall:
                c.multicall = True
                applet = services._norm_name(c.name)
                if not elfchain.applet_present(real, applet):
                    c.drop_reason = (
                        f"dangling multicall symlink: applet '{applet}' "
                        f"absent from {real_rel} build")
                elif applet in services.NON_LISTENING_BUSYBOX_APPLETS \
                        and c.port_source != "observed":
                    c.drop_reason = (
                        f"busybox applet '{applet}' is a client/non-listener "
                        f"by default and no listen flag/config evidence was "
                        f"found")
                else:
                    c.evidence.append(
                        f"multicall binary {real_rel}; applet-level socket "
                        f"imports unavailable (whole-binary import union "
                        f"not used as evidence)")
        if c.kind == "daemon" and not svc and c.drop_reason is None:
            # unknown daemons only survive on server-socket import evidence
            if not c.path:
                c.drop_reason = ("referenced by init/config but binary not "
                                 "found in the rootfs")
            elif not _is_elf(rootfs / c.path):
                c.drop_reason = ("referenced as a daemon but not an ELF "
                                 "binary (script/config?)")
            elif c.multicall:
                # unknown applet: the import union says nothing about it
                c.drop_reason = ("unknown busybox applet without per-applet "
                                 "socket/port evidence")
            else:
                _, undef = elfchain.elf_facts(rootfs / c.path)
                server_hits = set(undef) & _SERVER_SYMS
                if "bind" not in undef or not server_hits:
                    if not undef:
                        c.drop_reason = ("statically linked or unreadable "
                                         "ELF — server-socket imports "
                                         "unverifiable")
                    else:
                        c.drop_reason = ("no server-socket imports "
                                         "(bind + accept/recvfrom)")
                else:
                    ev = ("unknown daemon with server socket imports: "
                          + ",".join(sorted(set(undef) &
                                            elfchain.SOCKET_SYMS)))
                    if ev not in c.evidence:
                        c.evidence.append(ev)
        if c.transport is None:
            c.transport = svc.get("transport", "tcp")
        if c.port is None:
            ports = svc.get("ports") or []
            if ports:
                c.port = ports[0]
                c.port_source = c.port_source or "default"
        # no bind evidence -> address stays null (never defaulted to 0.0.0.0)
        if svc.get("protocol"):
            c.protocol = svc["protocol"]
        elif not c.protocol:
            c.protocol = "tcp" if c.transport == "tcp" else "udp"
        # evidence grading
        if c.evidence_grade is None:
            if c.svc is None:
                c.evidence_grade = "candidate"
            elif c.port_source == "observed":
                c.evidence_grade = "observed"
            elif c.has_config:
                c.evidence_grade = "config"
            else:
                c.evidence_grade = "kb_default"
        c.needs_confirmation = c.evidence_grade in ("kb_default", "candidate")
        out.append(c)

    # deterministic order before merging; excluded-by-design daemons
    # (loopback-only / infrastructure) never take part in merging — folding
    # them into a public listener would corrupt both entries
    out.sort(key=lambda c: (c.port or 0, c.name))

    def _excludable(c):
        s = c.svc or {}
        return bool(s.get("not_public") or s.get("loopback_only")) \
            or c.transport == "unix"

    _GRADE_RANK = {"observed": 0, "config": 1, "kb_default": 2,
                   "candidate": 3, None: 9}
    merged = {}
    passthrough = []
    for c in out:
        if c.drop_reason is not None:
            # promotion/config-disabled failures stay visible individually
            passthrough.append(c)
            continue
        if c.kind == "daemon" and _excludable(c):
            passthrough.append(c)
            continue
        if c.kind == "daemon" and c.port is not None:
            # merge aliases of the same listener (netatalk/afpd, ...)
            key = (c.protocol, c.port, c.transport)
        elif c.kind == "daemon":
            # unknown-port daemons never merge — two different services
            # would otherwise collapse into one phantom entry
            key = (c.kind, c.name)
        else:
            key = (c.kind, c.name)
        if key in merged:
            m = merged[key]
            for ep in c.endpoints:
                if ep not in m.endpoints:
                    m.endpoints.append(ep)
            if c.path and c.path != m.path and c.path not in m.endpoints:
                m.endpoints.append(c.path)
            m.evidence.extend(e for e in c.evidence if e not in m.evidence)
            m.autostart = m.autostart or c.autostart
            m.has_config = m.has_config or c.has_config
            m.multicall = m.multicall or c.multicall
            for note in c.auth_posture:
                if note not in m.auth_posture:
                    m.auth_posture.append(note)
            for p_ in c.extra_ports:
                if p_ not in m.extra_ports:
                    m.extra_ports.append(p_)
            if _GRADE_RANK.get(c.evidence_grade, 9) < \
                    _GRADE_RANK.get(m.evidence_grade, 9):
                m.evidence_grade = c.evidence_grade
            if c.port_source == "observed":
                m.port_source = "observed"
            m.needs_confirmation = \
                m.evidence_grade in ("kb_default", "candidate")
            if not m.path and c.path:
                m.path = c.path
        else:
            merged[key] = c
    return sorted([*merged.values(), *passthrough],
                  key=lambda c: (c.kind != "daemon", c.port or 0, c.name))
