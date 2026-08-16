"""Known network-service knowledge base for external-input identification.

Each entry describes a daemon that can accept external input:
  names        binary / config basenames that identify the service
  protocol     human protocol label (as reported in identification.json)
  ports        default listening ports
  transport    tcp / udp
  input_types  user-controllable input categories for this service
  loopback_only  True -> daemon conventionally binds loopback only
                 (excluded from the public attack surface by gate 1)
  not_public   True -> infrastructure/control daemon that is not part of
                 the public network attack surface (VPN server, Wi-Fi AP,
                 port-forward helpers...); excluded with a reason

The table is deliberately conservative: unknown daemons still get an entry
via the generic fallback in discover.py, this table only refines knowledge
for services we actually recognise.
"""

# fmt: off
SERVICES = [
    # --- web ---
    {"names": ["httpd", "nginx", "apache", "apache2", "lighttpd", "thttpd",
               "mini_httpd", "boa", "goahead", "webs", "appweb", "civetweb"],
     "protocol": "http", "ports": [80], "transport": "tcp",
     "input_types": ["URL path", "query string parameters", "HTTP headers",
                     "cookies", "POST body", "multipart form data"]},
    {"names": ["uhttpd"],
     "protocol": "http", "ports": [80], "transport": "tcp",
     "input_types": ["URL path", "query string parameters", "HTTP headers",
                     "cookies", "POST body (ubus RPC / CGI)"]},
    {"names": ["ssl.httpd", "httpsd", "stunnel", "lighttpd-ssl"],
     "protocol": "https", "ports": [443], "transport": "tcp",
     "input_types": ["URL path", "query string parameters", "HTTP headers",
                     "cookies", "POST body", "multipart form data"]},
    {"names": ["synoscgi", "synocgid"],
     "protocol": "http", "ports": [5000, 5001], "transport": "tcp",
     "not_public": True,
     "input_types": ["CGI request parameters"]},
    {"names": ["webapi", "synowebapi", "webman"],
     "protocol": "https", "ports": [5001], "transport": "tcp",
     "input_types": ["URL path", "query string parameters", "HTTP headers",
                     "cookies", "POST body", "SYNO API (api/method/version)"]},
    # --- remote access ---
    {"names": ["sshd", "dropbear", "openssh"],
     "protocol": "ssh", "ports": [22], "transport": "tcp",
     "input_types": ["SSH handshake/KEX", "auth credentials",
                     "SSH channel requests (exec/sftp/port-forward)"]},
    {"names": ["telnetd", "utelnetd"],
     "protocol": "telnet", "ports": [23], "transport": "tcp",
     "input_types": ["telnet IAC negotiation", "login credentials",
                     "shell command lines"]},
    {"names": ["vsftpd", "pure-ftpd", "proftpd", "ftpd", "bftpd", "tnftpd"],
     "protocol": "ftp", "ports": [21], "transport": "tcp",
     "input_types": ["FTP commands (USER/PASS/RETR/STOR/...)",
                     "file paths", "PASV/PORT data connection"]},
    # --- name / discovery ---
    {"names": ["dnsmasq", "named", "bind9", "unbound", "pdnsd"],
     "protocol": "dns", "ports": [53], "transport": "udp",
     "input_types": ["DNS query packets", "DNS zone data",
                     "dynamic DNS updates"]},
    {"names": ["dnrd"],
     "protocol": "dns", "ports": [53], "transport": "udp",
     "input_types": ["DNS query packets",
                     "upstream DNS relay responses"]},
    {"names": ["avahi-daemon", "avahi", "mdnsd", "mDNSResponder"],
     "protocol": "mDNS/Bonjour", "ports": [5353], "transport": "udp",
     "input_types": ["mDNS query packets", "mDNS query/response records",
                     "DNS-SD records", "service discovery queries"]},
    {"names": ["miniupnpd", "upnpd", "igd", "miniigd"],
     "protocol": "SSDP/UPnP", "ports": [1900, 5000], "transport": "udp",
     "input_types": ["SSDP M-SEARCH/NOTIFY packets",
                     "SOAP actions (WANIPConnection)",
                     "GENA event subscriptions"]},
    {"names": ["minissdpd"],
     "protocol": "SSDP", "ports": [1900], "transport": "udp",
     "input_types": ["SSDP M-SEARCH/NOTIFY packets",
                     "minissdpd control socket requests"]},
    {"names": ["wsdd", "wsdd2", "ws-discovery", "synowsdiscoveryd"],
     "protocol": "WS-Discovery", "ports": [3702], "transport": "udp",
     "input_types": ["WS-Discovery Probe/Resolve SOAP messages"]},
    {"names": ["lldpd"],
     "protocol": "LLDP", "ports": [], "transport": "raw",
     "input_types": ["LLDP TLV frames"]},
    {"names": ["synology-findd", "findd", "synoassistant", "syno-discovery",
               "findhostd"],
     "protocol": "Synology Assistant discovery", "ports": [9999, 9998],
     "transport": "udp",
     "input_types": ["discovery broadcast packets", "device info queries"]},
    {"names": ["synorelayd", "synology-relay"],
     "protocol": "synology-relay", "ports": [443], "transport": "tcp",
     "input_types": ["QuickConnect relay protocol frames",
                     "relay session registration"]},
    # --- file sharing ---
    {"names": ["smbd", "samba", "winbindd", "synowstransferd"],
     "protocol": "SMB/CIFS", "ports": [445, 139], "transport": "tcp",
     "input_types": ["SMB2/SMB3 requests (negotiate/session/tree/IOCTL)",
                     "SMB1AndX commands", "named pipe RPC (srvsvc/wkssvc)",
                     "file paths and ACLs"]},
    {"names": ["nmbd"],
     "protocol": "NetBIOS-NS", "ports": [137, 138], "transport": "udp",
     "input_types": ["NetBIOS name queries", "datagram service messages"]},
    {"names": ["afpd", "netatalk"],
     "protocol": "AFP (Netatalk)", "ports": [548], "transport": "tcp",
     "input_types": ["AFP commands (login/open fork/read/write)",
                     "DSI session packets", "file paths / CNIDs"]},
    {"names": ["nfsd", "unfsd", "ganesha.nfsd"],
     "protocol": "nfs", "ports": [2049], "transport": "tcp",
     "input_types": ["NFS RPC calls (LOOKUP/READ/WRITE/READDIR)",
                     "file handles"]},
    {"names": ["rpcbind", "portmap"],
     "protocol": "SUN RPC portmapper", "ports": [111], "transport": "tcp",
     "input_types": ["portmap lookup (PMAPPROC_GETPORT)",
                     "RPC program/version registrations",
                     "indirect RPC calls"]},
    {"names": ["mountd", "rpc.mountd"],
     "protocol": "sunrpc", "ports": [892], "transport": "tcp",
     "input_types": ["MOUNT protocol RPC (MNT/UMNT/EXPORT)",
                     "export paths"]},
    {"names": ["statd", "rpc.statd"],
     "protocol": "sunrpc", "ports": [662], "transport": "tcp",
     "input_types": ["NSM stat/notify RPC"]},
    {"names": ["rsyncd"],
     "protocol": "rsync", "ports": [873], "transport": "tcp",
     "input_types": ["rsync module listing", "file list protocol",
                     "module paths and filters"]},
    {"names": ["tftpd", "in.tftpd", "atftpd", "dnsmasq-tftp", "opentftp"],
     "protocol": "TFTP", "ports": [69], "transport": "udp",
     "input_types": ["TFTP RRQ/WRQ packets", "filenames", "block data"]},
    # --- infra ---
    {"names": ["snmpd", "net-snmpd", "mini_snmpd"],
     "protocol": "snmp", "ports": [161], "transport": "udp",
     "input_types": ["SNMP GET/GETNEXT/GETBULK/SET PDUs",
                     "community strings", "OID walks", "SNMPv3 USM auth"]},
    {"names": ["ntpd", "chronyd", "openntpd", "busybox-ntpd"],
     "protocol": "NTP", "ports": [123], "transport": "udp",
     "input_types": ["NTP client packets (mode 3/4)",
                     "monlist/mode 6-7 control queries"]},
    {"names": ["cups-lpd"],
     "protocol": "IPP (CUPS LPD)", "ports": [515], "transport": "tcp",
     "input_types": ["LPD print jobs (receive job/control file/data file)"]},
    {"names": ["cupsd", "cups"],
     "protocol": "IPP (CUPS)", "ports": [631], "transport": "tcp",
     "input_types": ["IPP operations (Print-Job/Create-Job/Get-Printers)",
                     "printer attributes", "PPD filters input"]},
    {"names": ["slapd", "openldap"],
     "protocol": "LDAP", "ports": [389], "transport": "tcp",
     "input_types": ["LDAP bind/search/modify requests",
                     "DNs and filters", "SASL mechanisms"]},
    {"names": ["upsd", "nut"],
     "protocol": "NUT (Network UPS Tools)", "ports": [3493], "transport": "tcp",
     "input_types": ["NUT protocol commands (GET/SET/INSTCMD/FSD)",
                     "UPS variable names", "login credentials"]},
    {"names": ["syslogd", "rsyslogd", "syslog-ng"],
     "protocol": "syslog", "ports": [514], "transport": "udp",
     "input_types": ["syslog messages (PRI/header/MSG)",
                     "remote log injection"]},
    {"names": ["usbipd"],
     "protocol": "USB/IP", "ports": [3240], "transport": "tcp",
     "input_types": ["USBIP OP_REQ_IMPORT/URB submit packets",
                     "USB descriptor data"]},
    {"names": ["mosquitto", "mqttd"],
     "protocol": "MQTT", "ports": [1883, 8883], "transport": "tcp",
     "input_types": ["MQTT CONNECT/PUBLISH/SUBSCRIBE packets",
                     "topics and payloads", "will messages"]},
    {"names": ["redis-server", "redis"],
     "protocol": "redis", "ports": [6379], "transport": "tcp",
     "loopback_only": True,
     "input_types": ["RESP commands"]},
    {"names": ["postgres", "postmaster"],
     "protocol": "postgresql", "ports": [5432], "transport": "tcp",
     "loopback_only": True,
     "input_types": ["Postgres wire protocol"]},
    {"names": ["mysqld", "mariadbd"],
     "protocol": "mysql", "ports": [3306], "transport": "tcp",
     "loopback_only": True,
     "input_types": ["MySQL wire protocol"]},
    {"names": ["dbus-daemon"],
     "protocol": "dbus", "ports": [], "transport": "unix",
     "loopback_only": True,
     "input_types": ["D-Bus messages (system bus)"]},
    {"names": ["saslauthd"],
     "protocol": "sasl", "ports": [], "transport": "unix",
     "loopback_only": True,
     "input_types": ["SASL auth requests"]},
    # --- excluded-by-default infrastructure (not public attack surface) ---
    {"names": ["openvpn", "openvpn-server"],
     "protocol": "openvpn", "ports": [1194], "transport": "udp",
     "not_public": True, "input_types": ["VPN tunnel packets"]},
    {"names": ["xl2tpd"],
     "protocol": "l2tp", "ports": [1701], "transport": "udp",
     "not_public": True, "input_types": ["L2TP control messages"]},
    {"names": ["pppd", "pptpd", "pptp", "pppoe-server", "pppdv2", "ppoed"],
     "protocol": "pptp/ppp", "ports": [1723], "transport": "tcp",
     "not_public": True, "input_types": ["PPP/PPTP session data"]},
    {"names": ["hostapd", "wpa_supplicant"],
     "protocol": "802.11", "ports": [], "transport": "raw",
     "not_public": True, "input_types": ["Wi-Fi management frames"]},
    {"names": ["natpmpd", "nat-pmp"],
     "protocol": "NAT-PMP", "ports": [5351], "transport": "udp",
     "not_public": True, "input_types": ["NAT-PMP mapping requests"]},
    {"names": ["iscsid", "iscsiuio"],
     "protocol": "iscsi", "ports": [3260], "transport": "tcp",
     "not_public": True, "input_types": ["iSCSI PDUs"]},
    {"names": ["tgtd", "iscsitarget", "ietd", "iscsitrg", "targetd"],
     "protocol": "iscsi", "ports": [3260], "transport": "tcp",
     "input_types": ["iSCSI PDUs (login/text/SCSI commands)",
                     "CHAP credentials", "target/LUN addressing"]},
]
# fmt: on

# busybox applets that are pure clients or non-listeners. Promoting them to
# public inputs from name knowledge alone produces phantom entries — e.g.
# busybox syslogd only reads /dev/log (its -R/-L flags make it a log
# *client*), udhcpc/ntpc are pure clients. A multicall symlink named after
# one of these is never promoted without explicit listen-flag/config
# evidence.
NON_LISTENING_BUSYBOX_APPLETS = frozenset({
    "syslogd", "klogd", "logread", "udhcpc", "udhcpc6", "ntpc", "ntpdate",
    "rdate", "zcip", "pump", "ftpget", "ftpput", "tftp", "telnet", "wget",
    "nslookup", "arping",
})

# loopback / non-public bind addresses (gate 1)
LOOPBACK_ADDRS = {"127.0.0.1", "127.0.1.1", "::1", "localhost",
                  "localhost.localdomain"}
WILDCARD_ADDRS = {"", "0.0.0.0", "::", "*", "0", "any"}


def _norm_name(name):
    base = name.rsplit("/", 1)[-1].lower()
    for suffix in (".bin", ".sh", ".elf"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def lookup(name):
    """Return the first service entry whose names match this binary/config
    basename, else None."""
    base = _norm_name(name)
    for svc in SERVICES:
        if base in svc["names"]:
            return svc
    # substring fallback for versioned names like nginx-1.2 or smbd-foo
    for svc in SERVICES:
        for n in svc["names"]:
            if len(n) >= 4 and (base.startswith(n + "-") or
                                base.startswith(n + ".")):
                return svc
    # underscore variants: helper/monitor names like dnrd_monitor or
    # miniupnpd_dbg carry the daemon name as an underscore prefix
    if "_" in base:
        parts = base.split("_")
        for cut in range(len(parts) - 1, 0, -1):
            prefix = "_".join(parts[:cut])
            if len(prefix) < 4:
                continue
            for svc in SERVICES:
                if prefix in svc["names"]:
                    return svc
    return None


def is_public_address(address):
    """Gate 1: an input is public only if it is not bound to loopback."""
    if address is None:
        return True  # unknown bind -> default wildcard behaviour
    addr = str(address).strip().strip("[]").lower()
    if addr in LOOPBACK_ADDRS:
        return False
    if addr.startswith("127.") or addr.startswith("::ffff:127."):
        return False
    return True
