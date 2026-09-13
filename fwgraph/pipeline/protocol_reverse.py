"""Firmware-bound protocol reverse: identify, classify crypto, decode pasted traffic.

This module only reads already-extracted artifacts and user-pasted bytes.
It does not talk to the network, recover session keys, or break ciphertext.
"""

from __future__ import annotations

import base64
import json
import re
from collections import Counter
from pathlib import Path


MAX_DECODE_BYTES = 65536
MAX_FUNCTIONS = 80
MAX_DEEP = 12
MAX_SOURCE_CHARS = 24000

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{6,48}-----", re.IGNORECASE)
_LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")

PLAINTEXT = {
    "http", "telnet", "ftp", "tftp", "smtp", "pop3", "imap",
    "ssdp", "ssdp/upnp", "mdns/bonjour", "ws-discovery",
}
WEAK_ALGOS = {"md5", "des", "rc4"}
LEGACY_ALGOS = {"sha1", "3des"}

FAMILY_OF = {
    "http": "Web", "https": "Web", "ssl.httpd": "Web",
    "ssh": "远程访问", "telnet": "远程访问",
    "ftp": "文件传输", "tftp": "文件传输", "smb": "文件传输",
    "dns": "名称解析", "mdns/bonjour": "发现",
    "ssdp/upnp": "发现", "ssdp": "发现", "ws-discovery": "发现",
    "dhcp": "地址分配", "dhcp6": "地址分配",
    "mqtt": "消息", "coap": "消息",
    "modbus": "工控", "s7": "工控", "opcua": "工控", "dnp3": "工控",
    "udp": "自定义", "tcp": "自定义",
}

FAMILY_COLOR = {
    "Web": "#22d3ee",
    "远程访问": "#f472b6",
    "文件传输": "#fbbf24",
    "名称解析": "#a78bfa",
    "发现": "#34d399",
    "地址分配": "#38bdf8",
    "消息": "#c084fc",
    "工控": "#fb923c",
    "自定义": "#64748b",
}

ALGORITHMS = (
    {
        "id": "aes", "label": "AES", "family": "对称加密", "strength": "modern",
        "patterns": (r"(?<![a-z0-9])aes(?:[_-]?\d{0,3})?(?![a-z0-9])", r"rijndael"),
    },
    {
        "id": "des", "label": "DES", "family": "对称加密", "strength": "weak",
        "patterns": (
            r"(?<![a-z0-9])des_(?:en|de)crypt(?![a-z0-9])",
            r"(?<![a-z0-9])des_set_key(?![a-z0-9])",
            r"(?<![a-z0-9])des_(?:ecb|cbc)(?![a-z0-9])",
            r"(?<![a-z0-9])desencrypt(?![a-z0-9])",
            r"(?<![a-z0-9])desdecrypt(?![a-z0-9])",
        ),
    },
    {
        "id": "3des", "label": "3DES", "family": "对称加密", "strength": "legacy",
        "patterns": (r"(?<![a-z0-9])(?:3des|des3|triple_?des)(?![a-z0-9])",),
    },
    {
        "id": "rc4", "label": "RC4", "family": "对称加密", "strength": "weak",
        "patterns": (r"(?<![a-z0-9])(?:rc4|arc4)(?![a-z0-9])",),
    },
    {
        "id": "chacha", "label": "ChaCha20", "family": "对称加密", "strength": "modern",
        "patterns": (r"chacha(?:20)?", r"poly1305"),
    },
    {
        "id": "blowfish", "label": "Blowfish", "family": "对称加密", "strength": "legacy",
        "patterns": (r"blowfish", r"(?<![a-z0-9])bf_(?:ecb|cbc|encrypt)"),
    },
    {
        "id": "tea", "label": "TEA/XTEA", "family": "对称加密", "strength": "legacy",
        "patterns": (r"(?<![a-z0-9])(?:xxtea|xtea|tea_encrypt|tea_decrypt)(?![a-z0-9])",),
    },
    {
        "id": "rsa", "label": "RSA", "family": "非对称", "strength": "modern",
        "patterns": (r"(?<![a-z0-9])rsa(?![a-z0-9])",),
    },
    {
        "id": "ecc", "label": "ECC/ECDSA", "family": "非对称", "strength": "modern",
        "patterns": (r"ecdsa", r"ecdh", r"curve25519", r"(?<![a-z0-9])ecc(?![a-z0-9])"),
    },
    {
        "id": "dh", "label": "Diffie-Hellman", "family": "密钥交换", "strength": "modern",
        "patterns": (r"diffie.?hellman", r"(?<![a-z0-9])dh_(?:compute|generate|key)"),
    },
    {
        "id": "md5", "label": "MD5", "family": "哈希", "strength": "weak",
        "patterns": (r"(?<![a-z0-9])md5(?![a-z0-9])",),
    },
    {
        "id": "sha1", "label": "SHA-1", "family": "哈希", "strength": "legacy",
        "patterns": (r"(?<![a-z0-9])sha[-_]?1(?![a-z0-9])",),
    },
    {
        "id": "sha256", "label": "SHA-256", "family": "哈希", "strength": "modern",
        "patterns": (r"(?<![a-z0-9])sha[-_]?256(?![a-z0-9])", r"(?<![a-z0-9])sha2(?![a-z0-9])"),
    },
    {
        "id": "hmac", "label": "HMAC", "family": "消息认证", "strength": "modern",
        "patterns": (r"(?<![a-z0-9])hmac(?![a-z0-9])",),
    },
    {
        "id": "pbkdf", "label": "PBKDF/KDF", "family": "密钥派生", "strength": "modern",
        "patterns": (r"pbkdf2?", r"hkdf", r"scrypt"),
    },
    {
        "id": "tls", "label": "TLS/SSL", "family": "协议栈", "strength": "modern",
        "patterns": (
            r"(?<![a-z0-9])(?:tlsv?\d*|ssl|openssl|mbedtls|wolfssl)(?![a-z0-9])",
        ),
    },
    {
        "id": "base64", "label": "Base64", "family": "编码", "strength": "none",
        "patterns": (r"base64",),
    },
    {
        "id": "crc", "label": "CRC", "family": "校验", "strength": "none",
        "patterns": (r"(?<![a-z0-9])crc(?:16|32)?(?![a-z0-9])",),
    },
)

_ALGO_COMPILED = tuple(
    {
        **algo,
        "rx": [re.compile(p, re.IGNORECASE) for p in algo["patterns"]],
    }
    for algo in ALGORITHMS
)

_CONSTANTS = (
    ("AES S-box", re.compile(r"0x63,\s*0x7c,\s*0x77,\s*0x7b", re.I)),
    ("MD5/SHA 初始向量", re.compile(r"0x67452301", re.I)),
    ("TEA delta", re.compile(r"0x9e3779b9", re.I)),
    ("CRC32 多项式", re.compile(r"0xedb88320", re.I)),
    ("AES Rcon", re.compile(r"0x01000000.*0x02000000", re.I)),
)

_MODE_RX = (
    ("ECB", re.compile(r"\becb\b", re.I)),
    ("CBC", re.compile(r"\bcbc\b", re.I)),
    ("CTR", re.compile(r"\bctr\b", re.I)),
    ("GCM", re.compile(r"\bgcm\b", re.I)),
    ("CFB", re.compile(r"\bcfb\b", re.I)),
    ("OFB", re.compile(r"\bofb\b", re.I)),
)

_KEYLEN_RX = re.compile(
    r"(?:aes[-_ ]?)?(128|192|256)\s*(?:bit)?", re.I)

STRENGTH_LABEL = {
    "weak": "弱",
    "legacy": "过时",
    "modern": "现行",
    "none": "非密码",
    "depends": "视用法",
}


_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def parse_payload(text: str) -> bytes:
    compact = re.sub(r"\s+", "", text or "")
    if not compact:
        raise ValueError("请先粘贴报文")
    if _HEX_RE.fullmatch(compact):
        if len(compact) % 2:
            raise ValueError("十六进制长度必须为偶数")
        data = bytes.fromhex(compact)
    elif _B64_RE.fullmatch(compact) and len(compact) >= 4:
        pad = (-len(compact)) % 4
        try:
            data = base64.b64decode(compact + ("=" * pad), validate=True)
        except Exception as exc:
            raise ValueError("既不是偶数位十六进制，也不是 Base64") from exc
        if not data:
            raise ValueError("Base64 解码结果为空")
    else:
        raise ValueError("既不是偶数位十六进制，也不是 Base64")
    if len(data) > MAX_DECODE_BYTES:
        raise ValueError(f"报文超过 {MAX_DECODE_BYTES} 字节上限")
    return data


def _ascii_preview(data: bytes, limit: int = 180) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def _u16(data: bytes, off: int, endian: str = "big") -> int | None:
    if off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], endian)


def _u32(data: bytes, off: int, endian: str = "big") -> int | None:
    if off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], endian)


def _field(name, offset, length, value, note=""):
    return {
        "name": name,
        "offset": offset,
        "length": length,
        "value": value,
        "note": note,
    }


def _hex_head(data: bytes, n: int = 32) -> str:
    return " ".join(f"{b:02x}" for b in data[:n])


def decode_traffic(data: bytes) -> dict:
    """Field-level decode of a single pasted datagram / stream slice."""
    ascii_ = _ascii_preview(data)
    fields: list[dict] = []
    notes: list[str] = []
    proto = "unknown"
    label = "未匹配已知明文协议"
    confidence = 0.2
    encrypted = False
    summary = ""

    if not data:
        return {
            "protocol": "empty", "label": "空报文", "confidence": 0,
            "length": 0, "ascii": "", "hex_head": "", "fields": [],
            "summary": "没有字节可解码。", "encrypted": False, "notes": [],
        }

    upper = ascii_.upper()
    if (data.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"HTTP/",
                         b"DELETE ", b"OPTIONS ", b"PATCH ", b"M-SEARCH ",
                         b"NOTIFY ", b"SUBSCRIBE "))
            or upper.startswith("HTTP/")):
        proto = "ssdp" if data.startswith((b"M-SEARCH ", b"NOTIFY ",
                                           b"SUBSCRIBE ")) else "http"
        label = "SSDP / UPnP 明文" if proto == "ssdp" else "HTTP 明文"
        confidence = 0.95
        lines = data.split(b"\r\n") if b"\r\n" in data else data.split(b"\n")
        start = lines[0].decode("ascii", "replace")[:200]
        fields.append(_field("起始行", 0, min(len(lines[0]), len(data)),
                             start, "请求或状态行"))
        off = len(lines[0]) + (2 if b"\r\n" in data else 1)
        for raw in lines[1:12]:
            if not raw:
                break
            text = raw.decode("latin-1", "replace")[:160]
            fields.append(_field("头字段", off, len(raw), text))
            off += len(raw) + (2 if b"\r\n" in data else 1)
        summary = start
    elif len(data) >= 5 and data[0] in (0x14, 0x15, 0x16, 0x17) and data[1] == 0x03:
        rec = {0x14: "ChangeCipherSpec", 0x15: "Alert",
               0x16: "Handshake", 0x17: "ApplicationData"}.get(data[0], "Record")
        ver = f"TLS 1.{data[2] - 1}" if data[2] in (1, 2, 3, 4) else f"0x03{data[2]:02x}"
        length = _u16(data, 3) or 0
        proto = "tls"
        label = f"TLS 记录（{rec}）"
        confidence = 0.92
        encrypted = data[0] == 0x17
        fields.extend([
            _field("记录类型", 0, 1, f"0x{data[0]:02x}", rec),
            _field("版本", 1, 2, ver),
            _field("长度", 3, 2, str(length)),
        ])
        if data[0] == 0x16 and len(data) >= 6:
            hs = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
                  16: "ClientKeyExchange"}.get(data[5], f"0x{data[5]:02x}")
            fields.append(_field("握手类型", 5, 1, hs))
            summary = f"{ver} {rec} / {hs}"
        else:
            summary = f"{ver} {rec}，应用数据不在此解密"
            notes.append("TLS 应用数据需要会话密钥，本页只拆记录头。")
    elif data.startswith(b"SSH-"):
        proto, label, confidence = "ssh", "SSH 横幅", 0.97
        banner = data.split(b"\n", 1)[0].decode("ascii", "replace").strip()
        fields.append(_field("横幅", 0, len(banner), banner))
        summary = banner
    elif (len(data) >= 240 and data[236:240] == b"\x63\x82\x53\x63"):
        proto, label, confidence = "dhcp", "DHCP / BOOTP", 0.93
        op = {1: "BOOTREQUEST", 2: "BOOTREPLY"}.get(data[0], str(data[0]))
        xid = _u32(data, 4)
        fields.extend([
            _field("op", 0, 1, op),
            _field("htype", 1, 1, str(data[1])),
            _field("xid", 4, 4, f"0x{xid:08x}" if xid is not None else ""),
            _field("magic", 236, 4, "63 82 53 63", "DHCP magic cookie"),
        ])
        summary = f"DHCP {op}"
    elif (len(data) >= 8 and _u16(data, 2) == 0 and 0 < (_u16(data, 4) or 0) < 260):
        proto, label, confidence = "modbus", "Modbus TCP", 0.88
        tid, proto_id, length = _u16(data, 0), _u16(data, 2), _u16(data, 4)
        uid = data[6] if len(data) > 6 else 0
        func = data[7] if len(data) > 7 else 0
        fields.extend([
            _field("事务标识", 0, 2, str(tid)),
            _field("协议标识", 2, 2, str(proto_id), "0 表示 Modbus"),
            _field("长度", 4, 2, str(length)),
            _field("单元标识", 6, 1, str(uid)),
            _field("功能码", 7, 1, f"0x{func:02x}"),
        ])
        summary = f"Modbus 功能 0x{func:02x}"
    elif data[:4] in (b"HELF", b"OPNF", b"MSGF", b"ACKF", b"ERRF"):
        proto, label, confidence = "opcua", "OPC UA 二进制", 0.9
        size = _u32(data, 4, "little")
        fields.append(_field("消息类型", 0, 4, data[:4].decode("ascii", "replace")))
        fields.append(_field("消息长度", 4, 4, str(size), "小端"))
        summary = data[:4].decode("ascii", "replace")
    elif len(data) >= 4 and data[0] == 0x03 and data[1] == 0x00:
        proto, label, confidence = "s7", "S7comm / TPKT", 0.84
        tlen = _u16(data, 2)
        fields.extend([
            _field("TPKT 版本", 0, 1, str(data[0])),
            _field("长度", 2, 2, str(tlen)),
        ])
        summary = "ISO-on-TCP TPKT，后续可能是 COTP/S7"
    elif len(data) >= 2 and data[0] == 0x05 and data[1] == 0x64:
        proto, label, confidence = "dnp3", "DNP3 链路帧", 0.86
        fields.append(_field("起始", 0, 2, "05 64"))
        if len(data) >= 3:
            fields.append(_field("长度", 2, 1, str(data[2])))
        summary = "DNP3 链路层"
    elif data and (data[0] >> 4) == 4 and (data[0] & 0x0F) >= 5 and len(data) >= 20:
        ihl = (data[0] & 0x0F) * 4
        proto_id = data[9]
        names = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto, label, confidence = "ipv4", f"IPv4 / {names.get(proto_id, proto_id)}", 0.8
        fields.extend([
            _field("版本/IHL", 0, 1, f"4 / {ihl}"),
            _field("总长度", 2, 2, str(_u16(data, 2))),
            _field("协议", 9, 1, names.get(proto_id, str(proto_id))),
            _field("源地址", 12, 4, ".".join(str(b) for b in data[12:16])),
            _field("目的地址", 16, 4, ".".join(str(b) for b in data[16:20])),
        ])
        summary = label
    elif data and (data[0] >> 4) == 1 and len(data) >= 4:
        proto, label, confidence = "coap", "CoAP", 0.78
        code = data[1]
        mid = _u16(data, 2)
        fields.extend([
            _field("版本/类型/TKL", 0, 1, f"0x{data[0]:02x}"),
            _field("Code", 1, 1, f"{code >> 5}.{code & 0x1F:02d}"),
            _field("Message ID", 2, 2, str(mid)),
        ])
        summary = f"CoAP {code >> 5}.{code & 0x1F:02d}"
    elif data and (data[0] >> 4) in range(1, 15) and len(data) >= 2:
        # MQTT control packet: type in high nibble, remaining length follows
        mtype = data[0] >> 4
        names = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 8: "SUBSCRIBE",
                 13: "PINGREQ", 14: "DISCONNECT"}
        if mtype in names and data[1] < 128:
            proto, label, confidence = "mqtt", f"MQTT {names[mtype]}", 0.8
            fields.extend([
                _field("类型", 0, 1, names[mtype]),
                _field("标志", 0, 1, f"0x{data[0] & 0x0F:x}"),
                _field("剩余长度", 1, 1, str(data[1])),
            ])
            if mtype == 1 and len(data) >= 8:
                proto_name = data[4:8]
                if proto_name == b"MQTT" or data[2:6] == b"MQTT":
                    fields.append(_field("协议名", 4, 4, "MQTT"))
            summary = label
    if proto == "unknown" and len(data) >= 12:
        qd, an = _u16(data, 4), _u16(data, 6)
        ns, ar = _u16(data, 8), _u16(data, 10)
        flags = _u16(data, 2) or 0
        total_rr = (qd or 0) + (an or 0) + (ns or 0) + (ar or 0)
        opcode = (flags >> 11) & 0xF
        if total_rr <= 40 and opcode <= 5 and (qd or 0) <= 20:
            proto, label, confidence = "dns", "DNS 报文头", 0.7
            fields.extend([
                _field("事务 ID", 0, 2, f"0x{(_u16(data, 0) or 0):04x}"),
                _field("标志", 2, 2, f"0x{flags:04x}",
                       "QR=响应" if flags & 0x8000 else "QR=查询"),
                _field("问题数", 4, 2, str(qd)),
                _field("回答数", 6, 2, str(an)),
            ])
            qname, consumed = _dns_name(data, 12)
            if qname:
                fields.append(_field("QNAME", 12, consumed, qname))
            summary = qname or "DNS 头"

    if proto == "unknown":
        fields.append(_field("原始长度", 0, len(data), str(len(data))))
        notes.append("未匹配已知明文协议，按原始字节展示。")
        summary = f"{len(data)} 字节未识别载荷"

    return {
        "protocol": proto,
        "label": label,
        "confidence": confidence,
        "length": len(data),
        "ascii": ascii_,
        "hex_head": _hex_head(data),
        "fields": fields,
        "summary": summary,
        "encrypted": encrypted,
        "notes": notes,
    }


def _dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    start = offset
    guard = 0
    while offset < len(data) and guard < 16:
        guard += 1
        ln = data[offset]
        if ln == 0:
            offset += 1
            break
        if ln & 0xC0 == 0xC0:
            break
        if offset + 1 + ln > len(data):
            break
        labels.append(data[offset + 1:offset + 1 + ln].decode("ascii", "replace"))
        offset += 1 + ln
    return ".".join(labels), offset - start


def identify_protocols(identification: dict) -> dict:
    inputs = list(identification.get("inputs") or [])
    meta = identification.get("metadata") or {}
    families: Counter = Counter()
    items = []
    for row in inputs:
        proto = str(row.get("protocol") or "unknown").strip() or "unknown"
        key = proto.lower()
        family = FAMILY_OF.get(key, "自定义")
        families[family] += 1
        evidence = str(row.get("evidence") or "")
        grade = "kb" if "kb" in evidence.lower() else (
            "candidate" if evidence else "inferred")
        confidence = 0.86 if grade == "kb" else 0.62 if grade == "candidate" else 0.5
        items.append({
            "id": row.get("id"),
            "protocol": proto,
            "family": family,
            "service": row.get("service") or "",
            "address": row.get("address"),
            "port": row.get("port"),
            "transport": row.get("transport") or "",
            "public": bool(row.get("public")),
            "input_types": list(row.get("input_types") or []),
            "entry_files": list(row.get("entry_files") or [])[:6],
            "binary_md5": row.get("binary_md5"),
            "evidence": evidence[:240],
            "confidence": confidence,
            "plaintext": key in PLAINTEXT,
        })
    proto_counts = Counter((i["protocol"] or "unknown") for i in items)
    return {
        "target": meta.get("target") or "",
        "total": len(items),
        "public": sum(1 for i in items if i["public"]),
        "plaintext": sum(1 for i in items if i["plaintext"]),
        "families": [
            {"key": name, "label": name, "value": n,
             "color": FAMILY_COLOR.get(name, "#64748b")}
            for name, n in families.most_common()
        ],
        "protocol_counts": [
            {"key": name, "label": name, "value": n}
            for name, n in proto_counts.most_common()
        ],
        "items": items,
        "gate_1": meta.get("gate_1") or "",
        "gate_2": meta.get("gate_2") or "",
    }


def _fn_blob(fn: dict) -> str:
    return " ".join([
        str(fn.get("name") or ""),
        str(fn.get("ai_name") or ""),
        str(fn.get("rule_name") or ""),
        " ".join(str(t) for t in (fn.get("tags") or [])),
        " ".join(str(s) for s in (fn.get("strings") or [])[:20]),
    ])


def _role_of(name: str) -> str:
    low = (name or "").lower()
    if re.search(r"decrypt|dec(?:rypt)?\b", low):
        return "解密"
    if re.search(r"encrypt|enc(?:rypt)?\b", low):
        return "加密"
    if re.search(r"hmac|cmac", low):
        return "消息认证"
    if re.search(r"sign", low):
        return "签名"
    if re.search(r"verify", low):
        return "校验"
    if re.search(r"digest|hash|md5|sha", low):
        return "摘要"
    if re.search(r"set_?key|key_?expand|schedule|init", low):
        return "密钥编排"
    return "实现"


def _modes_of(blob: str) -> list[str]:
    return [name for name, rx in _MODE_RX if rx.search(blob)]


def _keylen_of(blob: str) -> list[str]:
    found = []
    for m in _KEYLEN_RX.finditer(blob):
        bits = m.group(1)
        tag = f"{bits} bit"
        if tag not in found:
            found.append(tag)
    return found[:3]


def identify_crypto(symbols: dict) -> dict:
    algos = {
        spec["id"]: {
            "id": spec["id"],
            "label": spec["label"],
            "family": spec["family"],
            "strength": spec["strength"],
            "strength_label": STRENGTH_LABEL[spec["strength"]],
            "count": 0,
            "binaries": set(),
        }
        for spec in _ALGO_COMPILED
    }
    functions = []
    materials = []
    seen = set()
    for md5, info in (symbols.get("binaries") or {}).items():
        path = info.get("path") or ""
        for fn in info.get("functions") or []:
            blob = _fn_blob(fn)
            hit_ids = []
            for spec in _ALGO_COMPILED:
                if any(rx.search(blob) for rx in spec["rx"]):
                    hit_ids.append(spec["id"])
                    rec = algos[spec["id"]]
                    rec["count"] += 1
                    rec["binaries"].add(md5)
            if not hit_ids:
                for s in fn.get("strings") or []:
                    text = str(s)
                    if _PEM_RE.search(text) or (
                            _LONG_HEX_RE.search(text) and "BEGIN" in text.upper()):
                        materials.append({
                            "kind": "PEM 形态",
                            "preview": text[:72],
                            "name": fn.get("name"),
                            "addr": fn.get("addr"),
                            "binary": md5,
                            "path": path,
                        })
                continue
            key = f"{md5}:{fn.get('addr')}"
            if key in seen:
                continue
            seen.add(key)
            name = fn.get("name") or fn.get("ai_name") or fn.get("addr")
            row = {
                "name": name,
                "ai_name": fn.get("ai_name") or "",
                "addr": fn.get("addr"),
                "binary": md5,
                "path": path,
                "size": fn.get("size") or 0,
                "algos": hit_ids,
                "role": _role_of(str(name)),
                "modes": _modes_of(blob),
                "key_lengths": _keylen_of(blob),
                "strings": [str(s)[:80] for s in (fn.get("strings") or [])[:6]],
                "on_attack_path": bool(fn.get("on_attack_path")),
                "observed_in_trace": bool(fn.get("observed_in_trace")),
                "asrc": list(fn.get("asrc") or []),
                "asink": list(fn.get("asink") or []),
                "decompile_ok": bool(fn.get("decompile_ok")),
            }
            functions.append(row)
            for s in fn.get("strings") or []:
                text = str(s)
                if _PEM_RE.search(text):
                    materials.append({
                        "kind": "PEM 形态",
                        "preview": text[:72],
                        "name": name,
                        "addr": fn.get("addr"),
                        "binary": md5,
                        "path": path,
                    })
                elif _LONG_HEX_RE.fullmatch(text.strip()) and len(text.strip()) >= 32:
                    materials.append({
                        "kind": "长十六进制串",
                        "preview": text.strip()[:64],
                        "name": name,
                        "addr": fn.get("addr"),
                        "binary": md5,
                        "path": path,
                    })
    functions.sort(
        key=lambda r: (
            0 if r["on_attack_path"] else 1,
            0 if r["observed_in_trace"] else 1,
            -len(r["algos"]),
            r["name"] or "",
        )
    )
    algo_list = []
    for spec in _ALGO_COMPILED:
        rec = algos[spec["id"]]
        if rec["count"] <= 0:
            continue
        algo_list.append({
            "id": rec["id"],
            "label": rec["label"],
            "family": rec["family"],
            "strength": rec["strength"],
            "strength_label": rec["strength_label"],
            "count": rec["count"],
            "binaries": len(rec["binaries"]),
        })
    return {
        "algorithms": algo_list,
        "functions": functions[:MAX_FUNCTIONS],
        "function_total": len(functions),
        "materials": materials[:30],
        "weak": [a for a in algo_list if a["strength"] == "weak"],
        "legacy": [a for a in algo_list if a["strength"] == "legacy"],
    }


def deepen_crypto(crypto: dict, symbols: dict, source_dir: Path | None = None) -> list[dict]:
    by_key = {}
    for md5, info in (symbols.get("binaries") or {}).items():
        for fn in info.get("functions") or []:
            by_key[(md5, str(fn.get("addr") or "").lower())] = fn
    deep = []
    for row in (crypto.get("functions") or [])[:MAX_DEEP]:
        fn = by_key.get((row["binary"], str(row.get("addr") or "").lower()), {})
        blob = _fn_blob(fn) if fn else " ".join(row.get("strings") or [])
        constants = []
        src_head = ""
        if source_dir is not None:
            text = _read_source(source_dir, row["binary"], row.get("addr") or "")
            if text:
                src_head = "\n".join(text.splitlines()[:16])
                for name, rx in _CONSTANTS:
                    if rx.search(text):
                        constants.append(name)
        notes = []
        if row.get("modes"):
            notes.append("工作模式线索：" + "、".join(row["modes"]))
        if row.get("key_lengths"):
            notes.append("密钥长度线索：" + "、".join(row["key_lengths"]))
        if "ECB" in (row.get("modes") or []):
            notes.append("ECB 无完整性、相同明文得到相同密文，评估时优先看鉴权/配置通道。")
        if any(a in WEAK_ALGOS for a in row.get("algos") or []):
            notes.append("命中弱算法实现，不能当作现代完整性或保密性依据。")
        if row.get("on_attack_path"):
            notes.append("该函数落在已计算的攻击路径上。")
        if row.get("observed_in_trace"):
            notes.append("动态覆盖曾经观测到该函数。")
        deep.append({
            **row,
            "constants": constants,
            "notes": notes,
            "source_head": src_head,
            "string_hits": [s for s in (row.get("strings") or []) if s][:6],
            "blob_hint": blob[:160],
        })
    return deep


def reverse_function(fn: dict, source: str, asm: str = "") -> dict:
    name = fn.get("name") or fn.get("ai_name") or fn.get("addr") or "sub"
    blob = (source or "") + "\n" + _fn_blob(fn)
    primitives = []
    for spec in _ALGO_COMPILED:
        if any(rx.search(blob) for rx in spec["rx"]):
            primitives.append({
                "id": spec["id"],
                "label": spec["label"],
                "strength": spec["strength"],
            })
    constants = [label for label, rx in _CONSTANTS if rx.search(source or "")]
    modes = _modes_of(blob)
    calls = []
    seen = set()
    for match in _CALL_RE.findall(source or ""):
        if match in seen or match in {"if", "for", "while", "switch", "return"}:
            continue
        seen.add(match)
        calls.append(match)
        if len(calls) >= 24:
            break
    role = _role_of(str(name))
    bits = []
    if primitives:
        bits.append("识别到 " + "、".join(p["label"] for p in primitives[:4]) + " 相关实现")
    bits.append(f"角色偏向「{role}」")
    if modes:
        bits.append("模式线索 " + "、".join(modes))
    if constants:
        bits.append("源码中出现 " + "、".join(constants))
    if not source:
        bits.append("没有伪 C，只能按符号名判断")
    bits.append("这里只还原实现路径，不对密文做破解，也不导出可用会话密钥")
    return {
        "name": name,
        "addr": fn.get("addr"),
        "role": role,
        "primitives": primitives,
        "modes": modes,
        "key_lengths": _keylen_of(blob),
        "constants": constants,
        "calls": calls,
        "narrative": "；".join(bits) + "。",
        "source": (source or "")[:MAX_SOURCE_CHARS],
        "asm": (asm or "")[:MAX_SOURCE_CHARS],
        "source_truncated": bool(source) and len(source) > MAX_SOURCE_CHARS,
    }


def assess_attack_surface(protocols: dict, crypto: dict,
                          surfaces_summary: dict | None,
                          surface_docs: list[dict] | None,
                          attack_summary: dict | None) -> dict:
    weak_ids = {a["id"] for a in (crypto.get("weak") or [])}
    legacy_ids = {a["id"] for a in (crypto.get("legacy") or [])}
    analysis = (attack_summary or {}).get("analysis") or {}
    net_sources = int((analysis.get("source_counts") or {}).get("network") or 0)
    path_n = int(analysis.get("paths_returned") or 0)
    surf = surfaces_summary or {}
    unresolved = {}
    for doc in surface_docs or []:
        sid = doc.get("surface_id") or doc.get("source_input")
        handler = (doc.get("final_handler") or {}).get("function") or ""
        unresolved[sid] = (not handler) or handler in ("unknown", "（未定位函数）")

    ranked = []
    for item in protocols.get("items") or []:
        score = 12
        reasons = []
        if item.get("public"):
            score += 18
            reasons.append("公网可达")
        if item.get("plaintext"):
            score += 26
            reasons.append("明文协议")
        proto = str(item.get("protocol") or "").lower()
        if proto in {"telnet", "ftp"}:
            score += 10
            reasons.append("口令或文件以明文走线")
        ntypes = len([t for t in item.get("input_types") or []
                      if not str(t).startswith("binary_md5=")])
        if ntypes >= 3:
            score += 8
            reasons.append(f"{ntypes} 类可控输入")
        if unresolved.get(item.get("id")):
            score += 8
            reasons.append("终点 handler 未解析")
        if weak_ids:
            score += 10
            reasons.append("固件含弱算法实现")
        elif legacy_ids:
            score += 4
            reasons.append("固件含过时算法")
        if net_sources >= 20:
            score += 6
            reasons.append("网络源攻击路径较多")
        score = min(100, score)
        level = ("严重" if score >= 80 else "高" if score >= 60
                 else "中" if score >= 40 else "低")
        ranked.append({
            "id": item.get("id"),
            "protocol": item.get("protocol"),
            "service": item.get("service"),
            "port": item.get("port"),
            "public": item.get("public"),
            "score": score,
            "level": level,
            "reasons": reasons,
            "input_types": item.get("input_types") or [],
        })
    ranked.sort(key=lambda r: (-r["score"], r.get("id") or ""))
    overall = 0
    if ranked:
        top = ranked[:5]
        overall = int(round(sum(r["score"] for r in top) / len(top)))
    if weak_ids:
        overall = min(100, overall + 4)
    level = ("严重" if overall >= 80 else "高" if overall >= 60
             else "中" if overall >= 40 else "低")
    public_n = protocols.get("public") or 0
    total = max(1, protocols.get("total") or 0)
    plain_n = protocols.get("plaintext") or 0
    static_only = int(surf.get("static_only") or 0)
    axes = [
        {"key": "expose", "label": "公网暴露",
         "score": min(1.0, public_n / max(1, min(total, 8)))},
        {"key": "plain", "label": "明文协议",
         "score": min(1.0, plain_n / max(1, min(total, 6)))},
        {"key": "weak", "label": "弱算法",
         "score": 1.0 if weak_ids else (0.45 if legacy_ids else 0.1)},
        {"key": "inputs", "label": "输入复杂度",
         "score": min(1.0, sum(len(i.get("input_types") or [])
                               for i in (protocols.get("items") or [])) / 24)},
        {"key": "paths", "label": "路径密度",
         "score": min(1.0, (net_sources / 80) if net_sources else path_n / 40)},
        {"key": "static", "label": "静态未验证",
         "score": min(1.0, static_only / max(1, int(surf.get("surfaces") or 1)))},
    ]
    recs = []
    if any(r["protocol"] and str(r["protocol"]).lower() == "telnet" for r in ranked):
        recs.append("存在 Telnet 入口，口令与命令以明文传输，评估优先级最高。")
    if any(str(r.get("protocol") or "").lower() == "http" and r.get("public")
           for r in ranked):
        recs.append("公网 HTTP 管理面应核对鉴权、命令注入和文件操作路径。")
    if weak_ids:
        recs.append(
            "符号里出现 "
            + "、".join(a["label"] for a in crypto.get("weak") or [])
            + "，若用于鉴权或完整性校验，保护强度不足。"
        )
    if static_only:
        recs.append(f"{static_only} 个攻击面仍是静态推断，终点 handler 未在伪 C 中钉死。")
    if not recs:
        recs.append("当前协议面未见明显明文高危入口，继续对照算法实现与攻击路径即可。")
    recs.append("评估只基于固件识别与已粘贴报文，不会对公网主机做密钥抽取或在线探测。")
    return {
        "score": overall,
        "level": level,
        "axes": axes,
        "ranked": ranked[:40],
        "recommendations": recs,
        "surfaces": int(surf.get("surfaces") or 0),
        "auth_chains": int(surf.get("auth_chains") or 0),
        "static_only": static_only,
        "network_sources": net_sources,
        "paths_returned": path_n,
    }


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_source(source_dir: Path, md5: str, addr: str) -> str:
    funcs = source_dir / md5 / "functions"
    for name in (f"{addr}.c", f"{addr.lower()}.c"):
        cand = funcs / name
        if cand.is_file():
            try:
                return cand.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""
    return ""


def _read_asm(source_dir: Path, md5: str, addr: str) -> str:
    funcs = source_dir / md5 / "functions"
    for name in (f"{addr}.asm", f"{addr.lower()}.asm"):
        cand = funcs / name
        if cand.is_file():
            try:
                return cand.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""
    return ""


def load_surface_docs(surfaces_dir: Path, limit: int = 40) -> list[dict]:
    info = surfaces_dir / "information"
    if not info.is_dir():
        return []
    docs = []
    for path in sorted(info.glob("AS-*.json"))[:limit]:
        doc = _read_json(path)
        if doc:
            docs.append(doc)
    return docs


def build_report(job_id: str, *, firmware: str = "",
                 identification: dict | None = None,
                 symbols: dict | None = None,
                 surfaces_summary: dict | None = None,
                 surface_docs: list[dict] | None = None,
                 attack_summary: dict | None = None,
                 source_dir: Path | None = None,
                 missing: list[str] | None = None) -> dict:
    protocols = identify_protocols(identification or {})
    crypto = identify_crypto(symbols or {})
    deep = deepen_crypto(crypto, symbols or {}, source_dir)
    assessment = assess_attack_surface(
        protocols, crypto, surfaces_summary, surface_docs, attack_summary)
    return {
        "job_id": job_id,
        "firmware": firmware,
        "missing": missing or [],
        "protocols": protocols,
        "crypto": crypto,
        "crypto_deep": deep,
        "assessment": assessment,
    }


def build_report_from_disk(job_id: str, data_dir: Path, firmware: str = "") -> dict:
    missing = []
    ident = _read_json(data_dir / "inputs" / job_id / "identification.json")
    if ident is None:
        missing.append("identification")
    symbols = _read_json(data_dir / "pseudocode" / job_id / "symbols.json")
    if symbols is None:
        missing.append("symbols")
    surfaces_summary = _read_json(
        data_dir / "surfaces" / job_id / "surfaces_done.json")
    if surfaces_summary is None:
        missing.append("surfaces")
    attack_summary = _read_json(data_dir / "attack" / job_id / "attack_done.json")
    if attack_summary is None:
        missing.append("attack")
    surface_docs = load_surface_docs(data_dir / "surfaces" / job_id)
    source_dir = data_dir / "pseudocode" / job_id
    return build_report(
        job_id,
        firmware=firmware,
        identification=ident,
        symbols=symbols,
        surfaces_summary=surfaces_summary,
        surface_docs=surface_docs,
        attack_summary=attack_summary,
        source_dir=source_dir if source_dir.is_dir() else None,
        missing=missing,
    )


def reverse_from_disk(job_id: str, data_dir: Path, md5: str, addr: str) -> dict | None:
    symbols = _read_json(data_dir / "pseudocode" / job_id / "symbols.json")
    if not symbols:
        return None
    info = (symbols.get("binaries") or {}).get(md5)
    if not info:
        return None
    want = int(addr, 16)
    fn = None
    for cand in info.get("functions") or []:
        try:
            if int(str(cand.get("addr") or "0"), 16) == want:
                fn = cand
                break
        except ValueError:
            continue
    if fn is None:
        return None
    source_dir = data_dir / "pseudocode" / job_id
    source = _read_source(source_dir, md5, fn.get("addr") or addr)
    asm = _read_asm(source_dir, md5, fn.get("addr") or addr)
    out = reverse_function(fn, source, asm)
    out["job_id"] = job_id
    out["binary"] = md5
    out["path"] = info.get("path") or ""
    out["arch"] = info.get("arch")
    return out
