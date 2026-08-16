"""Per-input attack-surface export (M6b) — one AS-xxx.json per IN-xxx.

Consumes:
  data/inputs/<job>/identification.json   (M6a)
  data/pseudocode/<job>/symbols.json + per-function .c  (M2, when present)
  data/routes/<job>/routes.json           (route recovery, when present)
  data/attack/<job>/attack_paths.json     (M6, when present)

Emits, under data/surfaces/<job>/information/:
  AS-<NNN>.json       one per identification.json input, following
                      information/_schema.json (routing_path / dispatchers /
                      parsers / normalizers / final_handler /
                      carrier_bindings / auth_chain_refs / evidence)
  AS-AUTH-<NNN>.json  one per distinct authorization chain, referenced by
                      the surfaces that pass through it
  identification.json copied alongside for a self-contained bundle

Acceptance gates (validate()):
  gate 1  every IN-xxx has exactly one AS file (no gaps, no duplicates)
  gate 2  every AS file carries all required fields, non-empty; auth
          chains live in their own files and are referenced by id

Decompilation is optional: without symbols.json the surfaces fall back to
config/route evidence only, and the affected fields are marked
"static-only" in evidence instead of being silently empty.
"""

import json
import os
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from pipeline.attack import surface as attack_surface

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_VERSION = "fwgraph.surfaces.v1"

# ---------------------------------------------------------------------------
# function role classification (routing_path stages)
# ---------------------------------------------------------------------------
_ACCEPT_CALLS = {"accept", "accept4", "recvfrom", "recvmsg", "recv",
                 "select", "poll", "epoll_wait"}
_PARSE_HINTS = ("parse", "decode", "sscanf", "strtok", "strsep", "json",
                "cjson", "xml", "urlparse", "url_parse", "header",
                "tokenize", "split")
_NORM_HINTS = ("normalize", "canonical", "urldecode", "url_decode",
               "strtolower", "toupper", "realpath", "trim", "unescape",
               "hex2bin", "base64", "urlencode", "remove_dot", "cleanpath",
               "sanitize")
_DISPATCH_HINTS = ("dispatch", "route", "lookup_handler", "find_handler",
                   "handler_table", "cmd_table", "command", "method_table",
                   "rpc_call", "lib.def")
_HANDLER_HINTS = ("handle", "handler", "_cgi", "cgi_", "process_request",
                  "do_get", "do_post", "serve", "respond", "worker",
                  "entry", "api_")
_AUTH_TAGS = {"auth_related"}

_CARRIER_ENV_RX = re.compile(
    r"(\w+)\s*=\s*(?:getenv|secure_getenv)\s*\(\s*\"([A-Z_]+)\"\s*\)")
_CARRIER_RECV_RX = re.compile(
    r"(?:recv|recvfrom|recvmsg|SSL_read)\s*\(\s*\w+\s*,\s*&?(\w+)")
_CARRIER_READ_RX = re.compile(
    r"\bread\s*\(\s*(\w+)\s*,\s*&?(\w+)")
_CARRIER_FREAD_RX = re.compile(r"fread\s*\(\s*&?(\w+)\s*,")
_CARRIER_SSCANF_RX = re.compile(
    r"sscanf\s*\(\s*(\w+)\s*,\s*\"([^\"]*)\"\s*,\s*&?(\w+)")
_CARRIER_CGI_RX = re.compile(
    r"(\w+)\s*=\s*([A-Za-z_]\w*)\s*\(([^()]*)\)")
_CARRIER_QSTR_RX = re.compile(r'"(\w[\w.-]*)"')
_FD_ORIGIN_RX = re.compile(
    r"(\w+)\s*=\s*(socket|accept|accept4|open|open64|fopen|fileno)\s*\(")

# request-accessor call names are matched on underscore tokens, never on
# substrings — "platform_get" / "format(" must not bind as form accessors
_ACCESSOR_HEADS = {"cgi", "param", "params", "query", "form", "post",
                   "getvar", "websgetvar", "get", "input", "cookie",
                   "header", "arg"}


def _is_accessor(callee):
    c = callee.lower()
    if c in _ACCESSOR_HEADS:
        return True
    return c.split("_", 1)[0] in _ACCESSOR_HEADS and "_" in c


# thunk / PLT-stub names — never a real terminal handler
_STUB_RX = re.compile(r"^(?:__imp_|j_|\.plt|__plt|thunk_|\.thunk)")


def is_stub_name(name):
    """True for import-stub / thunk style names (__imp_x, j_x, ...)."""
    return bool(_STUB_RX.match(str(name or "")))


def anchor_applet(view, applet):
    """Locate a busybox-style applet's entry inside a multicall binary.

    Strategy: (1) an explicit `<applet>_main` symbol, (2) functions whose
    string xrefs contain the exact applet name — those sit around the
    argv[0] dispatch table, so their callees reach the applet body.

    Returns (start_addrs, note); an empty list means the applet boundary
    could not be resolved from the available symbols."""
    applet = (applet or "").strip().lower()
    if not applet:
        return [], "no applet name"
    starts = []
    for addr, f in view.functions.items():
        nm = (f.get("name") or "").lower()
        if nm == f"{applet}_main" or nm == applet:
            starts.append(addr)
    if starts:
        return sorted(starts), "applet main symbol"
    for addr, f in view.functions.items():
        for s in (f.get("strings") or []):
            if str(s).strip().lower() == applet:
                starts.append(addr)
                break
    if starts:
        return sorted(starts), "applet-name string xref"
    return [], "multicall binary, applet boundary unresolved"


# ---------------------------------------------------------------------------
# structural authorization evidence
# ---------------------------------------------------------------------------
_CRED_COMPARE = {"strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp",
                 "crypt", "crypt_r", "checkpassword", "password_verify"}
_CRED_STRINGS = ("password", "passwd", "pwd", "credential", "passphrase",
                 "authorize", "authentication")
_REJECT_RX = re.compile(
    r"(return\s+-1\b|\b403\b|\b401\b|auth\w*[\s_]*fail|fail\w*[\s_]*auth|"
    r"denied|unauthor)", re.IGNORECASE)


def auth_evidence(func, source_text):
    """Structural auth proof for one function: a credential-compare call
    (strcmp/crypt family over password-class data) AND a rejection branch
    (return -1 / 403 / auth fail path) in its pseudo-C. Returns a detail
    string or None — name-similarity alone is not evidence."""
    calls = {attack_surface._norm(c) for c in (func.get("calls") or [])}
    compare = sorted(calls & _CRED_COMPARE)
    if not compare:
        return None
    strings = " ".join(str(s).lower() for s in (func.get("strings") or []))
    name_l = " ".join(str(func.get(k) or "").lower()
                      for k in ("name", "ai_name", "rule_name"))
    if not any(k in strings or k in name_l for k in _CRED_STRINGS):
        return None
    if not source_text or not _REJECT_RX.search(source_text):
        return None
    return (f"credential compare ({', '.join(compare)}) with rejection "
            f"branch in pseudo-C")


def order_auth_chain(view, addrs):
    """Order auth functions caller->callee along real call edges (not a
    flat BFS set). Disconnected members keep a deterministic tail order."""
    addrset = set(addrs)
    edges, indeg = {}, {a: 0 for a in addrs}
    for a in addrs:
        for nxt in view.callees(a):
            if nxt in addrset and nxt != a:
                edges.setdefault(a, []).append(nxt)
                indeg[nxt] += 1
    roots = [a for a in addrs if indeg.get(a) == 0]
    order, seen = [], set()
    queue = list(roots)
    while queue:
        a = queue.pop(0)
        if a in seen:
            continue
        seen.add(a)
        order.append(a)
        queue.extend(sorted(edges.get(a, [])))
    for a in addrs:
        if a not in seen:
            order.append(a)
    return order


_GOAHEAD_REG_RX = re.compile(
    r"(websAddRoute|websDefineHandler|websDefineAction)\s*\(\s*\"([^\"]+)\""
    r"\s*(?:,\s*([A-Za-z_]\w*))?")


def extract_goahead_routes(view, source_reader, limit=40):
    """Recover GoAhead route registrations from pseudo-C: the string
    argument of websAddRoute/websDefineHandler/websDefineAction calls.
    `source_reader(addr)` must return the function's pseudo-C text."""
    routes = []
    for addr, f in view.functions.items():
        calls = {str(c) for c in (f.get("calls") or [])}
        if not calls & {"websAddRoute", "websDefineHandler",
                        "websDefineAction", "__imp_websAddRoute",
                        "__imp_websDefineHandler", "__imp_websDefineAction"}:
            continue
        src = source_reader(addr)
        if not src:
            continue
        for m in _GOAHEAD_REG_RX.finditer(src):
            handler = m.group(3) or ""
            routes.append({
                "route": m.group(2),
                "method": None,
                "confidence": 0.6,
                "evidence": f"goahead_register_call {m.group(1)}",
                "binary_path": view.path,
                "handler_addr": addr,
                "handler_name": None if is_stub_name(handler) or
                                handler in ("NULL", "0") else handler,
                "registrar": f.get("name", "?"),
            })
            if len(routes) >= limit:
                return routes
    return routes


def _now():
    return datetime.now(timezone.utc).isoformat()


def _read_source(pseudo_root, md5, addr):
    return attack_surface._read_source(pseudo_root, md5, addr)


class BinaryView:
    """Per-binary call graph + function metadata over symbols.json."""

    def __init__(self, md5, info):
        self.md5 = md5
        self.path = info.get("path", "")
        self.functions = {f["addr"]: f for f in info.get("functions", [])
                          if f.get("addr")}
        norm_index = {}
        for f in self.functions.values():
            norm_index.setdefault(attack_surface._norm(f.get("name", "")),
                                  set()).add(f["addr"])
        self.norm_index = norm_index

    def callees(self, addr):
        f = self.functions.get(addr)
        if not f:
            return []
        out = []
        for call in f.get("calls", []) or []:
            for target in self.norm_index.get(
                    attack_surface._norm(call), ()):
                out.append(target)
        return out

    def bfs_chain(self, starts, max_depth=6, limit=400):
        """Breadth-first walk from entry functions -> ordered addr list."""
        seen, order = set(), []
        q = deque((a, 0) for a in starts)
        while q and len(order) < limit:
            addr, depth = q.popleft()
            if addr in seen or depth > max_depth:
                continue
            seen.add(addr)
            order.append(addr)
            for nxt in self.callees(addr):
                if nxt not in seen:
                    q.append((nxt, depth + 1))
        return order

    def entry_functions(self):
        out = []
        for addr, f in self.functions.items():
            name = f.get("name", "")
            tags = set(f.get("tags", []) or [])
            if name in ("main", "_start") or "entrypoint" in tags:
                out.append(addr)
            elif "network_facing" in tags:
                out.append(addr)
        return out


def classify_function(func, source_text):
    """Assign routing roles to a function: accept/parse/normalize/dispatch/
    handler/auth. Multiple roles allowed."""
    roles = []
    name = attack_surface._norm(func.get("name", ""))
    ai = (func.get("ai_name") or func.get("rule_name") or "").lower()
    label = f"{name} {ai}"
    calls = {attack_surface._norm(c) for c in (func.get("calls") or [])}
    strings = " ".join(func.get("strings", []) or []).lower()
    tags = set(func.get("tags", []) or [])

    if calls & _ACCEPT_CALLS:
        roles.append("accept")
    if any(h in label for h in _PARSE_HINTS) or \
            any(h in strings for h in ("http/", "content-length",
                                       "content-type", "soapaction")):
        roles.append("parse")
    if any(h in label for h in _NORM_HINTS):
        roles.append("normalize")
    if any(h in label for h in _DISPATCH_HINTS):
        roles.append("dispatch")
    if any(h in label for h in _HANDLER_HINTS):
        roles.append("handler")
    if tags & _AUTH_TAGS or any(
            t in label for t in ("auth", "login", "session", "passwd",
                                 "cookie", "token", "permis", "acl")):
        roles.append("auth")
    if source_text and re.search(r"\(\s*\*\s*\w+\s*\)\s*\(", source_text):
        if "dispatch" not in roles:
            roles.append("dispatch")  # indirect call through function pointer
    return roles


def extract_carrier_bindings(func, source_text, limit=12):
    """Bind raw carriers (URL/header/body/opcode/buffer/env) to program
    variables inside a handler's pseudo-C. Evidence = func addr + line.

    Only regex hits with a concrete pseudo-C line are returned — callers
    handle the no-binding case with a separate placeholder hint, never by
    mixing a fabricated entry into this list."""
    bindings = []
    if not source_text:
        return bindings
    addr = func.get("addr", "?")
    # fd provenance: which variable was assigned a socket vs a file handle
    fd_origin = {}
    for m in _FD_ORIGIN_RX.finditer(source_text):
        fd_origin.setdefault(m.group(1), m.group(2))
    for lineno, line in enumerate(source_text.splitlines(), 1):
        line = line.strip()
        m = _CARRIER_ENV_RX.search(line)
        if m:
            bindings.append({
                "carrier": f"environment variable {m.group(2)}",
                "destination": m.group(1),
                "evidence": f"{addr}:{lineno} getenv(\"{m.group(2)}\")"})
            continue
        m = _CARRIER_SSCANF_RX.search(line)
        if m:
            bindings.append({
                "carrier": f"buffer {m.group(1)} (format \"{m.group(2)}\")",
                "destination": m.group(3),
                "evidence": f"{addr}:{lineno} sscanf"})
            continue
        m = _CARRIER_CGI_RX.search(line)
        if m and _is_accessor(m.group(2)):
            # the parameter name is the first *quoted* argument
            # (websGetVar(wp, "name")), falling back to a bare first arg
            qm = _CARRIER_QSTR_RX.search(m.group(3))
            param = qm.group(1) if qm else \
                m.group(3).split(",", 1)[0].strip()
            if re.fullmatch(r"\w[\w.-]*", param) \
                    and param.lower() not in ("null",):
                bindings.append({
                    "carrier": f"request parameter {param}",
                    "destination": m.group(1),
                    "evidence": f"{addr}:{lineno} accessor {m.group(2)}"})
                continue
        m = _CARRIER_RECV_RX.search(line)
        if m:
            bindings.append({
                "carrier": "socket/request buffer",
                "destination": m.group(1),
                "evidence": f"{addr}:{lineno} recv"})
            continue
        m = _CARRIER_READ_RX.search(line)
        if m:
            origin = fd_origin.get(m.group(1))
            if origin in ("open", "open64", "fopen", "fileno"):
                carrier = "file content buffer"
            elif origin in ("socket", "accept", "accept4"):
                carrier = "socket/request buffer"
            else:
                carrier = "fd buffer (origin unresolved)"
            bindings.append({
                "carrier": carrier,
                "destination": m.group(2),
                "evidence": f"{addr}:{lineno} read fd={m.group(1)}"})
            continue
        m = _CARRIER_FREAD_RX.search(line)
        if m:
            bindings.append({
                "carrier": "file stream buffer",
                "destination": m.group(1),
                "evidence": f"{addr}:{lineno} fread"})
        if len(bindings) >= limit:
            break
    # dedupe preserving order
    seen, out = set(), []
    for b in bindings:
        k = (b["carrier"], b["destination"])
        if k not in seen:
            seen.add(k)
            out.append(b)
    return out[:limit]
