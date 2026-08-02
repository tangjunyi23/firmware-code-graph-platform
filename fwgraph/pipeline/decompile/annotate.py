"""Attack-surface tagging + rule-based naming for merged symbols (M2).

Pure Python (no IDA). Reads data/pseudocode/<job>/symbols.json produced by
orchestrator.app.decompiler and enhances it in place:

  tags                                per-function attack-surface labels
  rule_name / rule_confidence / rule_source
                                      spec-compliant name proposals for
                                      sub_XXXX functions (plus cleaning of
                                      non-compliant exported names)

Candidate names are validated against config/naming_spec.yaml (pattern /
max_length / banned patterns / uniqueness per binary / confidence_min).

CLI: python -m pipeline.decompile.annotate <symbols.json> [...]
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - venv always has pyyaml
    yaml = None

# ---------------------------------------------------------------------------
# Feature tables (tune here)
# ---------------------------------------------------------------------------

# libc calls considered dangerous from an attack-surface point of view
DANGEROUS_CALLS = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
    "system", "popen", "execve", "execl", "execlp", "execvp",
    "dlopen", "mktemp", "tmpnam",
}

# calls that mark network-facing code
NETWORK_CALLS = {
    "socket", "bind", "listen", "accept", "accept4", "connect",
    "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
    "gethostbyname", "getaddrinfo",
}

# string tokens (matched lowercase, substring)
NETWORK_STRING_TOKENS = ("http://", "https://", "http/", "user-agent")
AUTH_STRING_TOKENS = ("password", "passwd", "crypt", "token", "login", "session")

# getenv-like calls whose uppercase string argument is an env/NVRAM key
ENV_GET_CALLS = {"getenv", "nvram_get", "nvram_safe_get", "nvram_bufget", "getnvram"}
ENV_SET_CALLS = {"setenv", "nvram_set", "nvram_bufset", "nvram_safe_set"}
NVRAM_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,31}$")

# libc call-combination rules: (required calls, name, confidence); first match
# wins, so keep specific combos above their subsets.
LIBC_COMBO_RULES = [
    (frozenset({"socket", "bind", "listen", "accept"}), "net_run_server", 0.85),
    (frozenset({"socket", "bind", "listen"}), "net_init_server", 0.85),
    (frozenset({"select", "recv"}), "net_poll_events", 0.75),
    (frozenset({"socket", "connect"}), "net_open_connection", 0.80),
    (frozenset({"socket", "recv"}), "net_recv_data", 0.70),
    (frozenset({"fork", "execve"}), "sys_spawn_process", 0.85),
    (frozenset({"fork", "waitpid"}), "sys_spawn_process", 0.80),
    (frozenset({"open", "read", "close"}), "sys_read_file", 0.80),
    (frozenset({"open", "write", "close"}), "sys_write_file", 0.80),
    (frozenset({"opendir", "readdir"}), "sys_read_dir", 0.80),
    (frozenset({"pthread_create"}), "sys_start_thread", 0.80),
    (frozenset({"system"}), "sys_run_command", 0.75),
    (frozenset({"popen"}), "sys_open_pipe", 0.75),
    (frozenset({"dlopen"}), "sys_load_library", 0.80),
    (frozenset({"strcpy", "strcat"}), "util_concat_string", 0.70),
    (frozenset({"malloc", "memcpy"}), "util_copy_buffer", 0.70),
]

# string-content -> naming domain hints, checked lowercase in order
STRING_DOMAIN_HINTS = [
    ("nvram", "nvram"),
    ("http://", "http"), ("https://", "http"),
    ("password", "auth"), ("passwd", "auth"),
    ("/bin/", "sys"), ("/sbin/", "sys"), ("/etc/", "sys"),
    ("/proc/", "sys"), ("/dev/", "sys"), ("/tmp/", "sys"),
]

SUB_NAME_RE = re.compile(r"^sub_[0-9a-fA-F]+$")

SPEC_PATH = Path(__file__).resolve().parents[2] / "config" / "naming_spec.yaml"

_DEFAULT_SPEC = {
    "format": {"pattern": r"^[a-z][a-z0-9]*(_[a-z0-9]+){1,4}$", "max_length": 40},
    "banned": {"patterns": [
        "^sub_", "^FUN_", "^j_", r"thing|stuff|misc2|temp|tmp[0-9]*$", "[A-Z]",
    ]},
    "arbitration": {"confidence_min": 0.6},
}


def load_spec(path=None):
    path = Path(path) if path else SPEC_PATH
    if yaml is not None and path.is_file():
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    return _DEFAULT_SPEC


class NameValidator:
    """Validate candidate names against naming_spec.yaml."""

    def __init__(self, spec):
        fmt = spec.get("format", {})
        self.pattern = re.compile(
            fmt.get("pattern", _DEFAULT_SPEC["format"]["pattern"]))
        self.max_length = int(fmt.get("max_length", 40))
        self.banned = [re.compile(p)
                       for p in spec.get("banned", {}).get("patterns", [])]
        self.confidence_min = float(
            spec.get("arbitration", {}).get("confidence_min", 0.6))

    def is_valid(self, name):
        if not name or len(name) > self.max_length:
            return False
        if not self.pattern.match(name):
            return False
        return not any(b.search(name) for b in self.banned)


# ---------------------------------------------------------------------------
# tagging
# ---------------------------------------------------------------------------

def _norm_call(name):
    """Normalize a callee name for table lookup (strip thunk/dedup noise)."""
    n = name.strip().lower()
    if n.startswith("j_"):
        n = n[2:]
    return re.sub(r"_\d+$", "", n)


def _norm_calls(func):
    return {_norm_call(c) for c in func.get("calls", [])}


def compute_tags(func):
    calls = _norm_calls(func)
    strings = [s.lower() for s in func.get("strings", [])]
    tags = []
    if calls & DANGEROUS_CALLS:
        tags.append("calls_dangerous")
    if calls & NETWORK_CALLS or any(
            tok in s for s in strings for tok in NETWORK_STRING_TOKENS):
        tags.append("network_facing")
    if any(tok in s for s in strings for tok in AUTH_STRING_TOKENS):
        tags.append("auth_related")
    if func.get("is_exported") or func.get("name") in ("main", "init"):
        tags.append("entrypoint")
    return tags


# ---------------------------------------------------------------------------
# naming rules: each returns (candidate, confidence, source) or None
# ---------------------------------------------------------------------------

def _sanitize(text):
    s = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()
    return re.sub(r"_+", "_", s)


def _informative_string(func):
    for s in func.get("strings", []):
        t = s.strip()
        if t.lower().startswith("usage:") or "://" in t \
                or (t.startswith("/") and len(t) > 3):
            return s
    return None


def _string_object(s):
    """Derive the object part of a name from an informative string."""
    t = s.strip()
    if t.lower().startswith("usage:"):
        rest = t.split(":", 1)[1].strip().split()
        return rest[0] if rest else ""
    if "://" in t:
        return re.split(r"[/?#]", t.split("://", 1)[1])[0]
    if "/" in t:
        base = t.rstrip("/").rsplit("/", 1)[-1]
        return base.rsplit(".", 1)[0] if "." in base else base
    return ""


def _domain_for_string(s):
    low = s.lower()
    for token, domain in STRING_DOMAIN_HINTS:
        if token in low:
            return domain
    return "http" if "://" in s else "sys"


def rule_string_xref(func):
    s = _informative_string(func)
    if s is None:
        return None
    obj = _sanitize(_string_object(s))
    if not obj:
        return None
    return (f"{_domain_for_string(s)}_handle_{obj}", 0.70, "string_xref")


def rule_libc_combo(func):
    calls = _norm_calls(func)
    for combo, name, conf in LIBC_COMBO_RULES:
        if combo <= calls:
            return (name, conf, "libc_combo")
    return None


def rule_nvram_key(func):
    calls = _norm_calls(func)
    keys = [s.strip() for s in func.get("strings", [])
            if NVRAM_KEY_RE.match(s.strip())]
    if not keys:
        return None
    if calls & ENV_GET_CALLS:
        return (f"nvram_get_{keys[0].lower()}", 0.85, "nvram_key")
    if calls & ENV_SET_CALLS:
        return (f"nvram_set_{keys[0].lower()}", 0.85, "nvram_key")
    return None


def rule_export_symbol(func):
    name = func.get("name", "")
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)  # camelCase boundary
    s = _sanitize(s)
    if not s or s == name:
        return None  # nothing to clean, or already spec-shaped
    return (s, 0.90, "export_symbol")


def propose_name(func):
    """First matching rule wins. Deterministic rule order."""
    name = func.get("name", "")
    if SUB_NAME_RE.match(name):
        for rule in (rule_nvram_key, rule_libc_combo, rule_string_xref):
            hit = rule(func)
            if hit:
                return hit
    elif func.get("is_exported"):
        return rule_export_symbol(func)
    return None


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

def _unique(candidate, used, validator):
    """Resolve name conflicts inside one binary with a _2/_3/... suffix."""
    name, n = candidate, 2
    while name in used:
        name = f"{candidate}_{n}"
        n += 1
    return name if validator.is_valid(name) else None


def annotate_functions(functions, validator):
    """Tag + rule-name one binary's function list in place; return stats."""
    used = {f.get("name", "") for f in functions}
    stats = {
        "functions": len(functions),
        "sub_initial": sum(1 for f in functions
                           if SUB_NAME_RE.match(f.get("name", ""))),
        "tagged": Counter(),
        "named": Counter(),
        "named_total": 0,
        "sub_remaining": 0,
    }
    for func in functions:
        tags = compute_tags(func)
        func["tags"] = tags
        for tag in tags:
            stats["tagged"][tag] += 1
        hit = propose_name(func)
        if hit:
            candidate, confidence, source = hit
            final = None
            if confidence >= validator.confidence_min \
                    and validator.is_valid(candidate):
                final = _unique(candidate, used, validator)
            if final:
                used.add(final)
                func["rule_name"] = final
                func["rule_confidence"] = confidence
                func["rule_source"] = source
                stats["named"][source] += 1
                stats["named_total"] += 1
        if SUB_NAME_RE.match(func.get("name", "")) and "rule_name" not in func:
            stats["sub_remaining"] += 1
    stats["tagged"] = dict(sorted(stats["tagged"].items()))
    stats["named"] = dict(sorted(stats["named"].items()))
    return stats


def annotate_symbols(symbols, spec=None):
    """Annotate a whole symbols.json structure (grouped by binary)."""
    validator = NameValidator(spec or load_spec())
    overall = {
        "binaries": {},
        "functions": 0,
        "sub_initial": 0,
        "named_total": 0,
        "sub_remaining": 0,
        "tagged": Counter(),
        "named": Counter(),
    }
    for key, entry in symbols.get("binaries", {}).items():
        stats = annotate_functions(entry.get("functions", []), validator)
        entry["annotate_stats"] = stats
        overall["binaries"][key] = stats
        overall["functions"] += stats["functions"]
        overall["sub_initial"] += stats["sub_initial"]
        overall["named_total"] += stats["named_total"]
        overall["sub_remaining"] += stats["sub_remaining"]
        overall["tagged"].update(stats["tagged"])
        overall["named"].update(stats["named"])
    overall["tagged"] = dict(sorted(overall["tagged"].items()))
    overall["named"] = dict(sorted(overall["named"].items()))
    symbols["annotate_stats"] = overall
    return overall


def annotate_file(path, spec=None):
    """Annotate symbols.json in place; return overall stats."""
    path = Path(path)
    symbols = json.loads(path.read_text(encoding="utf-8"))
    stats = annotate_symbols(symbols, spec)
    path.write_text(json.dumps(symbols, indent=1), encoding="utf-8")
    return stats


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    for arg in argv[1:]:
        stats = annotate_file(arg)
        print(f"{arg}:")
        print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
