"""Conservative URL classification shared by IDA and unit tests."""

import re

_METHOD_ROUTE_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(/[^\s?#]{0,254})$",
    re.IGNORECASE)
_BARE_ROUTE_RE = re.compile(
    r"^(?:cgi-bin|cgi|goform|api|rpc|web|action)[/:][A-Za-z0-9_.?=&/%+-]{1,240}$",
    re.IGNORECASE)
_FILESYSTEM_PREFIXES = (
    "/bin/", "/dev/", "/etc/", "/lib/", "/proc/", "/root/", "/sbin/",
    "/sys/", "/tmp/", "/usr/", "/var/",
)


def classify_route(value):
    """Return confidence/evidence for a route-like string, or None."""
    text = str(value or "").strip()
    if not 2 <= len(text) <= 256 or any(ord(ch) < 32 for ch in text):
        return None
    method = _METHOD_ROUTE_RE.match(text)
    if method:
        return {"route": method.group(2), "method": method.group(1).upper(),
                "confidence": 0.98, "evidence": "http_method_path"}
    lower = text.lower()
    if text.startswith("/") and not lower.startswith(_FILESYSTEM_PREFIXES):
        confidence = 0.96 if any(
            token in lower for token in ("cgi", "goform", "/api/", "/rpc/")) \
            else 0.90
        return {"route": text, "method": None, "confidence": confidence,
                "evidence": "absolute_url_path"}
    if _BARE_ROUTE_RE.match(text):
        return {"route": text, "method": None, "confidence": 0.84,
                "evidence": "route_token"}
    return None
