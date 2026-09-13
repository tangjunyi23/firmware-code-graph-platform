"""Local CVE/CNVD/CNNVD knowledge base for N-day lookup.

Advisory records live in data/vulnlib/advisories/<id>.json plus an atomic
index.jsonl. The store does not fetch NVD/CNVD; operators import JSON (one
object or a list). Query is substring / vendor-product / CWE matching over
the local index, then optional scoring against firmware jobs the caller can
see. fwgraph still does not declare a vulnerability — a match is a candidate.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

from orchestrator.app import config

_LOCK = threading.Lock()

_ID_RE = re.compile(
    r"^(?:CVE-\d{4}-\d{4,}|CNVD-\d{4}-\d{4,}|CNNVD-\d{8}-\d{1,}|VL-[A-Z0-9]{8,24})$",
    re.I,
)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_CNVD_RE = re.compile(r"^CNVD-\d{4}-\d{4,}$", re.I)
_CNNVD_RE = re.compile(r"^CNNVD-\d{8}-\d{1,}$", re.I)
_CWE_RE = re.compile(r"^CWE-\d+$", re.I)
_SOURCES = ("cve", "cnvd", "cnnvd", "manual")

_VENDOR_RULES = (
    (re.compile(r"tp-?link|archer|wr\d|c7v|tl-", re.I), "TP-Link"),
    (re.compile(r"netgear|r7\d|r6\d", re.I), "Netgear"),
    (re.compile(r"d-?link|dir-", re.I), "D-Link"),
    (re.compile(r"xiaomi|miwifi|redmi", re.I), "小米"),
    (re.compile(r"huawei|honor|hg\d", re.I), "华为"),
    (re.compile(r"cisco|linksys", re.I), "Cisco"),
    (re.compile(r"asus|rt-", re.I), "ASUS"),
    (re.compile(r"zte|f6\d", re.I), "中兴"),
    (re.compile(r"hikvision|ds-", re.I), "海康"),
    (re.compile(r"dahua", re.I), "大华"),
)


class VulnlibError(ValueError):
    """Validation failure; str() is a Chinese 422 detail."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _data_dir() -> Path:
    return config.data_dir()


def root() -> Path:
    return _data_dir() / "vulnlib"


def _adv_dir() -> Path:
    return root() / "advisories"


def _index_path() -> Path:
    return root() / "index.jsonl"


def _new_id() -> str:
    return "VL-" + os.urandom(6).hex()


def guess_vendor(name: str) -> str:
    text = str(name or "")
    for rule, label in _VENDOR_RULES:
        if rule.search(text):
            return label
    return ""


def _norm_id(raw: str) -> str:
    text = str(raw or "").strip().upper()
    if _CVE_RE.match(text) or _CNVD_RE.match(text) or _CNNVD_RE.match(text):
        return text
    if _ID_RE.match(text):
        return text
    raise VulnlibError("id 必须是 CVE-YYYY-NNNN、CNVD-YYYY-NNNN、CNNVD-YYYYMMDD-N 或 VL-<hex>")


def _norm_source(raw: str, vid: str) -> str:
    text = str(raw or "").strip().lower()
    if not text:
        if vid.startswith("CVE-"):
            return "cve"
        if vid.startswith("CNVD-"):
            return "cnvd"
        if vid.startswith("CNNVD-"):
            return "cnnvd"
        return "manual"
    if text not in _SOURCES:
        raise VulnlibError("source 必须是 cve|cnvd|cnnvd|manual")
    return text


def _norm_severity(raw) -> str:
    text = str(raw or "info").strip().lower()
    aliases = {
        "crit": "critical", "critical": "critical",
        "high": "high", "medium": "medium", "med": "medium",
        "low": "low", "info": "info", "informational": "info",
        "严重": "critical", "高危": "high", "中危": "medium",
        "低危": "low", "提示": "info",
    }
    if text not in aliases:
        raise VulnlibError("severity 必须是 critical|high|medium|low|info")
    return aliases[text]


def _str_list(value, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        raise VulnlibError(f"{field} 必须是字符串或字符串数组")
    out = []
    seen = set()
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise VulnlibError(f"{field} 的每一项都必须是非空字符串")
        text = item.strip()
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _norm_cwes(value) -> list[str]:
    out = []
    for item in _str_list(value, "cwe"):
        text = item.upper().replace("CWE", "CWE-").replace("CWE--", "CWE-")
        if not text.startswith("CWE-"):
            text = "CWE-" + re.sub(r"\D+", "", text)
        if not _CWE_RE.match(text):
            raise VulnlibError("cwe 必须是 CWE-<数字>")
        if text not in out:
            out.append(text)
    return out


def _req_str(payload: dict, field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise VulnlibError(f"{field} 必填且必须是非空字符串")
    return value.strip()


def _opt_str(payload: dict, field: str, default: str = "") -> str:
    value = payload.get(field)
    if value is None:
        return default
    if not isinstance(value, str):
        raise VulnlibError(f"{field} 必须是字符串")
    return value.strip()


def normalize(payload: dict, *, owner: str = "", existing: dict | None = None) -> dict:
    """Validate and normalize one advisory. Raises VulnlibError."""
    if not isinstance(payload, dict):
        raise VulnlibError("条目必须是 JSON 对象")
    raw_id = payload.get("id") or (existing or {}).get("id") or _new_id()
    vid = _norm_id(str(raw_id))
    if payload.get("title") is not None or existing is None:
        title = _req_str(payload, "title")
    else:
        title = str(existing.get("title") or "")
    if not title:
        raise VulnlibError("title 必填且必须是非空字符串")
    source = _norm_source(payload.get("source"), vid)
    severity = _norm_severity(payload.get("severity", (existing or {}).get("severity")))
    summary = _opt_str(payload, "summary", str((existing or {}).get("summary") or ""))
    description = _opt_str(payload, "description", str((existing or {}).get("description") or ""))
    sink_alias = payload.get("sink") if isinstance(payload.get("sink"), str) else ""
    vuln_point = _opt_str(
        payload, "vuln_point",
        str((existing or {}).get("vuln_point") or sink_alias or ""))
    published = _opt_str(payload, "published", str((existing or {}).get("published") or ""))
    references = _str_list(payload["references"], "references") if "references" in payload else list((existing or {}).get("references") or [])
    aliases = [_norm_id(a) for a in (_str_list(payload["aliases"], "aliases") if "aliases" in payload else list((existing or {}).get("aliases") or []))]
    aliases = [a for a in aliases if a != vid]
    products = _str_list(payload["products"], "products") if "products" in payload else list((existing or {}).get("products") or [])
    vendors = _str_list(payload["vendors"], "vendors") if "vendors" in payload else list((existing or {}).get("vendors") or [])
    if not vendors:
        guessed = []
        for name in products:
            v = guess_vendor(name)
            if v and v not in guessed:
                guessed.append(v)
        vendors = guessed
    cwes = _norm_cwes(payload["cwe"] if "cwe" in payload else payload.get("cwes", (existing or {}).get("cwes")))
    cvss = payload.get("cvss")
    if cvss is None:
        cvss = (existing or {}).get("cvss")
    if cvss not in (None, ""):
        try:
            cvss = float(cvss)
        except (TypeError, ValueError) as exc:
            raise VulnlibError("cvss 必须是数字") from exc
        if not 0 <= cvss <= 10:
            raise VulnlibError("cvss 范围 0-10")
    else:
        cvss = None
    now = _now()
    doc = {
        "id": vid,
        "source": source,
        "title": title,
        "summary": summary,
        "description": description,
        "vuln_point": vuln_point,
        "severity": severity,
        "cvss": cvss,
        "cwes": cwes,
        "vendors": vendors,
        "products": products,
        "aliases": aliases,
        "references": references,
        "published": published,
        "owner": owner or str((existing or {}).get("owner") or ""),
        "created_at": str((existing or {}).get("created_at") or now),
        "updated_at": now,
    }
    return doc


def summary_of(doc: dict) -> dict:
    """Compact row for list/search (no long description)."""
    return {
        "id": doc.get("id"),
        "source": doc.get("source"),
        "title": doc.get("title"),
        "summary": doc.get("summary") or "",
        "vuln_point": doc.get("vuln_point") or "",
        "severity": doc.get("severity"),
        "cvss": doc.get("cvss"),
        "cwes": list(doc.get("cwes") or []),
        "vendors": list(doc.get("vendors") or []),
        "products": list(doc.get("products") or []),
        "aliases": list(doc.get("aliases") or []),
        "published": doc.get("published") or "",
        "updated_at": doc.get("updated_at") or "",
    }


def _file_for(vid: str) -> Path:
    return _adv_dir() / f"{vid}.json"


def load(vid: str) -> dict | None:
    try:
        nid = _norm_id(vid)
    except VulnlibError:
        return None
    path = _file_for(nid)
    if not path.is_file():
        for line in _index_lines():
            if str(line.get("id") or "").upper() == nid:
                path = _file_for(str(line["id"]))
                break
            aliases = [str(a).upper() for a in (line.get("aliases") or [])]
            if nid in aliases:
                path = _file_for(str(line.get("id")))
                break
        else:
            return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def _index_lines() -> list[dict]:
    path = _index_path()
    if not path.is_file():
        return []
    out = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("id"):
            out.append(row)
    return out


def _rewrite_index(docs: list[dict]) -> None:
    path = _index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    body = "".join(json.dumps(summary_of(d), ensure_ascii=False) + "\n" for d in docs)
    tmp.write_text(body, encoding="utf-8")
    os.replace(tmp, path)


def save(doc: dict) -> dict:
    vid = doc["id"]
    path = _file_for(vid)
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
        rows = _index_lines()
        kept = [r for r in rows if str(r.get("id")) != vid]
        kept.append(summary_of(doc))
        _rewrite_index(kept)
    return doc


def delete(vid: str) -> bool:
    doc = load(vid)
    if doc is None:
        return False
    real = str(doc["id"])
    path = _file_for(real)
    with _LOCK:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            return False
        rows = [r for r in _index_lines() if str(r.get("id")) != real]
        _rewrite_index(rows)
    return True


def stats(rows: list[dict] | None = None) -> dict:
    items = rows if rows is not None else _index_lines()
    by_source: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for row in items:
        src = str(row.get("source") or "manual")
        sev = str(row.get("severity") or "info")
        by_source[src] = by_source.get(src, 0) + 1
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return {
        "total": len(items),
        "by_source": by_source,
        "by_severity": by_sev,
    }


def _haystack(row: dict) -> str:
    parts = [
        row.get("id"), row.get("title"), row.get("summary"),
        " ".join(row.get("aliases") or []),
        " ".join(row.get("vendors") or []),
        " ".join(row.get("products") or []),
        " ".join(row.get("cwes") or []),
        row.get("source"),
    ]
    return " ".join(str(p or "") for p in parts).lower()


def search(
    *,
    q: str = "",
    source: str = "",
    severity: str = "",
    vendor: str = "",
    product: str = "",
    cwe: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    q = str(q or "").strip().lower()
    source = str(source or "").strip().lower()
    severity = str(severity or "").strip().lower()
    vendor = str(vendor or "").strip().lower()
    product = str(product or "").strip().lower()
    cwe = str(cwe or "").strip().upper()
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(offset))
    except (TypeError, ValueError):
        offset = 0
    rows = _index_lines()
    out = []
    for row in rows:
        if source and str(row.get("source") or "").lower() != source:
            continue
        if severity and str(row.get("severity") or "").lower() != severity:
            continue
        if vendor:
            vendors = " ".join(row.get("vendors") or []).lower()
            products = " ".join(row.get("products") or []).lower()
            if vendor not in vendors and vendor not in products:
                continue
        if product:
            blob = " ".join(row.get("products") or []).lower()
            if product not in blob:
                continue
        if cwe:
            cwes = [str(x).upper() for x in (row.get("cwes") or [])]
            if cwe not in cwes:
                continue
        if q and q not in _haystack(row):
            continue
        out.append(row)
    out.sort(key=lambda r: str(r.get("updated_at") or ""), reverse=True)
    total = len(out)
    page = out[offset:offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "items": page, "stats": stats(rows)}


def parse_import(raw) -> list[dict]:
    """Accept one object, a list, or {advisories:[...]}/{items:[...]}."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("advisories", "items", "vulnerabilities", "CVE_Items"):
            if isinstance(raw.get(key), list):
                return raw[key]
        return [raw]
    raise VulnlibError("导入体必须是 JSON 对象或数组")


def _row_id(row: dict):
    for key in ("id", "cve_id"):
        val = row.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    cve = row.get("cve")
    if isinstance(cve, str) and cve.strip():
        return cve.strip()
    if isinstance(cve, dict):
        val = cve.get("id")
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def ingest(payload, *, owner: str = "") -> dict:
    """Create or replace advisories. Returns {imported, ids, errors}."""
    try:
        rows = parse_import(payload)
    except VulnlibError:
        raise
    imported = []
    errors = []
    for i, row in enumerate(rows):
        try:
            if not isinstance(row, dict):
                raise VulnlibError(f"第 {i + 1} 条不是对象")
            raw_id = _row_id(row)
            existing = load(raw_id) if raw_id else None
            work = dict(row)
            if raw_id:
                work["id"] = raw_id
            if not work.get("title"):
                work["title"] = str(raw_id or f"未命名条目 {i + 1}")
            doc = normalize(work, owner=owner, existing=existing)
            save(doc)
            imported.append(doc["id"])
        except VulnlibError as exc:
            rid = ""
            if isinstance(row, dict):
                rid = str(row.get("id") or "")
            errors.append({"index": i, "id": rid, "detail": str(exc)})
    return {"imported": len(imported), "ids": imported, "errors": errors, "stats": stats()}



def _job_blob(job: dict) -> str:
    return " ".join([
        str(job.get("firmware") or ""),
        str(job.get("task") or ""),
        str(job.get("job_id") or ""),
        guess_vendor(job.get("firmware") or ""),
    ]).lower()


def _match_score(row: dict, job: dict) -> tuple[int, list[str]]:
    """Heuristic N-day score against one firmware job. 0 = no match."""
    reasons = []
    score = 0
    blob = _job_blob(job)
    firmware = str(job.get("firmware") or "").lower()
    job_vendor = guess_vendor(job.get("firmware") or "").lower()
    for vendor in row.get("vendors") or []:
        v = str(vendor).lower()
        if v and v in blob:
            score += 40
            reasons.append(f"厂商 {vendor}")
            break
    if job_vendor:
        for vendor in row.get("vendors") or []:
            if job_vendor == str(vendor).lower():
                break
        else:
            if job_vendor in _haystack(row):
                score += 25
                reasons.append(f"固件厂商 {job_vendor}")
    for product in row.get("products") or []:
        p = str(product).strip().lower()
        if len(p) < 3:
            continue
        if p in firmware or p in blob:
            score += 50
            reasons.append(f"产品 {product}")
            break
        # token overlap: archer c7 vs ArcherC7v2_*.bin
        tokens = [t for t in re.split(r"[^a-z0-9]+", p) if len(t) >= 3]
        hits = [t for t in tokens if t in firmware]
        if hits and (len(hits) >= 2 or (len(tokens) == 1 and hits)):
            score += 35
            reasons.append(f"产品词 {','.join(hits)}")
            break
    return score, reasons


def nday(jobs: list[dict], *, q: str = "", vendor: str = "", product: str = "",
         source: str = "", limit: int = 50) -> dict:
    """Score local advisories against visible firmware jobs."""
    found = search(q=q, vendor=vendor, product=product, source=source, limit=500, offset=0)
    hits = []
    for row in found["items"]:
        matches = []
        for job in jobs:
            score, reasons = _match_score(row, job)
            if score <= 0:
                continue
            matches.append({
                "job_id": job.get("job_id"),
                "firmware": job.get("firmware"),
                "status": job.get("status"),
                "score": score,
                "reasons": reasons,
            })
        if not matches:
            continue
        matches.sort(key=lambda m: -m["score"])
        hits.append({
            **summary_of(row),
            "match_score": matches[0]["score"],
            "matches": matches[:8],
        })
    hits.sort(key=lambda h: (-int(h["match_score"]), str(h.get("id") or "")))
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50
    return {
        "total": len(hits),
        "limit": limit,
        "jobs_considered": len(jobs),
        "items": hits[:limit],
        "stats": found["stats"],
    }

