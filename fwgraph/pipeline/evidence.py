"""Cross-tool evidence identity borrowed from Firida, adapted to fwgraph.

Join key is job_id + binary content md5 + canonical function address
(lowercase 0x-hex). Paths and symbol names are not join keys.

Dynamic results carry an envelope with attribution:
  - observed_in_window: seen in one trace/frida window (not request-caused)
  - verified_in_single_trace: the whole static path was in ONE trace
  - static_only: no runtime observation

compose() only joins facts the caller already fetched. It does not query
IDA, the graph, or traces, and must not rewrite those producers.
"""

from __future__ import annotations

from typing import Any

SCHEMA_ADDRESS = "fwgraph.evidence-address.v1"
SCHEMA_ENVELOPE = "fwgraph.dynamic-evidence.envelope.v1"
SCHEMA_COMPOSE = "fwgraph.evidence-composition.v1"

ATTRIBUTION_OBSERVED = "observed_in_window"
ATTRIBUTION_VERIFIED = "verified_in_single_trace"
ATTRIBUTION_STATIC = "static_only"

_NOTES = {
    ATTRIBUTION_OBSERVED: (
        "Observed in this capture/trace window. Not request-caused; "
        "not a coverage percentage."
    ),
    ATTRIBUTION_VERIFIED: (
        "Entire static path observed in one trace. "
        "Do not merge traces into one execution path."
    ),
    ATTRIBUTION_STATIC: "Static path only; no runtime observation.",
}


def canonical_addr(addr: Any) -> str:
    """Lowercase 0x-prefixed hex. Invalid input is stripped and lowercased."""
    text = str(addr or "").strip()
    if not text:
        return ""
    try:
        return hex(int(text, 16))
    except ValueError:
        return text.lower()


def make_address(binary_md5: str, addr: Any, job_id: str | None = None) -> dict[str, Any]:
    payload = {
        "schema": SCHEMA_ADDRESS,
        "binary_md5": str(binary_md5 or ""),
        "addr": canonical_addr(addr),
    }
    if job_id:
        payload["job_id"] = str(job_id)
    return payload


def wrap_envelope(
    *,
    producer: str,
    view_kind: str,
    job_id: str,
    items: list[Any] | None,
    attribution: str = ATTRIBUTION_OBSERVED,
    capture_id: str | None = None,
    integrity: str = "ok",
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    rows = list(items or [])
    total = len(rows)
    offset = max(0, int(offset or 0))
    if limit is None:
        sliced = rows[offset:]
    else:
        cap = max(0, int(limit))
        sliced = rows[offset: offset + cap]
    has_more = (offset + len(sliced)) < total
    return {
        "schema": SCHEMA_ENVELOPE,
        "producer": producer,
        "view_kind": view_kind,
        "attribution": attribution,
        "integrity": integrity,
        "note": _NOTES.get(attribution, ""),
        "scope": {"job_id": job_id, "capture_id": capture_id},
        "pagination": {
            "offset": offset,
            "items_returned": len(sliced),
            "items_total": total,
            "has_more": has_more,
            "analysis_complete": not has_more,
        },
        "items": sliced,
    }


def compose(
    *,
    job_id: str,
    binary_md5: str,
    addr: Any,
    static_block: dict[str, Any] | None = None,
    decompile_text: str | None = None,
    dynamic_envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Join already-fetched producer facts at one Evidence Address."""
    address = make_address(binary_md5, addr, job_id=job_id)
    producers: list[str] = []
    if static_block is not None:
        producers.append("attack_surface")
    excerpt = None
    if decompile_text is not None:
        producers.append("hexrays")
        text = str(decompile_text)
        excerpt = {"chars": len(text), "excerpt": text[:200]}
    dyn = None
    if dynamic_envelope is not None:
        producers.append("dynamic")
        scope = dynamic_envelope.get("scope") or {}
        dyn = {
            "producer": dynamic_envelope.get("producer"),
            "view_kind": dynamic_envelope.get("view_kind"),
            "capture_id": scope.get("capture_id"),
            "attribution": dynamic_envelope.get("attribution"),
            "items": dynamic_envelope.get("items") or [],
        }
    return {
        "schema": SCHEMA_COMPOSE,
        "address": address,
        "producers": producers,
        "static_block": static_block,
        "decompile": excerpt,
        "dynamic": dyn,
    }
