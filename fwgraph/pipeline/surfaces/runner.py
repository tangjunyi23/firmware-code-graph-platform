"""Per-input attack-surface export runner (M6b). See package docstring in
classify.py header / module contract in information/_schema.json."""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.inputs import elfchain
from pipeline.surfaces import classify

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

SCHEMA_VERSION = "fwgraph.surfaces.v1"

_STAGE_NAMES = {
    "accept": "accept",
    "parse": "parse",
    "normalize": "normalize",
    "dispatch": "dispatch",
    "handler": "handler",
    "auth": "auth",
}

REQUIRED_SURFACE_FIELDS = (
    "surface_id", "source_input", "service", "entry", "routing_path",
    "dispatchers", "parsers", "normalizers", "final_handler",
    "carrier_bindings", "carrier_hint", "auth_chain_refs", "evidence",
)

# cross-library attribution: at most this many processing-chain libraries
# are scanned for routes/auth functions per input (router daemons link
# dozens — libgo.so was 17th on the MX12 httpd chain)
_MAX_CHAIN_LIBS = 32
# structural auth scan: source reads per binary are capped (prefilter is
# metadata-only, the source read is the expensive step)
_MAX_AUTH_SRC_READS = 200


def _now():
    return datetime.now(timezone.utc).isoformat()


def _load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _binary_index(symbols):
    """path-basename -> (md5, BinaryView)"""
    out = {}
    for md5, info in (symbols or {}).get("binaries", {}).items():
        view = classify.BinaryView(md5, info)
        path = info.get("path", "")
        for p in {path, path.rsplit("/", 1)[-1]}:
            if p:
                out.setdefault(p, view)
    return out


def _find_view(bin_index, entry_file):
    ef = entry_file.lstrip("/")
    for key, view in bin_index.items():
        if ef.endswith(key) or key.endswith(ef.rsplit("/", 1)[-1]):
            return view
    return None


def _chain_lib_views(inp, bin_index, limit=_MAX_CHAIN_LIBS):
    """BinaryViews for the shared libraries on this input's processing
    chain (cross-library attribution: GoAhead routes live in libgo.so,
    session checks in libucapi.so, ...)."""
    views = []
    seen = set()
    for hop in inp.get("processing_chain") or []:
        for lib in hop.get("libs") or []:
            base = str(lib).rsplit("/", 1)[-1]
            if not base or base in seen:
                continue
            seen.add(base)
            view = bin_index.get(base) or bin_index.get(str(lib))
            if view is not None:
                views.append(view)
            if len(views) >= limit:
                return views
    return views


def _read_source_limited(pseudo_root, md5, addr, limit=120_000):
    text = classify._read_source(pseudo_root, md5, addr)
    return text[:limit] if text else ""


def _build_routing(view, inp, pseudo_root):
    """Trace request flow listen -> accept -> parse -> normalize/dispatch ->
    handler for one input. Returns (routing, dispatchers, parsers,
    normalizers, handlers_with_roles, auth_funcs, boundary_note).

    For multicall binaries (busybox) the walk is anchored at the applet's
    own dispatch site; when the applet boundary cannot be resolved, no
    whole-binary roam is emitted — the surface degrades to an annotated
    static-only shape instead of borrowing sibling applets' functions."""
    routing, dispatchers, parsers, normalizers = [], [], [], []
    handlers, auth_funcs = [], []
    boundary_note = None
    entry_file = (inp.get("entry_files") or [None])[0] or inp["service"]

    routing.append({
        "stage": "listen",
        "file": entry_file,
        "detail": f"{inp['service']} binds {inp.get('address')}:"
                  f"{inp.get('port')}/{inp.get('transport')} "
                  f"({inp.get('protocol')})",
    })
    if view is None:
        routing.append({
            "stage": "unavailable",
            "file": entry_file,
            "detail": "binary not decompiled in this job — downstream "
                      "stages unknown (static-only surface)",
        })
        return routing, dispatchers, parsers, normalizers, handlers, \
            auth_funcs, boundary_note

    applet = None
    if elfchain.is_multicall_name(view.path):
        svc_name = str(inp.get("service") or "")
        if svc_name and " " not in svc_name and ":" not in svc_name:
            applet = svc_name.lower()
    if applet:
        starts, boundary_note = classify.anchor_applet(view, applet)
        if not starts:
            routing.append({
                "stage": "unresolved",
                "file": view.path or entry_file,
                "detail": f"{boundary_note} — no whole-binary roam emitted; "
                          f"downstream stages unattributed "
                          f"(static-only surface)",
            })
            return routing, dispatchers, parsers, normalizers, handlers, \
                auth_funcs, boundary_note
        boundary_note = f"applet-anchored ({boundary_note})"
        chain = view.bfs_chain(starts, max_depth=5, limit=200)
    else:
        starts = view.entry_functions()
        chain = view.bfs_chain(starts) if starts else []
    seen_roles = {"parse": set(), "normalize": set(), "dispatch": set()}
    for addr in chain:
        func = view.functions[addr]
        if classify.is_stub_name(func.get("name")):
            continue  # import stubs carry no routing semantics
        src = _read_source_limited(pseudo_root, view.md5, addr)
        roles = classify.classify_function(func, src)
        label = func.get("ai_name") or func.get("rule_name") or \
            func.get("name", "?")
        for role in roles:
            item = {"file": view.path or entry_file,
                    "function": func.get("name", "?"),
                    "detail": f"{label} @ {addr}"}
            if role == "accept":
                routing.append({"stage": "accept", **item,
                                "detail": f"socket accept/read in {label}"})
            elif role == "parse" and addr not in seen_roles["parse"]:
                parsers.append(item)
                seen_roles["parse"].add(addr)
            elif role == "normalize" and addr not in seen_roles["normalize"]:
                normalizers.append(item)
                seen_roles["normalize"].add(addr)
            elif role == "dispatch" and addr not in seen_roles["dispatch"]:
                dispatchers.append(item)
                seen_roles["dispatch"].add(addr)
            elif role == "handler":
                handlers.append((addr, func))
            elif role == "auth":
                auth_funcs.append((addr, func))
    if parsers:
        routing.append({"stage": "parse", "file": parsers[0]["file"],
                        "detail": "; ".join(p["function"] for p in
                                            parsers[:5])})
    if normalizers:
        routing.append({"stage": "normalize",
                        "file": normalizers[0]["file"],
                        "detail": "; ".join(n["function"] for n in
                                            normalizers[:5])})
    if dispatchers:
        routing.append({"stage": "dispatch", "file": dispatchers[0]["file"],
                        "detail": "; ".join(d["function"] for d in
                                            dispatchers[:5])})
    return routing, dispatchers, parsers, normalizers, handlers, \
        auth_funcs, boundary_note


def _route_targets(inp):
    """Files this input's routes may live in: its own entry binaries plus
    every library on the processing chain (GoAhead's route table sits in
    libgo.so while the httpd input owns it)."""
    targets = set()
    for f in inp.get("entry_files") or []:
        targets.add(f.rsplit("/", 1)[-1])
        targets.add(f)
    for hop in inp.get("processing_chain") or []:
        if hop.get("file"):
            targets.add(hop["file"].rsplit("/", 1)[-1])
        for lib in hop.get("libs") or []:
            targets.add(str(lib).rsplit("/", 1)[-1])
            targets.add(str(lib))
    return {t for t in targets if t}


def _routes_for_input(inp, routes):
    """Routes attributable to this input, cross-library aware. Import stubs
    are never acceptable handlers."""
    targets = _route_targets(inp)
    out = []
    for r in routes or []:
        bp = r.get("binary_path") or ""
        if not bp:
            continue
        base = bp.rsplit("/", 1)[-1]
        if not (base in targets or bp in targets):
            continue
        handler = r.get("handler_name") or ""
        if classify.is_stub_name(handler):
            continue
        out.append(r)
    return out


def _pick_final_handler(inp, view, handlers, routes):
    """Final processing endpoint for this surface."""
    matched = _routes_for_input(inp, routes)
    # 1) static route table handler belonging to this binary or one of its
    #    processing-chain libraries
    best = None
    for r in matched:
        if best is None or r.get("confidence", 0) > \
                best.get("confidence", 0):
            best = r
    if best:
        return {
            "file": best.get("binary_path", ""),
            "function": best.get("handler_name", "?"),
            "route": best.get("route", ""),
            "detail": f"route-table handler ({best.get('method', '?')}) "
                      f"@ {best.get('handler_addr', '?')} "
                      f"confidence={best.get('confidence', '?')}",
        }
    # 2) deepest handler-role function on the chain — import stubs and
    #    thunks are skipped, they are never terminal handlers
    if view is not None and handlers:
        real_handlers = [(a, f) for a, f in handlers
                         if not classify.is_stub_name(f.get("name"))]
        if real_handlers:
            addr, func = real_handlers[-1]
            return {
                "file": view.path,
                "function": func.get("name", "?"),
                "route": "",
                "detail": f"request handler @ {addr} "
                          f"(role-classified from call chain)",
            }
    # 3) static-only fallback
    return {
        "file": (inp.get("entry_files") or ["unknown"])[0],
        "function": "unknown",
        "route": "",
        "detail": "handler not resolved (binary not decompiled or no "
                  "route table); endpoint = daemon main loop",
    }


def _carrier_bindings(inp, view, handlers, pseudo_root):
    """(real_bindings, placeholder_hint).

    carrier_bindings only ever holds regex hits backed by a pseudo-C line.
    When nothing concrete was found, a single placeholder goes to
    `carrier_hint` with quality=placeholder so downstream consumers can
    tell inference from evidence. Scan range covers the handler chain with
    a hard cap (previously only the first 3 handlers were read)."""
    bindings = []
    if view is not None:
        for addr, func in handlers[:10]:
            src = _read_source_limited(pseudo_root, view.md5, addr)
            bindings.extend(classify.extract_carrier_bindings(func, src))
    seen, out = set(), []
    for b in bindings:
        k = (b["carrier"], b["destination"])
        if k not in seen:
            seen.add(k)
            out.append(b)
    out = out[:12]
    hint = None
    if not out:
        carrier = {
            "tcp": "TCP request payload", "udp": "UDP datagram payload",
        }.get(inp.get("transport"), "request payload")
        for t in (inp.get("input_types") or [])[:2]:
            carrier = t
            break
        hint = {
            "carrier": carrier,
            "destination": f"receive buffer of {inp['service']} "
                           f"(unresolved variable — no pseudo-C binding)",
            "quality": "placeholder",
            "evidence": "static inference from identification.json",
        }
    return out, hint


def _find_auth_funcs(views, pseudo_root):
    """Structural auth scan across the input binary and its chain
    libraries. Only functions with a credential compare AND a rejection
    branch qualify; chain membership is ordered by call edges per binary."""
    per_view = []
    for view in views:
        scored = []
        reads = 0
        for addr, func in view.functions.items():
            # cheap metadata prefilter before any file IO
            calls = {classify.attack_surface._norm(c)
                     for c in (func.get("calls") or [])}
            if not calls & classify._CRED_COMPARE:
                continue
            if reads >= _MAX_AUTH_SRC_READS:
                break
            reads += 1
            src = _read_source_limited(pseudo_root, view.md5, addr)
            detail = classify.auth_evidence(func, src)
            if detail:
                scored.append((addr, func, detail))
        if scored:
            ordered = classify.order_auth_chain(
                view, [a for a, _, _ in scored])
            by_addr = {a: (f, d) for a, f, d in scored}
            per_view.append((view, [(a, *by_addr[a]) for a in ordered]))
    return per_view


def build_surfaces(doc, symbols=None, routes=None, pseudo_root=None):
    """identification document -> (surface_docs, auth_docs)"""
    bin_index = _binary_index(symbols)
    surfaces = []
    auth_chains = {}   # primary md5 -> {"funcs": [...], "applies": [...]}

    for inp in doc.get("inputs", []):
        in_id = inp["id"]
        as_id = "AS-" + in_id.split("-", 1)[1]
        view = None
        for ef in inp.get("entry_files") or []:
            view = _find_view(bin_index, ef)
            if view:
                break
        lib_views = _chain_lib_views(inp, bin_index)

        # route table recovery: routes.json plus GoAhead registration calls
        # visible in pseudo-C, both attributed cross-library
        all_routes = list(routes or [])
        if pseudo_root is not None:
            for v in [view, *lib_views] if view else lib_views:
                if v is None:
                    continue
                all_routes.extend(classify.extract_goahead_routes(
                    v, lambda a, vv=v: _read_source_limited(
                        pseudo_root, vv.md5, a)))
        seen_routes = set()
        deduped_routes = []
        for r in all_routes:
            key = (r.get("route"), r.get("binary_path"),
                   r.get("handler_name"))
            if key not in seen_routes:
                seen_routes.add(key)
                deduped_routes.append(r)
        matched_routes = _routes_for_input(inp, deduped_routes)

        routing, dispatchers, parsers, normalizers, handlers, auth_funcs, \
            boundary_note = _build_routing(view, inp, pseudo_root)
        final_handler = _pick_final_handler(inp, view, handlers,
                                            deduped_routes)

        auth_refs = []
        posture = list(inp.get("auth_posture") or [])
        scan_views = ([view] if view else []) + lib_views
        per_view_auth = _find_auth_funcs(scan_views, pseudo_root) \
            if scan_views else []
        if per_view_auth or posture:
            primary_md5 = view.md5 if view is not None else \
                f"static:{in_id}"
            chain_id = auth_chains.setdefault(primary_md5, {
                "funcs": [], "applies": [], "binary": view.path
                if view else "", "notes": [], "cross_lib": [],
            })
            for av, funcs in per_view_auth:
                target = "funcs" if av is view else "cross_lib"
                for addr, func, detail in funcs:
                    if addr not in [t[0] for t in chain_id[target]]:
                        chain_id[target].append((addr, func, detail,
                                                 av.path))
            for note in posture:
                if note not in chain_id["notes"]:
                    chain_id["notes"].append(note)
            chain_id["applies"].append(as_id)
            auth_refs.append(primary_md5)  # resolved to AS-AUTH ids below

        bindings, carrier_hint = _carrier_bindings(inp, view, handlers,
                                                   pseudo_root)
        evidence_bits = [f"input {in_id}: {inp.get('evidence', '')}"[:300]]
        if view is not None:
            evidence_bits.append(
                f"decompiled {view.path or '?'} md5={view.md5} "
                f"({len(view.functions)} functions)")
        if boundary_note:
            evidence_bits.append(boundary_note)

        surface = {
            "surface_id": as_id,
            "source_input": in_id,
            "service": inp["service"],
            "entry": {
                "protocol": inp.get("protocol"),
                "address": inp.get("address"),
                "port": inp.get("port"),
                "transport": inp.get("transport"),
                "file": (inp.get("entry_files") or ["unknown"])[0],
            },
            "routing_path": routing,
            "dispatchers": dispatchers,
            "parsers": parsers,
            "normalizers": normalizers,
            "final_handler": final_handler,
            "carrier_bindings": bindings,
            "carrier_hint": carrier_hint,
            "auth_chain_refs": auth_refs,
            "evidence": " | ".join(e for e in evidence_bits if e),
            "schema_version": SCHEMA_VERSION,
            "generated_at": _now(),
        }
        if matched_routes:
            surface["endpoints"] = [
                {"route": r.get("route"), "method": r.get("method"),
                 "handler": r.get("handler_name"),
                 "handler_addr": r.get("handler_addr"),
                 "binary": r.get("binary_path"),
                 "confidence": r.get("confidence")}
                for r in matched_routes[:24]]
        if boundary_note and "unresolved" in boundary_note:
            surface["applet_boundary"] = "unresolved"
            surface["confidence"] = "low"
        surfaces.append(surface)

    # sequential, deterministic auth-chain ids (AS-AUTH-001, ...) — the
    # surfaces carry binary md5 placeholders until this point
    auth_ids = {md5: f"AS-AUTH-{n:03d}"
                for n, md5 in enumerate(sorted(auth_chains), 1)}
    for s in surfaces:
        s["auth_chain_refs"] = [auth_ids[m] for m in s["auth_chain_refs"]]

    auth_docs = []
    for md5, chain in sorted(auth_chains.items()):
        aid = auth_ids[md5]
        stages = []
        for addr, func, detail, path in chain["funcs"][:8]:
            name = func.get("name", "?")
            label = func.get("ai_name") or func.get("rule_name") or name
            stage = ("credential-parse" if any(
                        k in name.lower() for k in ("cookie", "parse"))
                     else "session-lookup" if "session" in name.lower()
                     else "credential-verify")
            stages.append({"stage": stage, "file": path or "?",
                           "function": name,
                           "detail": f"{label} @ {addr} — {detail}"})
        for addr, func, detail, path in chain["cross_lib"][:6]:
            name = func.get("name", "?")
            label = func.get("ai_name") or func.get("rule_name") or name
            stages.append({"stage": "cross-library-auth",
                           "file": path or "?",
                           "function": name,
                           "detail": f"{label} @ {addr} — {detail}"})
        for note in chain["notes"]:
            stages.append({"stage": "config-posture",
                           "file": chain["binary"] or "?",
                           "function": "(config)",
                           "detail": note})
        auth_docs.append({
            "surface_id": aid,
            "type": "authorization_chain",
            "applies_to": sorted(set(chain["applies"])),
            "chain": stages,
            "carrier_bindings": [],
            "notes": chain["notes"],
            "bypass_notes": "static analysis only — verify authLevel=0 / "
                            "whitelist / anonymous route bypasses manually",
            "evidence": f"structural auth evidence (credential compare + "
                        f"rejection branch) reachable from input chains in "
                        f"{chain['binary'] or md5}",
            "schema_version": SCHEMA_VERSION,
            "generated_at": _now(),
        })
    return surfaces, auth_docs


def validate(doc, surfaces, auth_docs):
    """Acceptance gates. Returns (errors, warnings)."""
    errors, warnings = [], []
    in_ids = [i["id"] for i in doc.get("inputs", [])]
    as_for_in = {}
    for s in surfaces:
        as_for_in.setdefault(s["source_input"], []).append(s["surface_id"])
    # gate 1: every IN has exactly one AS
    for in_id in in_ids:
        n = len(as_for_in.get(in_id, []))
        if n == 0:
            errors.append(f"{in_id}: no AS file")
        elif n > 1:
            errors.append(f"{in_id}: multiple AS files {as_for_in[in_id]}")
    # gate 2: required fields present and non-empty
    for s in surfaces:
        for field in REQUIRED_SURFACE_FIELDS:
            if field not in s:
                errors.append(f"{s['surface_id']}: missing field {field}")
            elif field == "routing_path" and not s[field]:
                errors.append(f"{s['surface_id']}: empty {field}")
        if not s.get("carrier_bindings"):
            hint = s.get("carrier_hint") or {}
            if hint.get("quality") != "placeholder":
                errors.append(f"{s['surface_id']}: empty carrier_bindings "
                              f"and no placeholder carrier_hint")
            else:
                warnings.append(f"{s['surface_id']}: carrier bindings are "
                                f"placeholder-grade (no pseudo-C evidence)")
        fh = s.get("final_handler", {})
        # a thunk / import stub must never be the terminal handler
        if classify.is_stub_name(fh.get("function")):
            errors.append(f"{s['surface_id']}: final_handler is an import "
                          f"stub/thunk ({fh.get('function')})")
        if fh.get("function") == "unknown":
            warnings.append(f"{s['surface_id']}: final_handler unresolved "
                            f"(static-only)")
        if not s.get("dispatchers"):
            warnings.append(f"{s['surface_id']}: no dispatcher identified")
        for ref in s.get("auth_chain_refs", []):
            if ref not in {a["surface_id"] for a in auth_docs}:
                errors.append(f"{s['surface_id']}: dangling auth ref {ref}")
    for a in auth_docs:
        if not a.get("chain"):
            errors.append(f"{a['surface_id']}: empty auth chain")
        for ap in a.get("applies_to", []):
            if not any(s["surface_id"] == ap for s in surfaces):
                errors.append(f"{a['surface_id']}: applies_to unknown {ap}")
    return errors, warnings


def run_job(job_id, data_dir):
    data_dir = Path(data_dir)
    started = time.time()
    inputs_doc = _load_json(data_dir / "inputs" / job_id / "identification.json")
    if inputs_doc is None:
        raise FileNotFoundError(
            f"identification.json not found for job {job_id} — run the "
            f"inputs stage first")
    pseudo_root = data_dir / "pseudocode" / job_id
    symbols = _load_json(pseudo_root / "symbols.json")
    routes = (_load_json(data_dir / "routes" / job_id / "routes.json")
              or {}).get("routes")

    surfaces, auth_docs = build_surfaces(inputs_doc, symbols, routes,
                                         pseudo_root)
    errors, warnings = validate(inputs_doc, surfaces, auth_docs)

    out_dir = data_dir / "surfaces" / job_id
    info_dir = out_dir / "information"
    info_dir.mkdir(parents=True, exist_ok=True)
    for s in surfaces:
        (info_dir / f"{s['surface_id']}.json").write_text(
            json.dumps(s, indent=1, ensure_ascii=False), encoding="utf-8")
    for a in auth_docs:
        (info_dir / f"{a['surface_id']}.json").write_text(
            json.dumps(a, indent=1, ensure_ascii=False), encoding="utf-8")
    (info_dir / "identification.json").write_text(
        json.dumps(inputs_doc, indent=1, ensure_ascii=False), encoding="utf-8")

    summary = {
        "job_id": job_id,
        "status": "ok" if not errors else "gate_failed",
        "surfaces": len(surfaces),
        "auth_chains": len(auth_docs),
        "gate_errors": errors,
        "gate_warnings": warnings,
        # static-only accounting: unresolved handlers and placeholder-grade
        # carrier bindings are counted separately, never blended into real
        # evidence counts
        "static_only": sum(1 for s in surfaces
                           if s["final_handler"]["function"] == "unknown"),
        "placeholder_bindings": sum(
            1 for s in surfaces
            if not s["carrier_bindings"]
            and (s.get("carrier_hint") or {}).get("quality")
            == "placeholder"),
        "elapsed_seconds": round(time.time() - started, 2),
    }
    (out_dir / "surfaces_done.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    data_dir = Path(os.getenv("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    print(json.dumps(run_job(argv[1], data_dir), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
