"""External-input identification (M6a) -> identification.json.

Runs after extraction (no decompile needed). Scans every root found in the
extracted firmware (main rootfs, initrd, package containers) for network
listeners and web endpoints, resolves address/port/transport, the ELF
processing chain (DT_NEEDED libs) and dispatch references, then classifies
every candidate as a public input or an excluded non-public listener.

Output schema follows the platform contract (see information/_schema.json
and the DSM reference identification.json): every public external input is
an IN-xxx entry with processing_chain + dispatch_chain so the vuln-mining
agent can consume it directly.

Acceptance gates (checked and recorded, also enforced by validate()):
  gate 1  every emitted input is publicly reachable — never loopback /
          localhost / unix-socket only
  gate 2  completeness — every discovered listener appears exactly once,
          either in inputs[] or in metadata.excluded[] with a reason

CLI:
  python -m pipeline.inputs.runner <job_id>            # normal pipeline mode
  python -m pipeline.inputs.runner --rootfs <dir> -o <out.json>   # standalone
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.inputs import discover, elfchain, services

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

GENERIC_TCP_TYPES = ["TCP request payload"]
GENERIC_UDP_TYPES = ["UDP datagram payload"]
WEB_TYPES = ["URL path", "query string parameters", "HTTP headers",
             "cookies", "POST body"]


def _now():
    return datetime.now(timezone.utc).isoformat()


def _entry_name(cand):
    """Human service label for a candidate."""
    if cand.kind == "web_endpoint":
        if cand.name.startswith("vhost:"):
            return f"web vhost {cand.name[6:]} (frontend-routed service)"
        if cand.name.startswith("webapi:"):
            parent = cand.name.split(":", 2)[-1]
            label = parent.rsplit("/", 1)[-1] if "/" in parent else parent
            if label in (".", ""):
                label = "webapi"
            return f"{label} (webapi module group)"
        if cand.name.startswith("cgi:"):
            label = cand.name.split(":", 2)[-1]
            return f"{label} CGI endpoints"
    return cand.name


def _build_entry(idx, cand, rootfs, prefix):
    svc = cand.svc or {}
    entry_files = []
    for f in [cand.path, *cand.endpoints]:
        if f and f not in entry_files:
            entry_files.append(f if not prefix else prefix + f)
    processing_chain = []
    dispatch = []
    if cand.path:
        # multicall-binary resolution: telnetd -> busybox etc. The symlink
        # target is the real ELF whose processing chain matters; the applet
        # identity (argv[0]) is recorded as a dispatch-chain hop. Socket
        # imports and string scans of the shared binary are annotated —
        # they describe the whole multicall binary, not the applet.
        real, real_rel, multicall = elfchain.resolve_real(rootfs, cand.path)
        full = rootfs / cand.path
        if real_rel != cand.path:
            rel = real_rel
            entry_files.append(prefix + rel if prefix else rel)
            dispatch.append({
                "route": "argv[0] multicall dispatch",
                "file": prefix + rel if prefix else rel,
                "note": f"{cand.name} is a symlink to {rel}; "
                        f"applet selected via argv[0]"})
        needed, undef = elfchain.elf_facts(real)
        libs = elfchain.resolve_libs(rootfs, needed) if needed else []
        unresolved = elfchain.unresolved_needed(needed, libs) if needed else []
        processing_chain.append(
            {"file": (prefix + real_rel) if prefix else real_rel,
             "libs": libs,
             "unresolved_needed": unresolved,
             "needed_complete": not unresolved})
        for ref in elfchain.exec_paths(real, rootfs):
            if ref.lstrip("/") == cand.path:
                continue
            note = f"executable path referenced in {cand.name} strings " \
                   f"(spawn/exec candidate)"
            if multicall:
                note += " [multicall binary scan — not applet-specific]"
            dispatch.append({
                "file": prefix + ref.lstrip("/") if prefix else ref.lstrip("/"),
                "note": note})
    if cand.kind == "web_endpoint":
        input_types = list(WEB_TYPES)
        if cand.name.startswith("webapi:"):
            input_types.append("webapi RPC parameters (api/method/version)")
    else:
        input_types = list(svc.get("input_types") or
                           (GENERIC_UDP_TYPES if cand.transport == "udp"
                            else GENERIC_TCP_TYPES))
    evidence = list(cand.evidence)
    if cand.path:
        real, _, multicall = elfchain.resolve_real(rootfs, cand.path)
        _, undef = elfchain.elf_facts(real)
        sock = sorted(set(undef) & elfchain.SOCKET_SYMS)
        if sock:
            if multicall:
                evidence.append(
                    f"multicall binary imports socket API (union over all "
                    f"applets, applet-level attribution unresolved): "
                    f"{', '.join(sock)}")
            else:
                evidence.append(
                    f"binary imports socket API: {', '.join(sock)}")
    port = cand.port
    if cand.ports_ssl and len(cand.ports_ssl) > 1:
        port = [p for p, _ in cand.ports_ssl]
    return {
        "id": f"IN-{idx:03d}",
        "protocol": cand.protocol,
        "service": _entry_name(cand),
        "address": cand.address,
        "port": port,
        "transport": cand.transport,
        "public": True,
        "input_types": input_types,
        "entry_files": entry_files,
        "processing_chain": processing_chain,
        "dispatch_chain": dispatch,
        "evidence": "; ".join(evidence) if evidence else "",
        "evidence_grade": cand.evidence_grade,
        "port_source": cand.port_source,
        "autostart": bool(cand.autostart),
        "needs_confirmation": bool(cand.needs_confirmation),
        "auth_posture": list(cand.auth_posture),
        "notes": "",
    }


def _exclusion_reason(cand):
    svc = cand.svc or {}
    if cand.drop_reason:
        return cand.drop_reason
    if svc.get("not_public"):
        return ("infrastructure/control daemon — not part of the public "
                "network attack surface")
    if svc.get("loopback_only"):
        return "binds loopback only by configuration/default"
    if cand.transport == "unix":
        return "unix-socket only (not network reachable)"
    if not services.is_public_address(cand.address):
        return f"binds loopback address {cand.address}"
    return None


def build_document(base, target="unknown", extra_meta=None):
    """Scan all roots under `base` and build the identification document."""
    notes = []
    roots = discover.locate_roots(base, notes=notes)
    if not roots:
        raise FileNotFoundError(f"no rootfs located under {base}")

    inputs, excluded = [], []
    discovered = 0   # gate 2 independent recount: every candidate found
    for root, prefix in roots:
        for cand in discover.discover(root):
            discovered += 1
            reason = _exclusion_reason(cand)
            if reason is not None:
                label = (prefix + cand.path) if cand.path else cand.name
                kind = "not-promoted" if cand.drop_reason else "not-public"
                excluded.append(f"EXCLUDED({kind}): {label} "
                                f"({cand.protocol}: {reason})")
                continue
            inputs.append((cand, root, prefix))

    entries = []
    for idx, (cand, root, prefix) in enumerate(inputs, 1):
        entries.append(_build_entry(idx, cand, root, prefix))

    grade_counts = {}
    for e in entries:
        grade_counts[e["evidence_grade"]] = \
            grade_counts.get(e["evidence_grade"], 0) + 1
    kb_default_share = (grade_counts.get("kb_default", 0) / len(entries)
                        if entries else 0.0)

    doc = {
        "metadata": {
            "target": target,
            "roots": [f"{r} (prefix: {p or '-'})" for r, p in roots],
            "generated_by": "fwgraph.pipeline.inputs.v2",
            "generated_at": _now(),
            "total_inputs": len(entries),
            "candidates_found": discovered,
            "evidence_grades": grade_counts,
            "kb_default_share": round(kb_default_share, 3),
            "gate_1": "所有条目均为非回环/非 localhost 的公网可访问输入",
            "gate_2": "发现的每个监听者恰好在 inputs 或 excluded 中出现一次",
            "excluded": sorted(excluded),
            "unreadable": notes,
        },
        "inputs": entries,
    }
    if extra_meta:
        doc["metadata"].update(extra_meta)
    return doc


def validate(doc):
    """Acceptance-gate check. Returns (errors, warnings) — both empty ==
    clean pass. Warnings never fail the gate; errors do."""
    errors, warnings = [], []
    inputs = doc.get("inputs", [])
    meta = doc.get("metadata", {})

    # gate 1: public-only
    for ent in inputs:
        if not ent.get("public", False):
            errors.append(f"{ent.get('id')}: public flag false")
        addr = ent.get("address")
        if not services.is_public_address(addr):
            errors.append(f"{ent.get('id')}: loopback address {addr!r}")
        if ent.get("transport") == "unix":
            errors.append(f"{ent.get('id')}: unix transport not public")
        for field in ("protocol", "service", "transport", "input_types"):
            if not ent.get(field):
                errors.append(f"{ent.get('id')}: missing {field}")
        grade = ent.get("evidence_grade")
        if grade not in ("observed", "config", "kb_default", "candidate"):
            errors.append(f"{ent.get('id')}: missing/invalid evidence_grade")
        if grade in ("kb_default", "candidate") and \
                not ent.get("needs_confirmation"):
            errors.append(f"{ent.get('id')}: {grade} entry without "
                          f"needs_confirmation")
        if ent.get("port") is None:
            warnings.append(f"{ent.get('id')}: no port resolved")

    # gate 2: independent recount — inputs + excluded must account for every
    # candidate the discovery pass found
    if meta.get("total_inputs") != len(inputs):
        errors.append("metadata.total_inputs != len(inputs)")
    found = meta.get("candidates_found")
    if found is not None:
        accounted = len(inputs) + len(meta.get("excluded", []))
        if found != accounted:
            errors.append(
                f"gate 2 accounting mismatch: {found} candidates found but "
                f"inputs({len(inputs)}) + excluded("
                f"{len(meta.get('excluded', []))}) = {accounted}")
    ids = [e.get("id") for e in inputs]
    if len(set(ids)) != len(ids):
        errors.append("duplicate input ids")

    # evidence-quality warning: a report that is mostly knowledge-base
    # guesses needs human confirmation before mining
    share = meta.get("kb_default_share", 0.0)
    if len(inputs) >= 4 and share > 0.5:
        warnings.append(f"kb_default share {share:.0%} of inputs exceeds "
                        f"50% — mostly unconfirmed knowledge-base defaults")
    return errors, warnings


def run_job(job_id, data_dir, base_override=None, firmware_name=None):
    data_dir = Path(data_dir)
    started = time.time()
    extracted_dir = data_dir / "extracted" / job_id
    base = Path(base_override) if base_override else extracted_dir
    target = firmware_name or job_id
    if firmware_name is None:
        manifest = extracted_dir / "manifest.json"
        if manifest.is_file():
            try:
                target = json.loads(manifest.read_text(
                    encoding="utf-8")).get("firmware", job_id)
            except (json.JSONDecodeError, OSError):
                pass

    doc = build_document(base, target=target, extra_meta={"job_id": job_id})
    errors, warnings = validate(doc)

    out_dir = data_dir / "inputs" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "identification.json").write_text(
        json.dumps(doc, indent=1, ensure_ascii=False), encoding="utf-8")
    summary = {
        "job_id": job_id, "status": "ok" if not errors else "gate_failed",
        "roots": doc["metadata"]["roots"],
        "total_inputs": doc["metadata"]["total_inputs"],
        "candidates_found": doc["metadata"]["candidates_found"],
        "evidence_grades": doc["metadata"]["evidence_grades"],
        "kb_default_share": doc["metadata"]["kb_default_share"],
        "excluded": len(doc["metadata"]["excluded"]),
        "gate_errors": errors,
        "gate_warnings": warnings,
        "elapsed_seconds": round(time.time() - started, 2),
    }
    (out_dir / "inputs_done.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    if argv[1] == "--rootfs":
        base = Path(argv[2])
        out = Path(argv[argv.index("-o") + 1]) if "-o" in argv else None
        doc = build_document(base, target=base.name)
        errors, warnings = validate(doc)
        text = json.dumps(doc, indent=1, ensure_ascii=False)
        if out:
            out.write_text(text, encoding="utf-8")
            print(f"wrote {out} ({doc['metadata']['total_inputs']} inputs, "
                  f"{len(doc['metadata']['excluded'])} excluded)")
        else:
            print(text)
        if warnings:
            print("GATE WARNINGS:", json.dumps(warnings, indent=1,
                                               ensure_ascii=False))
        if errors:
            print("GATE ERRORS:", json.dumps(errors, indent=1,
                                             ensure_ascii=False))
            return 2
        return 0
    data_dir = Path(os.getenv("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    print(json.dumps(run_job(argv[1], data_dir), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
