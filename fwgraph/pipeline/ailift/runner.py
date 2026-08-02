"""AILIFT tag mode: funnel -> LLM -> validate -> symbols.json tags.

Function names and IDBs are immutable in this mode. The registry remains the
durable resume/audit store; successful tag rows are immediately `done` because
there is no IDA apply or second-pass export phase.

CLI: python -m pipeline.ailift.runner <job_id>
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.ailift import backfill, funnel, llm
from pipeline.ailift.registry import Registry, SpecValidator
from pipeline.decompile.annotate import load_spec

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]


def _cfg(name, default):
    return os.getenv(name, default)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _read_code(funcs_dir, addr):
    path = funcs_dir / f"{addr}.c"
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _caller_map(functions):
    callers = {}
    for func in functions:
        for callee in func.get("calls", []):
            callers.setdefault(callee, []).append(func.get("name", ""))
    return callers


def _fallback_libc(func):
    for value in (func.get("ai_name"), func.get("rule_name"),
                  func.get("libc_equiv"), func.get("name")):
        guessed = backfill.guess_libc_equiv(value)
        if guessed:
            return guessed
    return None


def _phase_llm(job_id, md5, entry, funcs_dir, registry, validator, client,
               max_funcs, noise_ratio, funnel_result=None, selected_addrs=None):
    functions = entry.get("functions", [])
    by_addr = {func["addr"]: func for func in functions}
    result = funnel_result or funnel.run_funnel(
        functions, max_funcs=max_funcs, noise_ratio=noise_ratio,
        code_reader=lambda addr: _read_code(funcs_dir, addr))
    candidates = result["candidates"]
    job_budget_skipped = 0
    if selected_addrs is not None:
        job_budget_skipped = sum(
            1 for candidate in candidates if candidate["addr"] not in selected_addrs
        )
        candidates = [candidate for candidate in candidates
                      if candidate["addr"] in selected_addrs]
    todo = [candidate for candidate in candidates
            if not registry.is_terminal(md5, candidate["addr"])]
    callers = _caller_map(functions)
    stats = {"funnel": result["stats"],
             "job_budget_selected": len(candidates),
             "job_budget_skipped": job_budget_skipped,
             "resumed_skip": len(candidates) - len(todo),
             "llm_sent": 0, "tagged": 0, "rejected": 0, "errors": 0}
    if not todo:
        return stats

    system = llm.build_system_prompt(validator.domains)
    items = []
    for candidate in todo:
        func = by_addr[candidate["addr"]]
        items.append({
            "candidate": candidate,
            "system": system,
            "user": llm.build_user_prompt(
                func, _read_code(funcs_dir, candidate["addr"]),
                callers.get(func.get("name", ""), []),
                binary_path=entry.get("path", ""), arch=entry.get("arch", "")),
        })

    stats["llm_sent"] = len(items)
    for item, parsed, error in llm.suggest_batch(client, items):
        candidate = item["candidate"]
        func = by_addr[candidate["addr"]]
        if error or parsed is None:
            registry.record(
                job_id, md5, candidate["addr"], candidate["current_name"],
                None, None, error or "no result", "ai", "error")
            stats["errors"] += 1
            continue
        confidence = parsed["confidence"]
        domain = parsed.get("domain")
        libc_equiv = parsed.get("libc_equiv")
        if domain is not None and domain not in validator.domains:
            registry.record(
                job_id, md5, candidate["addr"], candidate["current_name"],
                None, confidence, f"invalid_domain:{domain}: {parsed['reason']}",
                "ai", "rejected", libc_equiv=libc_equiv)
            stats["rejected"] += 1
            continue
        fallback = None
        if libc_equiv is None:
            fallback = _fallback_libc(func)
            libc_equiv = fallback
        if not domain and not libc_equiv:
            registry.record(
                job_id, md5, candidate["addr"], candidate["current_name"],
                None, confidence, f"no_tags: {parsed['reason']}",
                "ai", "rejected")
            stats["rejected"] += 1
            continue
        if confidence < validator.confidence_min:
            registry.record(
                job_id, md5, candidate["addr"], candidate["current_name"],
                None, confidence, f"low_confidence: {parsed['reason']}",
                "ai", "rejected", libc_equiv=libc_equiv, domain=domain)
            stats["rejected"] += 1
            continue
        source = "backfill" if fallback and parsed.get("libc_equiv") is None \
            else "ai"
        registry.record(
            job_id, md5, candidate["addr"], candidate["current_name"],
            None, confidence, parsed["reason"], source, "done",
            libc_equiv=libc_equiv, domain=domain)
        stats["tagged"] += 1
    return stats


def _binary_priority(entry, funnel_result):
    """Prefer attack-facing executables over generic shared libraries."""
    path = str(entry.get("path") or "").replace("\\", "/").lower()
    name = path.rsplit("/", 1)[-1]
    score = min(int(funnel_result["stats"].get("l2_flagged", 0)), 20)
    if any(token in name for token in (
            "http", "web", "boa", "nginx", "lighttpd", "uhttpd",
            "upnp", "dnsmasq", "dropbear", "telnet", "nvram", "upgrade")):
        score += 40
    if any(part in path for part in ("/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/")):
        score += 10
    if entry.get("file_format") == "raw":
        score += 30
    if "/lib/" in path or ".so" in name:
        score -= 40
    return score


def _plan_job_candidates(symbols, pseudo_root, max_funcs, noise_ratio, max_job):
    """Build one deterministic, resumable candidate budget for the job."""
    plans = {}
    ranked = []
    for md5 in sorted(symbols.get("binaries", {})):
        entry = symbols["binaries"][md5]
        funcs_dir = pseudo_root / md5 / "functions"
        result = funnel.run_funnel(
            entry.get("functions", []), max_funcs=max_funcs,
            noise_ratio=noise_ratio,
            code_reader=lambda addr, root=funcs_dir: _read_code(root, addr))
        plans[md5] = result
        binary_priority = _binary_priority(entry, result)
        path = str(entry.get("path") or "")
        for candidate in result["candidates"]:
            ranked.append((
                -candidate["priority"], -binary_priority,
                -candidate["caller_count"], path, md5, candidate["addr"],
            ))
    ranked.sort()
    selected = {}
    for _priority, _binary_priority_value, _callers, _path, md5, addr in ranked[:max_job]:
        selected.setdefault(md5, set()).add(addr)
    return plans, selected, {
        "eligible": len(ranked),
        "selected": min(len(ranked), max_job),
        "truncated": max(0, len(ranked) - max_job),
        "selected_binaries": len(selected),
    }


def run_job(job_id, data_dir):
    mode = _cfg("AILIFT_MODE", "tag")
    if mode != "tag":
        raise ValueError(f"unsupported AILIFT_MODE={mode!r}; expected 'tag'")
    data_dir = Path(data_dir)
    started = time.time()
    pseudo_root = data_dir / "pseudocode" / job_id
    symbols_path = pseudo_root / "symbols.json"
    symbols = json.loads(symbols_path.read_text(encoding="utf-8"))
    validator = SpecValidator(load_spec())
    max_funcs = int(_cfg("AI_MAX_FUNCS_PER_BIN", "150"))
    max_job = max(0, int(_cfg("AI_MAX_FUNCS_PER_JOB", "300")))
    noise_ratio = float(_cfg("AI_NOISE_RATIO", "0.2"))
    registry = Registry(pseudo_root / "name_registry.db")
    client = llm.LLMClient.from_env(usage_path=pseudo_root / "llm_usage.json")
    summary = {"job_id": job_id, "mode": mode, "started_at": _now(),
               "finished_at": None, "max_funcs_per_bin": max_funcs,
               "max_funcs_per_job": max_job,
               "binaries": {}, "elapsed_seconds": 0.0}
    try:
        plans, selected, plan_stats = _plan_job_candidates(
            symbols, pseudo_root, max_funcs, noise_ratio, max_job)
        summary["job_budget"] = plan_stats
        for md5 in sorted(symbols.get("binaries", {})):
            entry = symbols["binaries"][md5]
            summary["binaries"][md5] = _phase_llm(
                job_id, md5, entry, pseudo_root / md5 / "functions",
                registry, validator, client, max_funcs, noise_ratio,
                funnel_result=plans[md5], selected_addrs=selected.get(md5, set()))
        client.flush()

        # Preserve zero-token recovery for legacy rows with old AI names.
        summary["backfill"] = {}
        for md5 in sorted(symbols.get("binaries", {})):
            result = backfill.backfill_registry(registry, md5)
            summary["backfill"][md5] = {
                key: result[key] for key in ("checked", "updated")}

        rows_by_md5 = {}
        for row in registry.rows():
            if row["status"] in ("accepted", "done"):
                rows_by_md5.setdefault(row["md5"], {})[row["addr"]] = row
        for md5, rows in rows_by_md5.items():
            entry = symbols.get("binaries", {}).get(md5)
            if not entry:
                continue
            for func in entry.get("functions", []):
                row = rows.get(func.get("addr"))
                if not row:
                    continue
                # Legacy rows remain readable, but tag-mode rows have no name.
                if row.get("new_name"):
                    func["ai_name"] = row["new_name"]
                if row.get("domain"):
                    func["domain"] = row["domain"]
                func["ai_confidence"] = row["confidence"]
                func["ai_reason"] = row["reason"]
                if row.get("libc_equiv"):
                    func["libc_equiv"] = row["libc_equiv"]
        temporary = symbols_path.with_suffix(symbols_path.suffix + ".tmp")
        temporary.write_text(json.dumps(symbols, indent=1), encoding="utf-8")
        temporary.replace(symbols_path)

        summary["registry"] = registry.stats()
        summary["llm_usage"] = dict(client.usage)
        summary["finished_at"] = _now()
        summary["elapsed_seconds"] = round(time.time() - started, 2)
        (pseudo_root / "ailift_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        return summary
    finally:
        registry.close()


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    data_dir = Path(_cfg("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    print(json.dumps(run_job(argv[1], data_dir), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
