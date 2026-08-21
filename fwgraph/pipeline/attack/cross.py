"""Cross-check static attack paths against authoritative trace.json files."""

import json
from collections import defaultdict
from pathlib import Path

from pipeline import evidence as ev
from pipeline.attack.surface import function_key


def load_observations(trace_root):
    observations = defaultdict(lambda: defaultdict(set))
    trace_root = Path(trace_root)
    if not trace_root.is_dir():
        return observations
    for trace_file in sorted(trace_root.glob("*/trace.json")):
        try:
            trace = json.loads(trace_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not str(trace.get("status") or "").startswith("ok"):
            continue
        trace_id = trace.get("trace_id")
        md5 = (trace.get("binary") or {}).get("md5")
        if not trace_id or not md5:
            continue
        for func in (trace.get("diff") or {}).get("functions", []):
            if func.get("addr"):
                observations[trace_id][md5].add(str(func["addr"]).lower())
    return observations


def apply(analysis, path_result, trace_root):
    observations = load_observations(trace_root)
    observed_by_key = defaultdict(set)
    for trace_id, binaries in observations.items():
        for md5, addresses in binaries.items():
            for addr in addresses:
                observed_by_key[function_key(md5, addr)].add(trace_id)

    path_keys = set(path_result.get("path_ids_by_key", {}))
    for key, node in analysis["nodes"].items():
        trace_ids = sorted(observed_by_key.get(key, []))
        node["observed_in_trace"] = bool(trace_ids)
        node["trace_ids"] = trace_ids
        node["verified_reachable"] = key in path_keys and bool(trace_ids)

    verified_paths = 0
    for path in path_result.get("paths", []):
        md5 = path["binary_md5"]
        addresses = {str(node["addr"]).lower() for node in path["chain"]}
        full_trace_ids = sorted(
            trace_id for trace_id, binaries in observations.items()
            if addresses and addresses <= binaries.get(md5, set()))
        observed_trace_ids = sorted({
            trace_id for addr in addresses
            for trace_id in observed_by_key.get(function_key(md5, addr), set())})
        observed_nodes = sum(
            bool(observed_by_key.get(function_key(md5, addr)))
            for addr in addresses)
        path["observed_node_count"] = observed_nodes
        path["observed_trace_ids"] = observed_trace_ids
        path["trace_ids"] = full_trace_ids
        path["verified_reachable"] = bool(full_trace_ids)
        if full_trace_ids:
            path["attribution"] = ev.ATTRIBUTION_VERIFIED
            verified_paths += 1
        elif observed_nodes:
            path["attribution"] = ev.ATTRIBUTION_OBSERVED
        else:
            path["attribution"] = ev.ATTRIBUTION_STATIC

    return {
        "traces_considered": len(observations),
        "observed_functions": len(observed_by_key),
        "verified_functions": sum(
            bool(node.get("verified_reachable"))
            for node in analysis["nodes"].values()),
        "verified_paths": verified_paths,
    }
