"""Compute deterministic, bounded attack paths and risk scores."""

import hashlib
from collections import defaultdict, deque


def _reverse_distances(adjacency, sinks, max_depth):
    reverse = defaultdict(set)
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].add(source)
    distance = {sink: 0 for sink in sinks}
    queue = deque(sinks)
    while queue:
        node = queue.popleft()
        if distance[node] >= max_depth:
            continue
        for parent in reverse.get(node, ()):
            if parent not in distance:
                distance[parent] = distance[node] + 1
                queue.append(parent)
    return distance


def _path_id(binary_md5, chain):
    value = binary_md5 + "|" + "|".join(chain)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _display(node):
    return {
        "addr": node.get("addr"), "name": node.get("name"),
        "ai_name": node.get("ai_name"),
        "libc_equiv": node.get("libc_equiv"),
        "asrc": node.get("asrc") or [],
        "asink": node.get("asink") or [],
    }


def compute(analysis, config):
    nodes = analysis["nodes"]
    adjacency = analysis["adjacency"]
    scoring = config.get("scoring", {})
    max_depth = int(scoring.get("max_depth", 8))
    path_limit = int(scoring.get("path_limit", 50))
    candidate_limit = int(scoring.get("candidate_limit", 5000))
    length_penalty = float(scoring.get("length_penalty", 0.22))
    sanitizer_penalty = float(scoring.get("sanitizer_penalty", 0.45))
    sources = sorted(key for key, node in nodes.items() if node["asrc"])
    sinks = {key for key, node in nodes.items() if node["asink"]}
    reverse_distance = _reverse_distances(adjacency, sinks, max_depth)
    candidates = {}

    for source in sources:
        if source not in reverse_distance:
            continue
        queue = deque([(source, (source,))])
        while queue and len(candidates) < candidate_limit:
            current, chain = queue.popleft()
            edges = len(chain) - 1
            if current in sinks:
                source_node = nodes[source]
                sink_node = nodes[current]
                source_weight = max(float(config["sources"][category]["weight"])
                                    for category in source_node["asrc"])
                sink_weight = max(float(
                    config["sinks"].get(category, {"weight": 2.5})["weight"])
                    for category in sink_node["asink"])
                sanitizers = sorted({value for key in chain
                                     for value in nodes[key]["sanitizers"]})
                score = source_weight + sink_weight \
                    - edges * length_penalty \
                    - len(sanitizers) * sanitizer_penalty
                candidates[tuple(chain)] = {
                    "path_id": _path_id(source_node["binary_md5"], chain),
                    "binary_md5": source_node["binary_md5"],
                    "score": round(score, 3), "edge_count": edges,
                    "source": _display(source_node),
                    "sink": _display(sink_node),
                    "sanitizers": sanitizers,
                    "chain": [_display(nodes[key]) for key in chain],
                    "verified_reachable": False, "trace_ids": [],
                }
            if edges >= max_depth:
                continue
            for target in adjacency.get(current, []):
                if target in chain or target not in reverse_distance:
                    continue
                if edges + 1 + reverse_distance[target] > max_depth:
                    continue
                queue.append((target, chain + (target,)))

    ordered = sorted(
        candidates.values(),
        key=lambda value: (-value["score"], value["edge_count"],
                           value["binary_md5"], value["path_id"]))
    selected = ordered[:path_limit]
    by_key = defaultdict(list)
    for path in selected:
        for node in path["chain"]:
            key = f"{path['binary_md5']}:{str(node['addr']).lower()}"
            by_key[key].append(path["path_id"])
    return {
        "summary": {
            "sources": len(sources), "sinks": len(sinks),
            "path_candidates": len(candidates),
            "paths_returned": len(selected), "max_depth": max_depth,
            "source_counts": analysis["source_counts"],
            "sink_counts": analysis["sink_counts"],
        },
        "paths": selected, "path_ids_by_key": dict(by_key),
    }
