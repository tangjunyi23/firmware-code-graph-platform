"""Classify attack sources and sinks using names, calls, strings and code."""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = FWGRAPH_ROOT / "config" / "attack_surface.yaml"


def load_config(path=None):
    path = Path(path) if path else CONFIG_PATH
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not config.get("sources") \
            or not config.get("sinks"):
        raise ValueError(f"invalid attack-surface config: {path}")
    return config


def function_key(md5, addr):
    return f"{md5}:{str(addr).lower()}"


def _norm(value):
    value = str(value or "").strip().lower()
    if value.startswith("j_"):
        value = value[2:]
    # Tool-generated address names are identities, not duplicate suffixes.
    if re.match(r"^(?:sub|fun)_[0-9a-f]+$", value):
        return value
    return re.sub(r"_[0-9]+$", "", value)


def _terms(func):
    values = (func.get("name"), func.get("ai_name"),
              func.get("rule_name"), func.get("libc_equiv"))
    return {_norm(value) for value in values if value}


def _read_source(pseudo_root, md5, addr):
    path = pseudo_root / md5 / "functions" / f"{addr}.c"
    if not path.is_file():
        path = pseudo_root / md5 / "functions" / f"{str(addr).lower()}.c"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _anonymous_heuristics(code):
    """Return only high-confidence structural matches for unnamed helpers."""
    compact = re.sub(r"\s+", " ", code)
    hits = []
    pointer_copy = re.search(
        r"\*\s*\w+\+\+\s*=\s*\*\s*\w+\+\+", compact)
    nul_loop = re.search(
        r"(?:while|for)\s*\([^)]*(?:!=\s*0|\*\s*\w+)[^)]*\)",
        compact)
    if pointer_copy and nul_loop:
        hits.append(("memunsafe_like", "byte_copy_until_nul", 0.90))
    indexed_copy = re.search(
        r"\w+\s*\[\s*\w+\s*\]\s*=\s*\w+\s*\[\s*\w+\s*\]",
        compact)
    indexed_loop = re.search(
        r"(?:while|for)\s*\([^)]*\w+\s*\[\s*\w+\s*\][^)]*\)",
        compact)
    if indexed_copy and indexed_loop:
        hits.append(("memunsafe_like", "indexed_copy_until_nul", 0.88))
    pointer_loops = re.findall(
        r"(?:while|for)\s*\([^)]*\*\s*\w+[^)]*\)", compact)
    if len(pointer_loops) >= 2 and re.search(r"\*\s*\w+\+\+\s*=", compact):
        hits.append(("memunsafe_like", "scan_then_append", 0.86))
    return hits


def _category_matches(rule, func, call_terms, strings, code, semantic_terms):
    evidence = []
    calls = {_norm(value) for value in rule.get("calls", [])}
    for match in sorted(calls & call_terms):
        evidence.append({"kind": "call", "value": match})
    names = {_norm(value) for value in rule.get("names", [])}
    for match in sorted(names & semantic_terms):
        evidence.append({"kind": "name", "value": match})
    configured_equiv = {_norm(value) for value in rule.get("libc_equiv", [])}
    equiv = _norm(func.get("libc_equiv"))
    if equiv and equiv in configured_equiv:
        evidence.append({"kind": "libc_equiv", "value": equiv})
    for match in sorted(set(rule.get("tags", [])) & set(func.get("tags") or [])):
        evidence.append({"kind": "tag", "value": match})
    for token in rule.get("strings", []):
        if any(str(token).lower() in value for value in strings):
            evidence.append({"kind": "string", "value": str(token)})
    for pattern in rule.get("code_patterns", []):
        if re.search(pattern, code, re.IGNORECASE):
            evidence.append({"kind": "code_pattern", "value": pattern})
    return evidence


def analyze(symbols, pseudo_root, config=None):
    config = config or load_config()
    pseudo_root = Path(pseudo_root)
    nodes = {}
    functions = {}
    names = defaultdict(set)
    raw_calls = {}
    sources = Counter()
    sinks = Counter()

    for md5, entry in symbols.get("binaries", {}).items():
        for func in entry.get("functions", []):
            if not func.get("decompile_ok"):
                continue
            key = function_key(md5, func.get("addr"))
            nodes[key] = {
                "key": key, "binary_md5": md5,
                "addr": func.get("addr"), "name": func.get("name"),
                "ai_name": func.get("ai_name"),
                "libc_equiv": func.get("libc_equiv"),
                "asrc": [], "asink": [], "evidence": {},
                "sanitizers": [],
            }
            functions[key] = func
            for term in _terms(func):
                names[(md5, term)].add(key)
            raw_calls[key] = list(func.get("calls") or [])

    adjacency = {key: set() for key in nodes}
    for key, calls in raw_calls.items():
        md5 = nodes[key]["binary_md5"]
        for call in calls:
            adjacency[key].update(names.get((md5, _norm(call)), set()))

    sanitizer_terms = tuple(
        _norm(value) for value in config.get("scoring", {}).get("sanitizers", []))
    for key, node in nodes.items():
        func = functions[key]
        code = _read_source(pseudo_root, node["binary_md5"], node["addr"])
        strings = [str(value).lower() for value in func.get("strings", [])]
        call_terms = {_norm(value) for value in raw_calls[key]}
        for target in adjacency[key]:
            target_node = nodes[target]
            call_terms.update(_norm(value) for value in
                              (target_node.get("name"), target_node.get("ai_name"),
                               target_node.get("libc_equiv")) if value)
        semantic_terms = _terms(func)
        for category, rule in config["sources"].items():
            evidence = _category_matches(
                rule, func, call_terms, strings, code, semantic_terms)
            if evidence:
                node["asrc"].append(category)
                node["evidence"][f"source:{category}"] = evidence
                sources[category] += 1
        for category, rule in config["sinks"].items():
            evidence = _category_matches(
                rule, func, call_terms, strings, code, semantic_terms)
            if evidence:
                node["asink"].append(category)
                node["evidence"][f"sink:{category}"] = evidence
                sinks[category] += 1
        for category, rule_id, confidence in _anonymous_heuristics(code):
            if category not in node["asink"]:
                node["asink"].append(category)
                sinks[category] += 1
            node["evidence"].setdefault(f"sink:{category}", []).append({
                "kind": "anonymous_heuristic", "value": rule_id,
                "confidence": confidence})
        node["asrc"].sort()
        node["asink"].sort()
        all_terms = call_terms | semantic_terms
        node["sanitizers"] = sorted({
            term for term in all_terms
            if any(token in term for token in sanitizer_terms)})

    return {
        "config_version": config.get("version"), "nodes": nodes,
        "adjacency": {key: sorted(value) for key, value in adjacency.items()},
        "source_counts": dict(sorted(sources.items())),
        "sink_counts": dict(sorted(sinks.items())),
    }


def apply_annotations(symbols, analysis, path_ids_by_key):
    nodes = analysis["nodes"]
    for md5, entry in symbols.get("binaries", {}).items():
        for func in entry.get("functions", []):
            key = function_key(md5, func.get("addr"))
            node = nodes.get(key)
            func["asrc"] = list(node["asrc"]) if node else []
            func["asink"] = list(node["asink"]) if node else []
            func["attack_evidence"] = dict(node["evidence"]) if node else {}
            path_ids = sorted(path_ids_by_key.get(key, []))
            func["on_attack_path"] = bool(path_ids)
            func["path_ids"] = path_ids
            func["observed_in_trace"] = bool(
                node and node.get("observed_in_trace"))
            func["verified_reachable"] = bool(
                node and node.get("verified_reachable"))
            func["trace_ids"] = list(node.get("trace_ids") or []) if node else []
    return symbols


def write_symbols(path, symbols):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(symbols, indent=1), encoding="utf-8")
    temporary.replace(path)
