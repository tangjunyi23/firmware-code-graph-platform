"""Three-layer funnel: pick which functions of one binary go to the AI.

Input:  the function list of one binary from symbols.json (M2 output,
        annotated with tags / rule_name / rule_confidence).
Output: candidate list [{addr, current_name, reasons, priority, ...}]
        plus per-layer skip/keep statistics.

Layers:
  L1 skip      already has a real (non-placeholder) name; thunk (single call,
               tiny body); trivial (decompiled, <10 lines); rule-named with
               rule_confidence >= high_conf.
  L2 must-send has any attack-surface tag and is still a sub_/FUN_ name.
  L3 hard      (evaluated for everything that passed L1): decompile failed;
               noisy pseudo-C (CONCAT/__PAIR__/cast density over threshold);
               called by >= MIN_CALLERS functions but still sub_; has string
               refs but still sub_; lines > LARGE_LINES with rule_confidence
               below high_conf.
               The many-callers rule has two tiers: >= HUB_CALLERS callers
               marks a small hub (usually a library helper) and sorts just
               below L2 instead of with plain L3. Note symbols.json only
               carries outgoing calls, so caller counts come from the
               reverse index (Counter over all callees) built below.

Candidates are sorted by (priority desc, caller count desc) and truncated to
max_funcs. priority: 2 = L2, 1.5 = L3 hub (>= HUB_CALLERS callers),
1 = L3-only.
"""

import re
from collections import Counter

PLACEHOLDER_RE = re.compile(r"^(sub_[0-9a-fA-F]+|FUN_[0-9a-fA-F]+)$")
TRIVIAL_NAME_RE = re.compile(r"^(j_|nullsub_)")

TAGS_OF_INTEREST = ("calls_dangerous", "network_facing", "auth_related", "entrypoint")

THUNK_MAX_SIZE = 32          # bytes; with exactly 1 call => thunk
TRIVIAL_MAX_LINES = 10       # decompiled lines below this => trivial
MIN_CALLERS = 4              # L3: called by at least this many functions
HUB_CALLERS = 8              # L3 hub tier: library-helper-like, sorts near L2
LARGE_LINES = 200            # L3: more lines than this (and low rule conf)
DEFAULT_HIGH_CONF = 0.85     # rule_confidence treated as "already named"
DEFAULT_MAX_FUNCS = 150
DEFAULT_NOISE_RATIO = 0.2

PRIORITY_L2 = 2.0            # attack-surface tag on an anonymous function
PRIORITY_HUB = 1.5           # >= HUB_CALLERS callers: near-L2 sort weight
PRIORITY_L3 = 1.0            # plain L3 signal

# hex-rays noise markers: register-pair concatenation and forced casts
NOISE_RE = re.compile(r"CONCAT\d+|__PAIR__|__int\d+|__QWORD__|__DWORD__|__WORD__")


def _is_placeholder(name):
    return bool(PLACEHOLDER_RE.match(name or ""))


def _noise_ratio(text):
    lines = text.splitlines()
    if not lines:
        return 0.0
    hits = sum(len(NOISE_RE.findall(line)) for line in lines)
    return hits / len(lines)


def run_funnel(functions, *, max_funcs=DEFAULT_MAX_FUNCS,
               noise_ratio=DEFAULT_NOISE_RATIO, high_conf=DEFAULT_HIGH_CONF,
               code_reader=None):
    """Classify one binary's functions.

    code_reader: optional callable(addr) -> pseudo-C text (for the L3 noise
    check); when None the noise check is skipped.

    Returns {"candidates": [...], "stats": {...}}.
    """
    caller_counts = Counter()
    for func in functions:
        caller_counts.update(func.get("calls", []))

    stats = {"total": len(functions), "l1_skipped": Counter(), "no_signal": 0,
             "l2_flagged": 0, "l3_flagged": 0, "selected": 0, "truncated": 0}
    candidates = []

    for func in functions:
        name = func.get("name", "")
        addr = func.get("addr", "")
        calls = func.get("calls", [])
        size = func.get("size", 0)
        lines = func.get("lines", 0)
        decompile_ok = bool(func.get("decompile_ok"))
        rule_conf = float(func.get("rule_confidence") or 0.0)
        placeholder = _is_placeholder(name)

        # ---- L1: cheap skips, first hit wins
        if TRIVIAL_NAME_RE.match(name) or (len(calls) == 1 and size <= THUNK_MAX_SIZE):
            stats["l1_skipped"]["thunk"] += 1
            continue
        if not placeholder:
            stats["l1_skipped"]["has_real_name"] += 1
            continue
        if decompile_ok and lines < TRIVIAL_MAX_LINES:
            stats["l1_skipped"]["trivial"] += 1
            continue
        if func.get("rule_name") and rule_conf >= high_conf:
            stats["l1_skipped"]["rule_named"] += 1
            continue

        # ---- L2: attack-surface tags on still-anonymous functions
        l2_reasons = ["tag:" + t for t in func.get("tags", [])
                      if t in TAGS_OF_INTEREST]

        # ---- L3: hard-to-recover signals (any function that passed L1)
        l3_reasons = []
        if not decompile_ok:
            l3_reasons.append("decompile_failed")
        elif code_reader is not None:
            text = code_reader(addr)
            if text and _noise_ratio(text) > noise_ratio:
                l3_reasons.append("noisy_pseudocode")
        ncallers = caller_counts.get(name, 0)
        hub = ncallers >= HUB_CALLERS
        if hub:
            l3_reasons.append("hub_callers")
        elif ncallers >= MIN_CALLERS:
            l3_reasons.append("many_callers")
        if func.get("strings"):
            l3_reasons.append("has_strings")
        if lines > LARGE_LINES and rule_conf < high_conf:
            l3_reasons.append("large_function")

        reasons = l2_reasons + l3_reasons
        if not reasons:
            stats["no_signal"] += 1
            continue
        if l2_reasons:
            stats["l2_flagged"] += 1
        if l3_reasons:
            stats["l3_flagged"] += 1
        priority = (PRIORITY_L2 if l2_reasons
                    else PRIORITY_HUB if hub else PRIORITY_L3)
        candidates.append({
            "addr": addr,
            "current_name": name,
            "reasons": reasons,
            "priority": priority,
            "caller_count": ncallers,
        })

    candidates.sort(key=lambda c: (-c["priority"], -c["caller_count"], c["addr"]))
    stats["eligible"] = len(candidates)
    if len(candidates) > max_funcs:
        stats["truncated"] = len(candidates) - max_funcs
        candidates = candidates[:max_funcs]
    stats["selected"] = len(candidates)
    stats["l1_skipped"] = dict(sorted(stats["l1_skipped"].items()))
    return {"candidates": candidates, "stats": stats}
