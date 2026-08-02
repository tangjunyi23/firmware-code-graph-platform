"""M7 address -> function mapping.

Builds a half-open interval table [addr, addr+size) from one binary's
symbols.json function list and maps executed PCs onto it. Functions with a
missing/zero size get size 1 (their entry PC still resolves). PCs that fall
outside every interval are counted as unknown (PLT stubs, trampolines, or
code IDA did not turn into a function).
"""

import bisect


class FunctionIndex:
    """Interval index over one binary's symbols.json functions."""

    def __init__(self, functions):
        self._starts = []
        self._funcs = []
        for fn in sorted(functions, key=lambda f: int(f["addr"], 16)):
            start = int(fn["addr"], 16)
            size = fn.get("size") or 0
            self._starts.append(start)
            self._funcs.append({"addr": fn["addr"],
                                "_start": start,
                                "_end": start + max(int(size), 1),
                                "name": fn.get("name"),
                                "ai_name": fn.get("ai_name"),
                                "libc_equiv": fn.get("libc_equiv")})

    def lookup(self, pc: int):
        """Return the function containing pc, or None."""
        i = bisect.bisect_right(self._starts, pc) - 1
        if i < 0:
            return None
        fn = self._funcs[i]
        return fn if pc < fn["_end"] else None


def map_addresses(addrs, functions):
    """Map ordered executed PCs to an ordered unique function sequence.

    Returns (sequence, unknown_count). Each sequence entry carries the
    symbols.json identity fields plus first_seen_idx — the position of the
    first PC of this function in the input address list, which defines the
    execution order of the sequence.
    """
    index = FunctionIndex(functions)
    seen = set()
    sequence = []
    unknown = 0
    for idx, pc in enumerate(addrs):
        fn = index.lookup(pc)
        if fn is None:
            unknown += 1
            continue
        if fn["_start"] in seen:
            continue
        seen.add(fn["_start"])
        sequence.append({"addr": fn["addr"],
                         "name": fn.get("name"),
                         "ai_name": fn.get("ai_name"),
                         "libc_equiv": fn.get("libc_equiv"),
                         "first_seen_idx": idx})
    return sequence, unknown
