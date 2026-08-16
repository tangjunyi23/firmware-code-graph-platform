"""Pseudo-C AST generation via tree-sitter (C grammar).

The IDA pseudo-C exports are not strict C: they carry IDA attribute
macros (`__noreturn`, `__fastcall`, ...), `// attributes:` marker lines
and inline `__asm { ... }` blocks, all of which parse as ERROR nodes.
parse_c() therefore preprocesses the source first (strip the macros /
marker lines / asm blocks), then records parse quality on the tree:
`error_nodes` (count of tree-sitter ERROR nodes) and `has_error`.

Output is a compact JSON tree: node type + named children, source text for
leaves <= 80 chars, depth/size capped so a pathological decompile cannot
explode the artifact.
"""

import re

from tree_sitter import Language, Parser

try:
    import tree_sitter_c
    _LANG = Language(tree_sitter_c.language())
    _PARSER = Parser(_LANG)
except Exception:  # pragma: no cover - env without tree-sitter
    _PARSER = None

MAX_NODES = 4000
MAX_DEPTH = 40

# IDA attribute macros that are not valid C; stripped before parsing.
# Extend this table as new pseudo-C attributes show up. Words are matched
# with boundaries, so identifiers merely containing them (e.g.
# proto_x__descriptor) are left untouched.
IDA_ATTRS = (
    "__noreturn", "__fastcall", "__cdecl", "__stdcall", "__thiscall",
    "__usercall", "__userpurge", "__thumb", "__pascal", "__syscall",
    "__sparse", "__hidden", "__forceinline",
)
_ATTR_RX = re.compile(r"\b(?:" + "|".join(IDA_ATTRS) + r")\b")
_ATTRS_LINE_RX = re.compile(r"^[ \t]*// attributes:.*(?:\n|$)", re.M)
_ASM_KW_RX = re.compile(r"\b__asm\b")


def _strip_asm_blocks(text):
    """Remove `__asm { ... }` blocks (brace-balanced); inline asm is not C.

    Bare `__asm` occurrences not followed by `{` are left in place so the
    ERROR metric still sees them.
    """
    out, i = [], 0
    for m in _ASM_KW_RX.finditer(text):
        j = m.end()
        while j < len(text) and text[j] in " \t":
            j += 1
        if j >= len(text) or text[j] != "{":
            continue
        depth, k = 0, j
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    k += 1
                    break
            k += 1
        out.append(text[i:m.start()])
        out.append(";")
        i = k
    out.append(text[i:])
    return "".join(out)


def preprocess(source):
    """Strip IDA-isms that are not valid C before feeding tree-sitter."""
    text = _ATTRS_LINE_RX.sub("", source)
    text = _strip_asm_blocks(text)
    return _ATTR_RX.sub(" ", text)


def parse_c(source, func_name=None):
    """-> AST dict (or None when tree-sitter unavailable)."""
    if _PARSER is None:
        return None
    body = preprocess(source) if isinstance(source, str) else source
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    tree = _PARSER.parse(body)
    state = {"count": 0, "error_nodes": 0}

    def walk(node, depth):
        state["count"] += 1
        if node.type == "ERROR":
            state["error_nodes"] += 1
        if state["count"] > MAX_NODES or depth > MAX_DEPTH:
            return None
        item = {"type": node.type}
        if node.named_child_count == 0:
            text = node.text.decode("utf-8", "replace")
            item["text"] = text[:80]
        kids = []
        for child in node.children:
            if not child.is_named:
                continue
            k = walk(child, depth + 1)
            if k is not None:
                kids.append(k)
        if kids:
            item["children"] = kids
        return item

    root = walk(tree.root_node, 0)
    return {"language": "c", "function": func_name,
            "truncated": state["count"] > MAX_NODES,
            "error_nodes": state["error_nodes"],
            "has_error": bool(tree.root_node.has_error), "root": root}
