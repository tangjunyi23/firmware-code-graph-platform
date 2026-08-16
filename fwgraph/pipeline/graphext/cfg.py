"""Build a control-flow graph from one exported function .asm file.

Input format (IDA headless export):
    // addr=0x131b4 name=cmd_communication arch=arm32le size=324
    000131b4: LDR             R3, =(...)
    000131e0: BGE             loc_131EC

Blocks split on: function entry, branch targets, and the instruction
following any control transfer. On MIPS the delay slot of a transfer is
kept inside the transfer's block (the split happens after the slot).

Edge kinds: fall, cond, jump, call, ret, indirect_jump.

ARM/Thumb terminals beyond the classic branch mnemonics:
    LDR PC, =imm            -> direct jump edge (target parsed from imm)
    LDR PC, [SP..], #imm    -> ret (stack-pop return; also [SP..],#imm
                               with IDA frame vars)
    LDR PC, [Rn, ...] other -> indirect_jump (jump table / GOT stub)
    ADD/SUB/MOV .., PC      -> indirect_jump (MOV PC,LR stays ret)
    TBB/TBH                 -> indirect_jump (Thumb table branch)
    BX rX (not LR)          -> indirect_jump
Conditional terminals (LDRLS PC, .. / POPEQ {..,PC} / BXEQ LR / ...)
emit their edge plus a fall edge to the next block. Jump-table data is
not present in the .asm exports, so switch dispatches stay honest
indirect_jump edges instead of forged case edges.
"""

import re

LINE_RX = re.compile(r"^([0-9a-fA-F]+):\s+(\S+)(?:\s+(.*))?$")
# bare (optionally IDA-labeled) hex addresses down to 4 digits, plus 0x form
TARGET_RX = re.compile(
    r"\b(?:loc_|locret_|sub_|off_|unk_|def_)?([0-9a-fA-F]{4,})\b"
    r"|\b0x([0-9a-fA-F]{4,})\b")

# exact mnemonic sets per arch family (no prefix guessing — BFI is not a
# branch, LDR is not a return)
_ARM_COND = {"beq", "bne", "bgt", "bge", "blt", "ble", "bhi", "bhs",
             "blo", "bls", "bmi", "bpl", "bvs", "bvc", "beqz", "bnez",
             "cbz", "cbnz"}
_ARM_JUMP = {"b", "bx"}
_ARM_CALL = {"bl", "blx"}
_A64_COND = {"cbz", "cbnz", "tbz", "tbnz"} | {
    f"b.{c}" for c in ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl",
                       "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le")}
_A64_JUMP = {"b", "br"}
_A64_CALL = {"bl", "blr"}
_A64_RET = {"ret", "retaa", "retab"}
_MIPS_COND = {"beq", "bne", "beqz", "bnez", "bgtz", "bgez", "bltz", "blez",
              "bc1t", "bc1f"}
_MIPS_JUMP = {"j", "jr", "b"}
_MIPS_CALL = {"jal", "jalr", "bal"}
_X86_COND = {"je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg",
             "jge", "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp",
             "jcxz", "jecxz"}
_X86_JUMP = {"jmp", "jmpq"}
_X86_CALL = {"call", "callq"}
_X86_RET = {"ret", "retq", "retn", "retf"}

# ARM condition-code suffixes; only stripped for PC-writing stems below so
# that plain branch mnemonics (BEQ & co.) stay intact for the cond table.
_ARM_COND_SUFFIX = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs",
                    "vc", "hi", "ls", "ge", "lt", "gt", "le", "al")
_ARM_PC_STEMS = {"ldr", "ldm", "ldmfd", "ldmia", "ldmib", "ldmed", "ldmea",
                 "pop", "bx", "add", "sub", "mov", "tbb", "tbh"}

_LR_RX = re.compile(r"^\s*(?:lr|r14)\s*(?:;.*)?$", re.I)
_PC_DEST_RX = re.compile(r"^\s*(?:pc|r15)\s*,", re.I)
_LDR_PC_RX = re.compile(r"^\s*(?:pc|r15)\s*,\s*(.*)$", re.I | re.S)
# stack-pop return: LDR PC, [SP..], #imm  /  LDR PC, [SP..]!
_LDR_SP_POP_RX = re.compile(r"^\[\s*(?:sp|r13)\b[^]]*\]\s*(?:,\s*#|!)", re.I)
# LDR PC, =imm / =0xIMM / =sub_XXXX / =(sub_XXXX - 0x..)
_LDR_IMM_RX = re.compile(
    r"^=\s*\(?\s*(?:0x([0-9a-fA-F]{4,})"
    r"|(?:loc_|locret_|sub_|off_|unk_|def_)?([0-9a-fA-F]{4,}))\b", re.I)
_MIPS_RA_RX = re.compile(r"^\s*(?:\$?ra|\$31)\s*(?:;.*)?$", re.I)


def _table(arch):
    a = (arch or "").lower()
    if a.startswith("aarch") or a.startswith("arm64"):
        return {"cond": _A64_COND, "jump": _A64_JUMP, "call": _A64_CALL}
    if a.startswith("arm") or a.startswith("thumb"):
        return {"cond": _ARM_COND, "jump": _ARM_JUMP, "call": _ARM_CALL}
    if a.startswith("mips"):
        return {"cond": _MIPS_COND, "jump": _MIPS_JUMP, "call": _MIPS_CALL}
    return {"cond": _X86_COND, "jump": _X86_JUMP, "call": _X86_CALL}


def _target(ops):
    """First address-like literal in an operand string, as int or None."""
    m = TARGET_RX.search(ops)
    if not m:
        return None
    return int(m.group(1) or m.group(2), 16)


def _arm_split(mn):
    """ARM/Thumb mnemonic -> (base, is_conditional).

    Handles Thumb .W/.N width suffixes and condition-code suffixes on the
    PC-writing stems only (LDRLS->(ldr,True)); BEQ etc. are deliberately
    left whole so the branch tables still match them.
    """
    low = mn.lower()
    if low.endswith((".w", ".n")):
        low = low[:-2]
    if low in _ARM_PC_STEMS:
        return low, False
    for cc in _ARM_COND_SUFFIX:
        if low.endswith(cc) and low[:-len(cc)] in _ARM_PC_STEMS:
            return low[:-len(cc)], True
    return low, False


def _arm_pc_terminal(mn, ops):
    """Classify ARM/Thumb PC-writing data instructions (not in branch
    tables) -> (kind, imm_target, conditional) or None.

    kind: ret | indirect_jump | jump_imm (direct jump via LDR PC, =imm;
    imm_target is the parsed absolute address).
    """
    base, cond = _arm_split(mn)
    o = ops.lower()
    if base == "pop" or base.startswith("ldm"):
        if re.search(r"\b(?:pc|r15)\b", o):
            return ("ret", None, cond)
        return None
    if base == "bx":
        if _LR_RX.match(o):
            return ("ret", None, cond)
        return ("indirect_jump", None, cond)
    if base in ("tbb", "tbh"):
        return ("indirect_jump", None, cond)
    if base in ("mov", "add", "sub"):
        if _PC_DEST_RX.match(o):
            if base == "mov" and _LR_RX.match(o.split(",", 1)[1]):
                return ("ret", None, cond)
            # e.g. ADDLS PC, PC, R3,LSL#2 — inline switch dispatch
            return ("indirect_jump", None, cond)
        return None
    if base == "ldr":
        m = _LDR_PC_RX.match(o)
        if not m:
            return None
        src = m.group(1).strip()
        if src.startswith("="):
            imm = _LDR_IMM_RX.match(src)
            if imm:
                return ("jump_imm", int(imm.group(1) or imm.group(2), 16),
                        cond)
            return ("indirect_jump", None, cond)
        if _LDR_SP_POP_RX.match(src):
            return ("ret", None, cond)
        # [PC,Rm,LSL#2] jump table, [Rn,#..]! GOT stub, plain register…
        return ("indirect_jump", None, cond)
    return None


def parse_asm(text, arch="arm"):
    """-> (instrs, blocks, edges). instrs: (addr:int, mnemonic, operands)."""
    instrs = []
    for line in text.splitlines():
        m = LINE_RX.match(line.strip())
        if m:
            instrs.append((int(m.group(1), 16), m.group(2), m.group(3) or ""))
    if not instrs:
        return [], [], []

    a = (arch or "").lower()
    is_arm = a.startswith("arm") or a.startswith("thumb")
    is_a64 = a.startswith("aarch") or a.startswith("arm64")
    is_mips = a.startswith("mips")
    tab = _table(a)
    addr_set = {addr for addr, _, _ in instrs}

    def branch_target(ops):
        tgt = _target(ops)
        return tgt if tgt in addr_set else None

    def classify(i):
        """instrs[i] -> (kind, target, conditional) or None when the
        instruction is not a control transfer."""
        _addr, mn, ops = instrs[i]
        low = mn.lower()
        if low in tab["cond"]:
            return ("cond", branch_target(ops), True)
        if low in tab["call"]:
            return ("call", branch_target(ops), False)
        if low in tab["jump"]:
            if is_arm:
                base, cond = _arm_split(mn)
                if base == "bx":
                    if _LR_RX.match(ops):
                        return ("ret", None, cond)
                    return ("indirect_jump", None, cond)
            if is_mips and low == "jr":
                if _MIPS_RA_RX.match(ops):
                    return ("ret", None, False)
                return ("indirect_jump", None, False)
            if is_a64 and low == "br":
                return ("indirect_jump", None, False)
            return ("jump", branch_target(ops), False)
        if is_arm:
            return _arm_pc_terminal(mn, ops)
        if is_a64:
            if low in _A64_RET:
                return ("ret", None, False)
            return None
        if is_mips:
            return None
        if low in _X86_RET:
            return ("ret", None, False)
        return None

    # MIPS delay slots: the instruction right after a transfer executes
    # before the transfer takes effect; it stays in the transfer's block.
    delay_idx = set()
    if is_mips:
        for i in range(len(instrs) - 1):
            if classify(i) is not None:
                delay_idx.add(i + 1)

    leaders = {instrs[0][0]}
    for i in range(len(instrs)):
        if i in delay_idx:
            continue
        t = classify(i)
        if t is None:
            continue
        kind, tgt, _cond = t
        if kind in ("cond", "jump", "call", "jump_imm") \
                and tgt is not None and tgt in addr_set:
            leaders.add(tgt)
        # the transfer terminates the block; on MIPS the delay slot comes
        # first, so the next block starts after it
        nxt = i + 2 if is_mips and (i + 1) in delay_idx else i + 1
        if nxt < len(instrs):
            leaders.add(instrs[nxt][0])

    leader_list = sorted(leaders)
    blocks, edges = [], []
    for bi, start in enumerate(leader_list):
        end_excl = leader_list[bi + 1] if bi + 1 < len(leader_list) else None
        body = [(i, ins) for i, ins in enumerate(instrs)
                if start <= ins[0] and (end_excl is None or ins[0] < end_excl)]
        if not body:
            continue
        blocks.append({
            "id": bi, "start": hex(start), "end": hex(body[-1][1][0]),
            "instrs": len(body),
            "text": "\n".join(
                f"{ad:x}: {mn} {op}".rstrip() for _i, (ad, mn, op) in body),
        })
        # terminal = last non-delay-slot instruction of the block
        ti = len(body) - 1
        if is_mips:
            while ti >= 0 and body[ti][0] in delay_idx:
                ti -= 1
        t = classify(body[ti][0]) if ti >= 0 else None
        nxt = hex(end_excl) if end_excl is not None else None
        sh = hex(start)
        if t is None:
            if nxt:
                edges.append([sh, nxt, "fall"])
            continue
        kind, tgt, cnd = t
        if kind == "call":
            if tgt is not None:
                edges.append([sh, hex(tgt), "call"])
            if nxt:
                edges.append([sh, nxt, "fall"])
        elif kind == "cond":
            if tgt is not None:
                edges.append([sh, hex(tgt), "cond"])
            if nxt:
                edges.append([sh, nxt, "fall"])
        elif kind in ("jump", "jump_imm"):
            if tgt is not None:
                edges.append([sh, hex(tgt), "jump"])
            if cnd and nxt:
                edges.append([sh, nxt, "fall"])
        elif kind == "ret":
            edges.append([sh, None, "ret"])
            if cnd and nxt:
                edges.append([sh, nxt, "fall"])
        elif kind == "indirect_jump":
            edges.append([sh, None, "indirect_jump"])
            if cnd and nxt:
                edges.append([sh, nxt, "fall"])

    seen, dedup = set(), []
    for e in edges:
        k = (e[0], e[1], e[2])
        if k not in seen:
            seen.add(k)
            dedup.append(e)
    return instrs, blocks, dedup
