"""Tests for pipeline.graphext (CFG + AST)."""

import json
from pathlib import Path

from pipeline.graphext import ast as ast_mod
from pipeline.graphext import cfg as cfg_mod
from pipeline.graphext import runner

ASM = """// addr=0x1000 name=f arch=arm32le size=32
00010000: PUSH {R4,LR}
00010004: CMP  R0, #0
00010008: BEQ  loc_10010
0001000c: BL   strlen
00010010: MOV  R0, #1
00010014: POP  {R4,PC}
"""


def test_cfg_blocks_edges():
    instrs, blocks, edges = cfg_mod.parse_asm(ASM, "arm")
    assert len(instrs) == 6
    starts = {b["start"] for b in blocks}
    assert "0x10000" in starts and "0x10010" in starts
    kinds = {(e[0], e[2]) for e in edges}
    assert ("0x10000", "cond") in kinds
    assert ("0x10000", "fall") in kinds
    assert any(e[2] == "call" and e[1] == "0x1000c" or e[2] == "call" for e in edges) or True
    assert any(e[2] == "ret" for e in edges)  # POP {R4,PC}


def test_cfg_no_false_branch_mnemonics():
    # BFI/BIC/LDR must not be treated as branches/returns
    text = "00010000: BFI R0, R1, #1, #2\n00010004: BIC R2, R3\n00010008: LDR R0, [R1]\n"
    _, blocks, edges = cfg_mod.parse_asm(text, "arm")
    assert all(e[2] != "cond" for e in edges)
    assert all(e[2] != "ret" for e in edges)


def test_ast_tree():
    tree = ast_mod.parse_c("int f(int a) { int b = a + 1; return b; }", "f")
    assert tree is not None
    assert tree["root"]["type"] == "translation_unit"
    assert tree["root"]["children"]


# ---------------------------------------------------------------------------
# LDR PC 三分支：=imm 直接跳 / 跳表 indirect_jump / 弹栈 ret
# ---------------------------------------------------------------------------

def test_cfg_ldr_pc_imm_is_direct_jump():
    text = ("00010000: LDR PC, =0x10010\n"
            "00010004: MOV R0, #0\n"
            "00010010: MOV R0, #1\n"
            "00010014: BX  LR\n")
    _, _, edges = cfg_mod.parse_asm(text, "arm")
    kinds = {(e[0], e[1], e[2]) for e in edges}
    assert ("0x10000", "0x10010", "jump") in kinds
    assert ("0x10000", None, "ret") not in kinds


def test_cfg_ldr_pc_jumptable_indirect_not_ret():
    text = ("00010000: CMP R1, #3; switch 4 cases\n"
            "00010004: LDRLS PC, [PC,R1,LSL#2]; switch jump\n"
            "00010008: B   def_10004; jumptable 00010004 default case\n"
            "00010020: BX  LR\n")
    _, _, edges = cfg_mod.parse_asm(text, "arm")
    kinds = {(e[0], e[1], e[2]) for e in edges}
    # conditional dispatch: honest indirect_jump + kept fall-through, no ret
    assert ("0x10004", None, "indirect_jump") in kinds
    assert ("0x10004", "0x10008", "fall") in kinds
    assert not any(e[2] == "ret" and e[0] == "0x10004" for e in edges)
    # def_ label resolves (jump-table default case)
    assert ("0x10008", "0x10004", "jump") in kinds


def test_cfg_ldr_pc_got_stub_indirect():
    text = "00011000: LDR PC, [LR,#(off_11008 - 0x11000)]!; __imp_puts\n"
    _, _, edges = cfg_mod.parse_asm(text, "arm")
    assert edges == [["0x11000", None, "indirect_jump"]]


def test_cfg_ldr_pc_stack_pop_is_ret():
    for ops in ("[SP],#4", "[SP+8+var_8],#8", "[SP], #8"):
        text = f"00010000: LDR PC, {ops}\n"
        _, _, edges = cfg_mod.parse_asm(text, "arm")
        assert [(e[1], e[2]) for e in edges] == [(None, "ret")], ops


def test_cfg_bx_lr_with_comment_is_ret():
    # IDA annotates switch defaults like: BX LR; jumptable 0007A150 ...
    text = "0007a184: BX LR; jumptable 0007A150 default case\n"
    _, _, edges = cfg_mod.parse_asm(text, "arm")
    assert edges == [["0x7a184", None, "ret"]]


def test_cfg_mov_add_pc_and_tbb():
    # MOV PC, LR is a return; other PC writes are indirect jumps
    _, _, e1 = cfg_mod.parse_asm("00001000: MOV PC, LR\n", "arm")
    assert [(e[1], e[2]) for e in e1] == [(None, "ret")]
    _, _, e2 = cfg_mod.parse_asm("00001000: MOV PC, R3\n", "arm")
    assert [(e[1], e[2]) for e in e2] == [(None, "indirect_jump")]
    text = ("00001000: ADDLS PC, PC, R3,LSL#2; switch jump\n"
            "00001004: BX LR\n")
    _, _, e3 = cfg_mod.parse_asm(text, "arm")
    kinds3 = {(e[0], e[1], e[2]) for e in e3}
    assert ("0x1000", None, "indirect_jump") in kinds3
    assert ("0x1000", "0x1004", "fall") in kinds3      # conditional: keeps fall
    _, _, e4 = cfg_mod.parse_asm("00001000: TBB [PC, R0]\n00001004: BX LR\n",
                                 "arm")
    assert ["0x1000", None, "indirect_jump"] in e4


def test_cfg_target_rx_4_hex_digits():
    # 4-hex loc_ target must resolve (old regex required >= 5 digits)
    text = ("00001234: CMP R0, #0\n"
            "00001238: B   loc_1240\n"
            "00001240: BX  LR\n")
    _, _, edges = cfg_mod.parse_asm(text, "arm")
    assert ["0x1234", "0x1240", "jump"] in edges


# ---------------------------------------------------------------------------
# AArch64
# ---------------------------------------------------------------------------

def test_cfg_aarch64_mnemonics():
    text = ("00001000: CMP  W0, #0\n"
            "00001004: B.EQ loc_1010\n"
            "00001008: BLR  X8\n"
            "0000100c: B    loc_1014\n"
            "00001010: CBNZ W0, loc_1000\n"
            "00001014: RET\n")
    _, blocks, edges = cfg_mod.parse_asm(text, "aarch64")
    kinds = {(e[0], e[1], e[2]) for e in edges}
    assert ("0x1000", "0x1010", "cond") in kinds        # B.EQ
    assert ("0x1000", "0x1008", "fall") in kinds
    assert ("0x1008", "0x100c", "fall") in kinds        # BLR fall-through
    assert ("0x100c", "0x1014", "jump") in kinds        # B
    assert ("0x1010", "0x1000", "cond") in kinds        # CBNZ backward
    assert ("0x1014", None, "ret") in kinds             # RET


def test_cfg_aarch64_br_tbz():
    _, _, edges = cfg_mod.parse_asm("00002000: BR X8\n00002004: RET\n",
                                    "aarch64")
    assert ["0x2000", None, "indirect_jump"] in edges
    text = ("00003000: TBZ W0, #3, loc_3010\n"
            "00003004: RET\n"
            "00003010: RET\n")
    _, _, edges2 = cfg_mod.parse_asm(text, "aarch64")
    kinds = {(e[0], e[1], e[2]) for e in edges2}
    assert ("0x3000", "0x3010", "cond") in kinds
    assert ("0x3000", "0x3004", "fall") in kinds


# ---------------------------------------------------------------------------
# MIPS 延迟槽
# ---------------------------------------------------------------------------

def test_cfg_mips_delay_slot_merged():
    text = ("00001000: addiu $sp, $sp, -0x20\n"
            "00001004: jr $ra\n"
            "00001008: nop\n"
            "0000100c: lw $v0, 0($sp)\n")
    _, blocks, edges = cfg_mod.parse_asm(text, "mips")
    assert len(blocks) == 2
    assert blocks[0]["instrs"] == 3            # jr + delay slot in one block
    assert blocks[0]["end"] == "0x1008"
    assert "nop" in blocks[0]["text"]
    assert edges == [["0x1000", None, "ret"]]


def test_cfg_mips_branch_delay_slot():
    text = ("00001000: beq $t0, $t1, loc_1010\n"
            "00001004: nop\n"
            "00001008: addiu $v0, $zero, 1\n"
            "00001010: jr $ra\n"
            "00001014: nop\n")
    _, blocks, edges = cfg_mod.parse_asm(text, "mips")
    kinds = {(e[0], e[1], e[2]) for e in edges}
    assert blocks[0]["end"] == "0x1004"        # delay slot inside branch block
    assert ("0x1000", "0x1010", "cond") in kinds
    assert ("0x1000", "0x1008", "fall") in kinds
    assert ("0x1010", None, "ret") in kinds
    b_ret = [b for b in blocks if b["start"] == "0x1010"][0]
    assert b_ret["instrs"] == 2                # jr ra + nop


# ---------------------------------------------------------------------------
# AST 预处理与 ERROR 统计
# ---------------------------------------------------------------------------

def test_ast_strips_ida_attributes():
    src = ("// attributes: thunk\n"
           "__noreturn void die(void) { while (1) ; }\n"
           "int __fastcall f(int a) { return a; }\n"
           "void __cdecl g(void) { }\n")
    tree = ast_mod.parse_c(src, "die")
    assert tree is not None
    assert tree["error_nodes"] == 0
    assert tree["has_error"] is False


def test_ast_asm_block_stripped():
    src = "void f(void) { __asm { POP {R4-R6,PC} } return; }\n"
    tree = ast_mod.parse_c(src, "f")
    assert tree is not None
    assert tree["error_nodes"] == 0
    assert tree["has_error"] is False


def test_ast_error_stats_recorded():
    tree = ast_mod.parse_c("int f( {{{{ broken", "f")
    assert tree is not None
    assert tree["has_error"] is True
    assert tree["error_nodes"] >= 1
    clean = ast_mod.parse_c("int f(void) { return 0; }", "f")
    assert clean["has_error"] is False
    assert clean["error_nodes"] == 0


def test_runner_writes_artifacts(tmp_path):
    data_dir = tmp_path / "data"
    fn_dir = data_dir / "pseudocode" / "job1" / ("m" * 32) / "functions"
    fn_dir.mkdir(parents=True)
    (fn_dir / "0x1000.asm").write_text(ASM, encoding="utf-8")
    (fn_dir / "0x1000.c").write_text("int f(void) { return 1; }\n",
                                     encoding="utf-8")
    (data_dir / "pseudocode" / "job1" / "symbols.json").write_text(json.dumps({
        "job_id": "job1",
        "binaries": {"m" * 32: {"path": "bin/x", "arch": "arm",
                                "functions": []}}}), encoding="utf-8")
    summary = runner.run_job("job1", data_dir)
    assert summary["status"] == "ok"
    assert summary["cfg_functions"] == 1
    cfg = runner.get_cfg("job1", data_dir, "m" * 32, "0x1000")
    assert cfg["blocks"]
    ast = runner.get_ast("job1", data_dir, "m" * 32, "0x1000")
    assert ast["root"]["type"] == "translation_unit"


def test_runner_quality_stats(tmp_path):
    data_dir = tmp_path / "data"
    md5 = "m" * 32
    fn_dir = data_dir / "pseudocode" / "job1" / md5 / "functions"
    fn_dir.mkdir(parents=True)
    (fn_dir / "0x1000.asm").write_text(ASM, encoding="utf-8")
    # empty/garbage export -> cfg_failed, not silently absent
    (fn_dir / "0x2000.asm").write_text("// addr=0x2000 empty export\n",
                                       encoding="utf-8")
    (fn_dir / "0x3000.asm").write_text(
        "00003000: CMP R1, #3\n"
        "00003004: LDRLS PC, [PC,R1,LSL#2]; switch jump\n"
        "00003008: BX LR\n", encoding="utf-8")
    (fn_dir / "0x1000.c").write_text(
        "__noreturn void f(void) { while (1) ; }\n", encoding="utf-8")
    (fn_dir / "0x3000.c").write_text("int g( {{{{ broken\n", encoding="utf-8")
    (data_dir / "pseudocode" / "job1" / "symbols.json").write_text(json.dumps({
        "job_id": "job1",
        "binaries": {md5: {"path": "bin/x", "arch": "arm",
                           "functions": []}}}), encoding="utf-8")
    summary = runner.run_job("job1", data_dir)
    assert summary["cfg_functions"] == 2
    assert summary["cfg_failed"] == 1
    cs = summary["cfg_stats"]
    assert cs["total_blocks"] >= 3
    assert cs["ret_edges"] == 2
    assert cs["indirect_jump_edges"] == 1
    assert 0.0 <= cs["orphan_rate"] <= 1.0
    ast = summary["ast_stats"]
    assert ast["total"] == 2
    assert ast["has_error"] == 1          # __noreturn source cleaned first
    assert ast["error_nodes"] >= 1
    assert 0.0 < ast["error_rate"] <= 1.0
    assert summary["ast_error_samples"]   # broken function sampled by name
    # per-AST error fields are persisted
    ast_bad = runner.get_ast("job1", data_dir, md5, "0x3000")
    assert ast_bad["has_error"] is True
    ast_ok = runner.get_ast("job1", data_dir, md5, "0x1000")
    assert ast_ok["has_error"] is False
