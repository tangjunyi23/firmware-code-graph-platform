"""Unit tests for M4 graph ingest (pipeline.graph.ingest).

No CBM, no git binary, no network: the CBM index call and the git helper are
monkeypatched; metadata injection runs against a real temporary SQLite db
replicating the CBM nodes schema.
"""

import json
import sqlite3

import pytest

from pipeline.graph import ingest

JOB = "testjob12345"
MD5 = "9e39391af855fd996cdd90437e2eeb7b"


def make_data_dir(tmp_path, functions=None):
    """Fake data dir: pseudocode/<job>/<md5>/functions/<addr>.c + symbols.json."""
    functions = functions if functions is not None else [
        {"addr": "0x1000", "name": "auth_check_password", "decompile_ok": True,
         "tags": ["auth_related"], "ai_confidence": 0.87,
         "ai_name": "auth_check_password", "rule_source": None,
         "libc_equiv": "strcmp", "domain": "auth"},
        {"addr": "0x2000", "name": "sub_2000", "decompile_ok": True,
         "tags": [], "ai_confidence": None},
        {"addr": "0x3000", "name": ".init_proc", "decompile_ok": True,
         "tags": ["entrypoint"], "rule_source": "export_symbol"},
        {"addr": "0x4000", "name": "sub_4000", "decompile_ok": False},
        {"addr": "0x5000", "name": "sub_5000", "decompile_ok": True},  # no .c
    ]
    pseudo = tmp_path / "pseudocode" / JOB
    funcs_dir = pseudo / MD5 / "functions"
    funcs_dir.mkdir(parents=True)
    for func in functions:
        if func["addr"] == "0x5000":
            continue  # symbols row without an exported file
        (funcs_dir / f"{func['addr']}.c").write_text(
            f"// addr={func['addr']} name={func['name']} arch=mips32be size=100\n"
            f"int {func['name'].lstrip('.')}(void) {{ return 0; }}\n",
            encoding="utf-8")
    symbols = {"job_id": JOB, "binaries": {MD5: {
        "path": "firmware.extracted/0/bin/busybox", "arch": "mips",
        "functions": functions}}}
    (pseudo / "symbols.json").write_text(json.dumps(symbols), encoding="utf-8")
    return tmp_path, symbols


# ---------------------------------------------------------------------------
# build_tree
# ---------------------------------------------------------------------------

class TestBuildTree:
    def test_tree_layout_and_names(self, tmp_path):
        data_dir, _ = make_data_dir(tmp_path)
        stats = ingest.build_tree(JOB, data_dir)
        bindir = tmp_path / "cbm" / JOB / f"busybox_{MD5[:8]}"
        assert stats["tree_root"] == str(tmp_path / "cbm" / JOB)
        assert stats["files_copied"] == 3          # 0x4000 not ok, 0x5000 no file
        assert stats["skipped"] == 2
        names = sorted(p.name for p in bindir.iterdir())
        assert names == ["0x1000_auth_check_password.c",
                         "0x2000_sub_2000.c",
                         "0x3000_.init_proc.c"]
        body = (bindir / "0x1000_auth_check_password.c").read_text()
        assert body.startswith("// addr=0x1000 name=auth_check_password")

    def test_rebuild_preserves_git_dir(self, tmp_path):
        data_dir, _ = make_data_dir(tmp_path)
        ingest.build_tree(JOB, data_dir)
        git_dir = tmp_path / "cbm" / JOB / ".git"
        git_dir.mkdir()
        marker = git_dir / "HEAD"
        marker.write_text("ref: refs/heads/master\n")
        ingest.build_tree(JOB, data_dir)
        assert marker.is_file()  # .git survived the rebuild
        assert (tmp_path / "cbm" / JOB / f"busybox_{MD5[:8]}").is_dir()

    def test_filename_sanitization(self, tmp_path):
        funcs = [{"addr": "0x10", "name": "weird/name with$chars",
                  "decompile_ok": True, "tags": []}]
        data_dir, _ = make_data_dir(tmp_path, functions=funcs)
        ingest.build_tree(JOB, data_dir)
        bindir = tmp_path / "cbm" / JOB / f"busybox_{MD5[:8]}"
        assert [p.name for p in bindir.iterdir()] == ["0x10_weird_name_with_chars.c"]

    def test_long_filename_is_bounded_and_deterministic(self):
        name = "_ZN" + ("very_long_namespace_" * 40)
        func = {"addr": "0xd860", "name": name}
        first = ingest._function_filename(func)
        second = ingest._function_filename(func)
        assert first == second
        assert len(first.encode("utf-8")) <= 255
        assert first.startswith("0xd860__ZNvery_long_namespace_")
        assert first.endswith(".c")


# ---------------------------------------------------------------------------
# git_init_commit
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestGitInitCommit:
    def test_init_add_commit_flow(self, tmp_path, monkeypatch):
        calls = []

        def fake_git(root, *args):
            calls.append(args)
            if args[:1] == ("status",):
                return _FakeProc(stdout=" M file.c\n")  # dirty -> commit
            return _FakeProc()

        monkeypatch.setattr(ingest, "_git", fake_git)
        out = ingest.git_init_commit(tmp_path)
        assert out == {"ok": True, "committed": True}
        assert calls[0] == ("init",)
        assert ("add", "-A") in calls
        commit = calls[-1]
        assert "commit" in commit and "user.name=fwgraph" in commit

    def test_clean_tree_skips_commit(self, tmp_path, monkeypatch):
        (tmp_path / ".git").mkdir()
        calls = []

        def fake_git(root, *args):
            calls.append(args)
            return _FakeProc(stdout="")  # clean

        monkeypatch.setattr(ingest, "_git", fake_git)
        out = ingest.git_init_commit(tmp_path)
        assert out == {"ok": True, "committed": False}
        assert all("commit" not in c for c in calls)
        assert all(c[:1] != ("init",) for c in calls)  # already a repo

    def test_failure_reported_not_raised(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ingest, "_git",
                            lambda root, *a: _FakeProc(1, stderr="boom"))
        out = ingest.git_init_commit(tmp_path)
        assert out["ok"] is False and "boom" in out["error"]


# ---------------------------------------------------------------------------
# inject_metadata (real SQLite, CBM nodes schema)
# ---------------------------------------------------------------------------

NODES_SCHEMA = """
CREATE TABLE nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    label TEXT NOT NULL,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    file_path TEXT DEFAULT '',
    start_line INTEGER DEFAULT 0,
    end_line INTEGER DEFAULT 0,
    properties TEXT DEFAULT '{}',
    UNIQUE(project, qualified_name)
)
"""


@pytest.fixture
def cbm_db(tmp_path):
    """Temp SQLite db with the CBM nodes schema + one Function node per
    copied file of make_data_dir()."""
    dbfile = tmp_path / "fwgraph_testjob12345.db"
    db = sqlite3.connect(str(dbfile))
    db.execute(NODES_SCHEMA)
    rows = [
        ("Function", "auth_check_password",
         f"busybox_{MD5[:8]}/0x1000_auth_check_password.c"),
        ("Function", "sub_2000", f"busybox_{MD5[:8]}/0x2000_sub_2000.c"),
        ("Function", ".init_proc", f"busybox_{MD5[:8]}/0x3000_.init_proc.c"),
        ("File", "0x1000_auth_check_password.c",      # not a Function: skipped
         f"busybox_{MD5[:8]}/0x1000_auth_check_password.c"),
    ]
    for i, (label, name, fpath) in enumerate(rows):
        db.execute(
            "INSERT INTO nodes(project,label,name,qualified_name,file_path,"
            "properties) VALUES (?,?,?,?,?,'{}')",
            ("fwgraph_" + JOB, label, name, f"q{i}", fpath))
    db.commit()
    db.close()
    return dbfile


class TestInjectMetadata:
    def _props(self, dbfile, name):
        db = sqlite3.connect(str(dbfile))
        row = db.execute("SELECT properties FROM nodes WHERE name=? AND "
                         "label='Function'", (name,)).fetchone()
        db.close()
        return json.loads(row[0])

    def test_injects_all_fields(self, tmp_path, cbm_db):
        _, symbols = make_data_dir(tmp_path)
        out = ingest.inject_metadata(cbm_db, symbols, "fwgraph_" + JOB)
        # 0x4000 not decompile_ok -> 4 wanted; 0x5000 has no node -> 3 matched
        assert out == {"wanted": 4, "matched": 3, "ai_named": 1,
                       "rule_named": 1, "libc_equiv": 1, "domain": 1}
        props = self._props(cbm_db, "auth_check_password")
        assert props["addr"] == "0x1000"
        assert props["arch"] == "mips"
        assert props["tags"] == ["auth_related"]
        assert props["ai_confidence"] == 0.87
        assert props["ai_name"] == "auth_check_password"
        assert props["libc_equiv"] == "strcmp"
        assert props["domain"] == "auth"
        assert "rule_source" not in props  # absent, not null
        props = self._props(cbm_db, ".init_proc")
        assert props["rule_source"] == "export_symbol"
        assert props["tags"] == ["entrypoint"]
        assert "ai_name" not in props
        props = self._props(cbm_db, "sub_2000")
        assert props["addr"] == "0x2000"
        assert "ai_confidence" not in props  # sparse keys stay sparse
        assert "libc_equiv" not in props

    def test_legacy_nulls_cleaned_on_replay(self, tmp_path, cbm_db):
        db = sqlite3.connect(str(cbm_db))
        db.execute("UPDATE nodes SET properties=json_set(properties,"
                   "'$.ai_name', NULL, '$.ai_confidence', NULL)"
                   " WHERE name='sub_2000'")
        db.commit()
        db.close()
        _, symbols = make_data_dir(tmp_path)
        ingest.inject_metadata(cbm_db, symbols, "fwgraph_" + JOB)
        props = self._props(cbm_db, "sub_2000")
        assert "ai_name" not in props and "ai_confidence" not in props

    def test_idempotent_replay(self, tmp_path, cbm_db):
        _, symbols = make_data_dir(tmp_path)
        ingest.inject_metadata(cbm_db, symbols, "fwgraph_" + JOB)
        first = self._props(cbm_db, "auth_check_password")
        out = ingest.inject_metadata(cbm_db, symbols, "fwgraph_" + JOB)
        assert out["matched"] == 3
        assert self._props(cbm_db, "auth_check_password") == first

    def test_preserves_existing_properties(self, tmp_path, cbm_db):
        db = sqlite3.connect(str(cbm_db))
        db.execute("UPDATE nodes SET properties=json_set(properties,"
                   "'$.complexity', 7) WHERE name='sub_2000'")
        db.commit()
        db.close()
        _, symbols = make_data_dir(tmp_path)
        ingest.inject_metadata(cbm_db, symbols, "fwgraph_" + JOB)
        props = self._props(cbm_db, "sub_2000")
        assert props["complexity"] == 7 and props["addr"] == "0x2000"

    def test_transaction_rolls_back_on_bad_db(self, tmp_path):
        _, symbols = make_data_dir(tmp_path)
        with pytest.raises(sqlite3.Error):
            ingest.inject_metadata(tmp_path / "nonexistent.db",
                                   symbols, "fwgraph_" + JOB)


# ---------------------------------------------------------------------------
# propagate_libc_equiv (SIMILAR_TO edges)
# ---------------------------------------------------------------------------

EDGES_SCHEMA = """
CREATE TABLE edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    source_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    properties TEXT DEFAULT '{}'
)
"""

PROJ = "fwgraph_" + JOB


@pytest.fixture
def similar_db(tmp_path):
    """CBM-like db: Function nodes 1..6 + File node 7, SIMILAR_TO edges.

    1 util_strcpy (libc_equiv=strcpy) -- 2 sub_2000 (none)
    3 util_memcpy (libc_equiv=memcpy) -- 4 sub_4000 (none)
    5 sub_5000 (none)                -- 3 (reverse direction: donor is target)
    1                                -- 6 sub_6000 (none)
    1                                -- 7 File (not a Function: skipped)
    """
    dbfile = tmp_path / "similar.db"
    db = sqlite3.connect(str(dbfile))
    db.execute(NODES_SCHEMA)
    db.execute(EDGES_SCHEMA)
    nodes = [
        ("Function", "util_strcpy", '{"libc_equiv": "strcpy"}'),
        ("Function", "sub_2000", "{}"),
        ("Function", "util_memcpy", '{"libc_equiv": "memcpy"}'),
        ("Function", "sub_4000", "{}"),
        ("Function", "sub_5000", "{}"),
        ("Function", "sub_6000", "{}"),
        ("File", "0x1000.c", "{}"),
    ]
    for i, (label, name, props) in enumerate(nodes, start=1):
        db.execute(
            "INSERT INTO nodes(id, project, label, name, qualified_name,"
            " file_path, properties) VALUES (?,?,?,?,?,?,?)",
            (i, PROJ, label, name, f"q{i}", f"f{i}.c", props))
    for src, dst in ((1, 2), (3, 4), (5, 3), (1, 6), (1, 7)):
        db.execute(
            "INSERT INTO edges(project, source_id, target_id, type)"
            " VALUES (?,?,?,'SIMILAR_TO')", (PROJ, src, dst))
    db.commit()
    db.close()
    return dbfile


class TestPropagateLibcEquiv:
    def _props(self, dbfile, node_id):
        db = sqlite3.connect(str(dbfile))
        row = db.execute("SELECT properties FROM nodes WHERE id=?",
                         (node_id,)).fetchone()
        db.close()
        return json.loads(row[0])

    def test_one_round_both_directions(self, tmp_path, similar_db):
        out = ingest.propagate_libc_equiv(similar_db, PROJ)
        assert out == {"edges_scanned": 4, "propagated": 4}  # File edge skipped
        assert self._props(similar_db, 2) == {
            "libc_equiv": "strcpy", "libc_equiv_propagated": 1}
        assert self._props(similar_db, 4) == {
            "libc_equiv": "memcpy", "libc_equiv_propagated": 1}
        # donor on the edge's target side still propagates back to the source
        assert self._props(similar_db, 5) == {
            "libc_equiv": "memcpy", "libc_equiv_propagated": 1}
        assert self._props(similar_db, 6) == {
            "libc_equiv": "strcpy", "libc_equiv_propagated": 1}
        # donors are never marked or overwritten
        assert self._props(similar_db, 1) == {"libc_equiv": "strcpy"}
        assert self._props(similar_db, 3) == {"libc_equiv": "memcpy"}
        # File node untouched
        assert self._props(similar_db, 7) == {}

    def test_no_chaining_across_runs(self, tmp_path):
        # 1 (authoritative donor) -> 2 (none) -> 3 (none): every run reaches
        # node 2 only; propagated nodes are never donors, so node 3 must
        # stay empty no matter how often the propagation replays.
        dbfile = tmp_path / "chain.db"
        db = sqlite3.connect(str(dbfile))
        db.execute(NODES_SCHEMA)
        db.execute(EDGES_SCHEMA)
        for i, props in enumerate(
                ('{"libc_equiv": "strcpy"}', "{}", "{}"), start=1):
            db.execute(
                "INSERT INTO nodes(id, project, label, name, qualified_name,"
                " properties) VALUES (?,?,'Function',?,?,?)",
                (i, PROJ, f"f{i}", f"q{i}", props))
        for src, dst in ((1, 2), (2, 3)):
            db.execute(
                "INSERT INTO edges(project, source_id, target_id, type)"
                " VALUES (?,?,?,'SIMILAR_TO')", (PROJ, src, dst))
        db.commit()
        db.close()
        out = ingest.propagate_libc_equiv(dbfile, PROJ)
        assert out["propagated"] == 1
        assert self._props(dbfile, 2) == {
            "libc_equiv": "strcpy", "libc_equiv_propagated": 1}
        assert self._props(dbfile, 3) == {}
        # fixpoint: replaying changes nothing at all
        out2 = ingest.propagate_libc_equiv(dbfile, PROJ)
        assert out2["propagated"] == 0
        assert self._props(dbfile, 3) == {}


# ---------------------------------------------------------------------------
# run_job (CBM index + git mocked)
# ---------------------------------------------------------------------------

class TestRunJob:
    def test_happy_path(self, tmp_path, monkeypatch):
        data_dir, _ = make_data_dir(tmp_path)
        monkeypatch.setattr(ingest, "CBM_CACHE_DIR", tmp_path / "cbmcache")
        monkeypatch.setattr(ingest, "git_init_commit",
                            lambda root: {"ok": True, "committed": True})
        monkeypatch.setattr(ingest.cbm, "index_repository",
                            lambda path, proj, mode="full":
                            {"nodes": 10, "edges": 8, "status": "indexed"})
        summary = ingest.run_job(JOB, data_dir)
        assert summary["status"] == "ok"
        assert summary["project"] == "fwgraph_" + JOB
        assert summary["index"]["nodes"] == 10
        assert summary["index"]["mode"] == "full"
        assert summary["index"]["semantic_enabled"] is True
        assert summary["meta_injected"] is None  # no db file -> warning
        assert summary["warnings"]
        done = tmp_path / "cbm" / JOB / "graph_done.json"
        assert json.loads(done.read_text())["job_id"] == JOB

    def test_large_tree_selects_fast_mode(self, tmp_path, monkeypatch):
        data_dir, _ = make_data_dir(tmp_path)
        monkeypatch.setenv("CBM_SEMANTIC_MAX_FILES", "1")
        monkeypatch.setattr(ingest, "CBM_CACHE_DIR", tmp_path / "cbmcache")
        monkeypatch.setattr(ingest, "git_init_commit",
                            lambda root: {"ok": True, "committed": True})
        calls = []

        def fake_index(path, proj, mode="full"):
            calls.append(mode)
            return {"nodes": 10, "edges": 8, "status": "indexed"}

        monkeypatch.setattr(ingest.cbm, "index_repository", fake_index)
        summary = ingest.run_job(JOB, data_dir)
        assert calls == ["fast"]
        assert summary["index"]["mode"] == "fast"
        assert summary["index"]["semantic_enabled"] is False
        assert any("structural nodes, calls and usages" in w
                   for w in summary["warnings"])

    def test_empty_tree_raises(self, tmp_path):
        pseudo = tmp_path / "pseudocode" / JOB
        pseudo.mkdir(parents=True)
        (pseudo / "symbols.json").write_text(
            json.dumps({"job_id": JOB, "binaries": {}}), encoding="utf-8")
        with pytest.raises(RuntimeError, match="no pseudocode"):
            ingest.run_job(JOB, tmp_path)


# ---------------------------------------------------------------------------
# _sanitize_source
# ---------------------------------------------------------------------------

class TestSanitizeSource:
    HDR = "// addr=0x41b1d0 name=util_strcpy arch=mips32be size=36\n"

    def test_unknown_type_pointer_fastcall_stripped_name_preserved(self):
        text = (self.HDR
                + "_BYTE *__fastcall sub_41B1D0(_BYTE *a1, int a2)\n"
                  "{ return a1; }\n")
        out, fixes = ingest._sanitize_source(text)
        assert fixes == ["signature"]
        assert "_BYTE * sub_41B1D0(_BYTE *a1, int a2)" in out
        assert "__fastcall" not in out
        assert out.startswith(self.HDR)  # header line untouched

    def test_builtin_type_fastcall_kept(self):
        text = self.HDR + "int __fastcall sub_41B1D0(int a1)\n{ return 0; }\n"
        out, fixes = ingest._sanitize_source(text)
        assert "__fastcall" in out           # parses fine as-is: keep it
        assert "int __fastcall sub_41B1D0(int a1)" in out
        assert fixes == []

    def test_noreturn_and_usercall_stripped(self):
        text = self.HDR + "void __fastcall __noreturn sub_41B1D0(int a1)\n{}\n"
        out, fixes = ingest._sanitize_source(text)
        assert "__noreturn" not in out and "__fastcall" not in out
        text = self.HDR + ("unsigned int __usercall sub_41B1D0@<$v0>"
                           "(float a1@<$f13>)\n{ return 0; }\n")
        out, fixes = ingest._sanitize_source(text)
        assert "__usercall" not in out
        assert "@<$v0>" not in out and "@<$f13>" not in out
        assert "sub_41B1D0(float a1)" in out

    def test_asm_block_and_regvars_removed(self):
        text = (self.HDR + "int __fastcall sub_41B1D0(int a1)\n{\n"
                "  __asm\n  {\n    cfc1 $v0, FCSR\n  }\n"
                "  _$AT = (_$V0 | 3) ^ 2;\n"
                "  __asm { ctc1    $at, FCSR }\n"
                "  return a1;\n}\n")
        out, fixes = ingest._sanitize_source(text)
        assert "asm" in fixes and "regvar" in fixes
        assert "__asm" not in out and "cfc1" not in out
        assert "_REGAT = (_REGV0 | 3) ^ 2;" in out
        assert "return a1;" in out

    def test_clean_file_untouched(self):
        text = self.HDR + "int sub_41B1D0(int a1)\n{\n  return a1 * 2;\n}\n"
        out, fixes = ingest._sanitize_source(text)
        assert fixes == [] and out == text

    def test_function_identity_is_never_rewritten(self):
        text = self.HDR + "_BYTE *sub_41B1D0(_BYTE *a1)\n{ return a1; }\n"
        out, fixes = ingest._sanitize_source(text)
        assert fixes == [] and "sub_41B1D0(" in out
