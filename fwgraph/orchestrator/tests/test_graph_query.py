"""Unit tests for the M4 CBM CLI wrapper (pipeline.graph.query).

subprocess.run is monkeypatched throughout: no CBM binary, no network.
"""

import json
import subprocess

import pytest

from pipeline.graph import query


class _FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture
def cli(monkeypatch):
    """Capture invocations; queue canned outputs via cli.respond(...)."""
    calls = []
    responses = []

    def fake_run(cmd, capture_output, text, timeout, env):
        calls.append({"cmd": cmd, "timeout": timeout, "env": env})
        return responses.pop(0) if responses else _FakeProc(stdout="{}")

    def respond(stdout="", stderr="", returncode=0):
        responses.append(_FakeProc(stdout, stderr, returncode))

    monkeypatch.setattr(query.subprocess, "run", fake_run)
    return type("CLI", (), {"calls": calls, "respond": staticmethod(respond)})()


class TestRunCli:
    def test_parses_single_json_line(self, cli):
        cli.respond(stdout='{"total": 1}\n')
        assert query._run_cli(["search_graph"], 30) == {"total": 1}
        assert cli.calls[0]["cmd"][1] == "cli"

    def test_falls_back_to_last_json_line(self, cli):
        cli.respond(stdout='noise line\n{"a": 1}\n')
        assert query._run_cli(["query_graph"], 30) == {"a": 1}

    def test_nonzero_rc_raises_with_stderr(self, cli):
        cli.respond(stderr="boom happened", returncode=3)
        with pytest.raises(query.CBMError, match="boom happened"):
            query._run_cli(["search_graph"], 30)

    def test_nonzero_rc_salvages_stdout_json(self, cli):
        cli.respond(stdout='{"status": "ambiguous", "suggestions": []}\n',
                    stderr="level=warn msg=mem.allocator.not_owned",
                    returncode=1)
        assert query._run_cli(["trace_path"], 30)["status"] == "ambiguous"

    def test_empty_stdout_raises(self, cli):
        cli.respond(stdout="", stderr="level=info msg=x")
        with pytest.raises(query.CBMError, match="no JSON"):
            query._run_cli(["search_graph"], 30)

    def test_error_payload_raises(self, cli):
        cli.respond(stdout=json.dumps({"error": "project not found",
                                       "hint": "use list_projects"}))
        with pytest.raises(query.CBMError, match="project not found"):
            query._run_cli(["get_code_snippet"], 30)

    def test_timeout_raises(self, cli, monkeypatch):
        def boom(cmd, capture_output, text, timeout, env):
            raise subprocess.TimeoutExpired(cmd, timeout)

        monkeypatch.setattr(query.subprocess, "run", boom)
        with pytest.raises(query.CBMError, match="timed out"):
            query._run_cli(["index_repository"], 5)

    def test_default_timeouts(self, cli, monkeypatch):
        monkeypatch.delenv("CBM_QUERY_TIMEOUT", raising=False)
        monkeypatch.delenv("CBM_INDEX_TIMEOUT", raising=False)
        cli.respond(stdout="{}")
        query._run_cli(["search_graph"], query.query_timeout())
        assert cli.calls[0]["timeout"] == 30
        cli.respond(stdout="{}")
        query.index_repository("/tmp/x", "p")
        assert cli.calls[-1]["timeout"] == 1800


class TestCommands:
    def test_index_repository_uses_explicit_full_mode(self, cli):
        cli.respond(stdout='{"status": "indexed", "nodes": 5, "edges": 4}')
        out = query.index_repository("/repo", "fwgraph_x")
        assert out["nodes"] == 5
        call = cli.calls[0]
        assert call["cmd"] == [query._cbm_bin(), "cli", "index_repository",
                               "--repo-path", "/repo", "--name", "fwgraph_x",
                               "--mode", "full"]

    def test_index_repository_can_use_fast_mode(self, cli):
        cli.respond(stdout='{"status": "indexed"}')
        query.index_repository("/repo", "fwgraph_x", mode="fast")
        assert cli.calls[0]["cmd"][-2:] == ["--mode", "fast"]

    def test_index_repository_rejects_unknown_mode(self, cli):
        with pytest.raises(ValueError, match="unsupported CBM index mode"):
            query.index_repository("/repo", "fwgraph_x", mode="turbo")
        assert cli.calls == []

    def test_search_args(self, cli):
        cli.respond(stdout='{"total": 0, "results": []}')
        query.search("p", "auth.*", label="Function", limit=10)
        assert cli.calls[0]["cmd"][2:] == [
            "search_graph", "--project", "p", "--name-pattern", "auth.*",
            "--format", "json", "--label", "Function", "--limit", "10"]

    def test_search_normalizes_tree_model(self, cli):
        # CBM >=0.9 --format json tree model -> classic results list
        cli.respond(stdout=json.dumps({
            "total": 2, "count": 2, "cols": ["name", "label", "lines"],
            "groups": [{"qn_prefix": "p.a", "file": "a.c",
                        "rows": [["sub_1", "Function", "1-9"],
                                 ["sub_2", "Function", "10-19"]]}],
            "has_more": False}))
        out = query.search("p", "sub_", label="Function")
        assert out["results"] == [
            {"name": "sub_1", "qualified_name": "p.a.sub_1",
             "label": "Function"},
            {"name": "sub_2", "qualified_name": "p.a.sub_2",
             "label": "Function"}]

    def test_cypher_args(self, cli):
        cli.respond(stdout='{"columns": [], "rows": [], "total": 0}')
        query.cypher("p", "MATCH (f:Function) RETURN f.name LIMIT 1")
        assert cli.calls[0]["cmd"][2:] == [
            "query_graph",
            json.dumps({"project": "p",
                        "query": "MATCH (f:Function) RETURN f.name LIMIT 1",
                        "format": "json"})]

    def test_trace_args(self, cli):
        cli.respond(stdout='{"function": "f", "callers": [], "callees": []}')
        query.trace("p", "f", direction="inbound")
        assert cli.calls[0]["cmd"][2:] == [
            "trace_path", "--project", "p", "--function-name", "f",
            "--direction", "inbound", "--format", "json"]

    def test_trace_maps_in_to_inbound(self, cli):
        cli.respond(stdout='{"function": "f", "callers": []}')
        query.trace("p", "f", direction="in")
        cmd = cli.calls[0]["cmd"]
        assert cmd[cmd.index("--direction") + 1] == "inbound"

    def test_trace_maps_out_to_outbound(self, cli):
        cli.respond(stdout='{"function": "f", "callees": []}')
        query.trace("p", "f", direction="out")
        cmd = cli.calls[0]["cmd"]
        assert cmd[cmd.index("--direction") + 1] == "outbound"

    def test_trace_rejects_unknown_direction(self, cli):
        with pytest.raises(query.CBMError, match="invalid trace direction"):
            query.trace("p", "f", direction="sideways")
        assert cli.calls == []

    def test_snippet_resolves_qualified_name(self, cli):
        cli.respond(stdout=json.dumps({"total": 2, "results": [
            {"name": "auth_check_password_2",
             "qualified_name": "p.b.auth_check_password_2"},
            {"name": "auth_check_password",
             "qualified_name": "p.a.auth_check_password"}]}))
        cli.respond(stdout=json.dumps({"name": "auth_check_password",
                                       "source": "int x;"}))
        out = query.snippet("p", "auth_check_password")
        assert out["source"] == "int x;"
        # second call must use the exact match's qualified_name
        assert cli.calls[1]["cmd"][2:] == [
            "get_code_snippet", "--project", "p",
            "--qualified-name", "p.a.auth_check_password"]

    def test_snippet_unknown_name_raises(self, cli):
        cli.respond(stdout='{"total": 0, "results": []}')
        with pytest.raises(query.CBMError, match="no Function"):
            query.snippet("p", "nonexistent")

    def test_dangerous_callsites_builds_in_query(self, cli):
        cli.respond(stdout='{"columns": [], "rows": [], "total": 0}')
        query.dangerous_callsites("p", functions=["strcpy", "system"], limit=20)
        sent = cli.calls[0]["cmd"]
        q = json.loads(sent[3])["query"]
        assert "g.name IN ['strcpy', 'system']" in q
        assert "g.libc_equiv IN ['strcpy', 'system']" in q  # dual match
        assert " OR " in q
        assert "LIMIT 20" in q
        assert "[:CALLS]" in q

    def test_dangerous_callsites_default_list(self, cli):
        cli.respond(stdout='{"columns": [], "rows": [], "total": 0}')
        query.dangerous_callsites("p")
        sent = cli.calls[0]["cmd"]
        q = json.loads(sent[3])["query"]
        for name in ("strcpy", "sprintf", "system", "popen"):
            assert f"'{name}'" in q
