"""Unit tests for M5: functions endpoints (main.py), CBM UI reverse proxy
and SPA static hosting (webui.py).

The proxy upstream is replaced by an in-process ASGI app via a monkeypatched
``webui._make_client``; auth is disabled via empty ORCH_TOKEN unless a test
sets it explicitly.
"""

import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main, webui

JOB = "webuijob0001"
MD5 = "9e39391af855fd996cdd90437e2eeb7b"

SYMBOLS = {
    "job_id": JOB,
    "binaries": {
        MD5: {
            "path": "firmware/bin/busybox",
            "arch": "mips",
            "bits": 32,
            "endianness": "be",
            "functions": [
                {"addr": "0x4000b4", "name": ".init_proc", "size": 44,
                 "lines": 4, "calls": [], "strings": [], "is_exported": True,
                 "decompile_ok": True, "decompile_error": None,
                 "tags": ["entrypoint"]},
                {"addr": "0x401000", "name": "sub_401000", "size": 128,
                 "lines": 40, "calls": ["strcpy"], "strings": ["pw"],
                 "is_exported": False, "decompile_ok": True,
                 "decompile_error": None, "tags": ["auth_related"],
                 "ai_name": "check_password", "ai_confidence": 0.91,
                 "ai_reason": "compares credentials",
                 "domain": "auth",
                 "observed_in_trace": True, "verified_reachable": True,
                 "trace_ids": ["abc123def456"]},
            ],
        },
    },
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setattr(main, "PSEUDOCODE_DIR", tmp_path / "pseudocode")
    pseudo_job = main.PSEUDOCODE_DIR / JOB
    (pseudo_job / MD5 / "functions").mkdir(parents=True)
    (pseudo_job / "symbols.json").write_text(json.dumps(SYMBOLS),
                                             encoding="utf-8")
    (pseudo_job / MD5 / "functions" / "0x4000b4.c").write_text(
        "int __start(void) { return 0; }\n", encoding="utf-8")
    (pseudo_job / MD5 / "functions" / "0x4000b4.asm").write_text(
        "// addr=0x4000b4 name=.init_proc arch=mips32be size=44\n"
        "lui $v0, 0x42\njr $ra\n", encoding="utf-8")
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "fw.bin",
                           "status": "graphed", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1}
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


class TestGraphLayout:
    def test_ok(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(main.graph_ingest, "db_path",
                            lambda proj: tmp_path / f"{proj}.db")
        (tmp_path / "fwgraph_webuijob0001.db").write_bytes(b"db")
        layout = {"total_nodes": 2,
                  "nodes": [{"id": 1, "x": 0.0, "y": 0.0, "label": "File",
                             "name": "a.c"},
                            {"id": 2, "x": 1.0, "y": 1.0, "label": "Function",
                             "name": "sub_1"}],
                  "edges": [{"source": 1, "target": 2, "type": "CONTAINS_FILE"}],
                  "missed_graph": {"nodes": []}}

        class FakeResp:
            status_code = 200

            @staticmethod
            def json():
                return layout

        seen = {}

        def fake_get(url, params=None, timeout=None):
            seen.update(url=url, params=params)
            return FakeResp()

        monkeypatch.setattr(main.httpx, "get", fake_get)
        resp = client.get(f"/jobs/{JOB}/graph/layout")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_nodes"] == 2
        assert len(body["nodes"]) == 2
        assert len(body["edges"]) == 1
        assert "missed_graph" not in body
        assert seen["params"] == {"project": "fwgraph_webuijob0001"}

    def test_not_graphed_409(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(main.graph_ingest, "db_path",
                            lambda proj: tmp_path / "missing.db")
        assert client.get(f"/jobs/{JOB}/graph/layout").status_code == 409

    def test_unknown_job_404(self, client):
        assert client.get("/jobs/nope/graph/layout").status_code == 404


    def test_flattened(self, client):
        resp = client.get(f"/jobs/{JOB}/functions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert body["binaries"][MD5]["arch"] == "mips"
        f0, f1 = body["functions"]
        assert f0["addr"] == "0x4000b4" and f0["tags"] == ["entrypoint"]
        assert f0["binary"] == MD5 and f0["arch"] == "mips"
        assert "calls" not in f0 and "strings" not in f0  # heavy fields dropped
        assert f1["ai_name"] == "check_password"
        assert f1["ai_confidence"] == 0.91
        assert f1["ai_reason"] == "compares credentials"
        assert f1["domain"] == "auth"
        assert f1["observed_in_trace"] is True
        assert f1["verified_reachable"] is True
        assert f1["trace_ids"] == ["abc123def456"]

    def test_unknown_job_404(self, client):
        assert client.get("/jobs/nope/functions").status_code == 404

    def test_no_symbols_404(self, client):
        (main.PSEUDOCODE_DIR / JOB / "symbols.json").unlink()
        assert client.get(f"/jobs/{JOB}/functions").status_code == 404


class TestFunctionSource:
    def test_ok(self, client):
        resp = client.get(f"/jobs/{JOB}/functions/{MD5}/0x4000b4/source")
        assert resp.status_code == 200
        assert "__start" in resp.text
        assert resp.headers["content-type"].startswith("text/plain")

    def test_addr_case_insensitive_fallback(self, client):
        resp = client.get(f"/jobs/{JOB}/functions/{MD5}/0X4000B4/source")
        # '0X' is rejected by the addr regex -> 400, not a path escape
        assert resp.status_code == 400
        resp = client.get(f"/jobs/{JOB}/functions/{MD5}/0x4000B4/source")
        assert resp.status_code == 200  # falls back to lowercase filename

    def test_bad_format_400(self, client):
        assert client.get(f"/jobs/{JOB}/functions/notamd5/0x4000b4/source"
                          ).status_code == 400

    def test_traversal_rejected(self, client):
        # Direct call: the regex guard rejects path escapes in the md5 segment
        # (at HTTP level %2F handling differs across starlette versions).
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            main.get_function_source(JOB, "../../etc", "0x1")
        assert exc_info.value.status_code == 400
        with pytest.raises(HTTPException) as exc_info:
            main.get_function_source(JOB, MD5, "0x1; rm -rf /")
        assert exc_info.value.status_code == 400

    def test_missing_file_404(self, client):
        assert client.get(f"/jobs/{JOB}/functions/{MD5}/0xdeadbeef/source"
                          ).status_code == 404

    def test_asm_ok(self, client):
        resp = client.get(f"/jobs/{JOB}/functions/{MD5}/0x4000b4/source?asm=1")
        assert resp.status_code == 200
        assert "jr $ra" in resp.text
        assert resp.headers["content-type"].startswith("text/plain")

    def test_asm_missing_404(self, client):
        # 0x401000 has pseudo-C exported but no .asm in this fixture
        assert client.get(f"/jobs/{JOB}/functions/{MD5}/0x401000/source?asm=1"
                          ).status_code == 404

    def test_unknown_job_404(self, client):
        assert client.get(f"/jobs/nope/functions/{MD5}/0x4000b4/source"
                          ).status_code == 404


# ---------------------------------------------------------------------------
# CBM UI reverse proxy
# ---------------------------------------------------------------------------

def _fake_upstream_app(seen: dict):
    async def app(scope, receive, send):
        assert scope["type"] == "http"
        body = b""
        while True:
            msg = await receive()
            if msg["type"] == "http.request":
                body += msg.get("body", b"")
                if not msg.get("more_body"):
                    break
            else:
                break
        headers = {k.decode(): v.decode() for k, v in scope["headers"]}
        seen.update(path=scope["path"], query=scope["query_string"].decode(),
                    host=headers.get("host"), body=body,
                    authorization=headers.get("authorization"),
                    origin=headers.get("origin"))
        if scope["path"] == "/":
            payload = (b'<html><head>'
                       b'<script src="/assets/index-A.js"></script>'
                       b'<link href="/assets/index-B.css">'
                       b'<a href="https://example.com/x">ext</a>'
                       b'</head></html>')
            resp_headers = [(b"content-type", b"text/html"),
                            (b"content-security-policy",
                             b"default-src 'self'; frame-ancestors 'none'")]
        else:
            payload = b'{"ok": true}'
            resp_headers = [(b"content-type", b"application/json")]
        await send({"type": "http.response.start", "status": 200,
                    "headers": resp_headers})
        await send({"type": "http.response.body", "body": payload})
    return app


@pytest.fixture
def proxy_client(monkeypatch):
    seen = {}

    def fake_make_client():
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=_fake_upstream_app(seen)))

    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setattr(webui, "_make_client", fake_make_client)
    return TestClient(main.app), seen


class TestCbmUiProxy:
    def test_index_html_rewritten(self, proxy_client):
        http, seen = proxy_client
        resp = http.get("/cbmui/")
        assert resp.status_code == 200
        # Host recomputed from the upstream URL (original was "testserver"):
        assert seen["path"] == "/"
        assert seen["host"] == "127.0.0.1:9749"
        assert 'src="/cbmui/assets/index-A.js"' in resp.text
        assert 'href="/cbmui/assets/index-B.css"' in resp.text
        assert 'href="https://example.com/x"' in resp.text  # external untouched
        csp = resp.headers["content-security-policy"]
        assert "frame-ancestors 'self'" in csp
        assert "'none'" not in csp

    def test_origin_header_stripped(self, proxy_client):
        # the public CBM nginx 403s any Origin that is not its own :9749;
        # browser module/fetch requests always carry the SPA's :8000 Origin
        http, seen = proxy_client
        resp = http.get("/cbmui/assets/index-A.js",
                        headers={"origin": "http://192.168.108.129:8000"})
        assert resp.status_code == 200
        assert seen["origin"] is None

    def test_cbmui_redirect(self, proxy_client):
        http, _ = proxy_client
        resp = http.get("/cbmui", follow_redirects=False)
        assert resp.status_code in (307, 302, 308)
        assert resp.headers["location"] == "/cbmui/"

    def test_api_passthrough_with_query_and_body(self, proxy_client):
        http, seen = proxy_client
        resp = http.post("/api/layout?x=1&y=2",
                         content=b'{"a": 1}',
                         headers={"content-type": "application/json"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        assert seen["path"] == "/api/layout"
        assert seen["query"] == "x=1&y=2"
        assert seen["body"] == b'{"a": 1}'

    def test_rpc_passthrough(self, proxy_client):
        http, seen = proxy_client
        resp = http.post("/rpc", content=b'{"jsonrpc":"2.0","id":1}')
        assert resp.status_code == 200
        assert seen["path"] == "/rpc"

    def test_auth_required_when_token_set(self, proxy_client, monkeypatch,
                                          tmp_path):
        http, _ = proxy_client
        monkeypatch.setenv("ORCH_TOKEN", "s3cret")
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        assert http.get("/cbmui/").status_code == 401
        assert http.get("/api/processes").status_code == 401
        # Bearer header with the main token: unchanged behavior
        assert http.get("/cbmui/", headers={
            "Authorization": "Bearer s3cret"}).status_code == 200
        # cookie: main token (legacy login) and session token both work
        assert http.get("/cbmui/", cookies={
            webui.TOKEN_COOKIE: "s3cret"}).status_code == 200
        session = accounts.create_session("alice", "user")
        assert session.startswith("fws-")
        assert http.get("/cbmui/", cookies={
            webui.TOKEN_COOKIE: session}).status_code == 200
        # query string: session tokens only — the main token is rejected so
        # it can never leak into URLs (access logs, history, Referer)
        assert http.get(f"/cbmui/?token={session}").status_code == 200
        assert http.get("/cbmui/?token=s3cret").status_code == 401
        assert http.get("/cbmui/?token=wrong").status_code == 401
        # a well-formed but unknown session token is still rejected
        assert http.get("/cbmui/?token=fws-notreal").status_code == 401

    def test_token_query_not_forwarded(self, proxy_client, monkeypatch,
                                       tmp_path):
        http, seen = proxy_client
        monkeypatch.setenv("ORCH_TOKEN", "s3cret")
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        session = accounts.create_session("alice", "user")
        assert http.get(f"/api/processes?token={session}&x=1"
                        ).status_code == 200
        assert seen["query"] == "x=1"

    def test_upstream_down_502(self, proxy_client, monkeypatch):
        http, _ = proxy_client

        def boom():
            return httpx.AsyncClient(transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(
                    httpx.ConnectError("refused"))))

        monkeypatch.setattr(webui, "_make_client", boom)
        assert http.get("/cbmui/").status_code == 502


# ---------------------------------------------------------------------------
# SPA static hosting
# ---------------------------------------------------------------------------

@pytest.fixture
def spa_app(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>spa</html>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log(1)",
                                            encoding="utf-8")
    app = FastAPI()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    webui.setup(app, dist_dir=dist)
    return TestClient(app)


class TestSpaHosting:
    def test_index_at_root(self, spa_app):
        resp = spa_app.get("/")
        assert resp.status_code == 200
        assert resp.text == "<html>spa</html>"

    def test_asset_served(self, spa_app):
        resp = spa_app.get("/assets/app.js")
        assert resp.status_code == 200
        assert "console.log" in resp.text

    def test_spa_fallback(self, spa_app):
        resp = spa_app.get("/functions/some/deep/link")
        assert resp.status_code == 200
        assert resp.text == "<html>spa</html>"

    def test_api_route_still_wins(self, spa_app):
        resp = spa_app.get("/healthz")
        assert resp.json() == {"status": "ok"}

    def test_no_dist_no_mount(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ORCH_TOKEN", "")
        app = FastAPI()
        webui.setup(app, dist_dir=tmp_path / "missing")
        assert TestClient(app).get("/").status_code == 404

    def test_mobile_drawer_width_contract(self):
        webui_src = Path(__file__).parents[2] / "webui" / "src"
        jobs = (webui_src / "views" / "JobsView.vue").read_text(
            encoding="utf-8")
        functions = (webui_src / "views" / "FunctionsView.vue").read_text(
            encoding="utf-8")
        app = (webui_src / "App.vue").read_text(encoding="utf-8")
        helper = (webui_src / "useNarrowViewport.js").read_text(
            encoding="utf-8")
        assert ":size=\"isNarrow ? '96%' : '52%'\"" in jobs
        assert ":column=\"isNarrow ? 1 : 3\"" in jobs
        assert ":size=\"isNarrow ? '96%' : '58%'\"" in functions
        assert "(max-width: 720px)" in helper
        assert "watch(functionsView, loadPendingFunctionJob)" in app
