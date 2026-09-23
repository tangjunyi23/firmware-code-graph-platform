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
        events = (webui_src / "views" / "EventsView.vue").read_text(
            encoding="utf-8")
        assert "WorkbenchView" in jobs
        wb_src = (webui_src / "workbench" / "WorkbenchView.vue").read_text(
            encoding="utf-8")
        # 主题类名契约：wb-root + data-wb-theme（旧 cyber class 已迁移）
        assert "wb-root" in wb_src
        assert "data-wb-theme" in wb_src
        tour = (webui_src / "components" / "OnboardingTour.vue").read_text(
            encoding="utf-8")
        assert "fwgraph_onboard_v2" in tour
        assert "固件解密" in tour
        # 2026-09 教程改版：九步看板/上传/回工作台选任务；协议逆向、
        # 许愿模式步骤已随导航精简移除
        assert "九步看板" in tour
        assert "入口风险评估" in tour
        assert "协议逆向" not in tour
        assert "许愿模式" not in tour
        assert "ops-home" in app
        assert "ParticleField" in app
        # SplashOverlay 已随 2026-09 壳层精简移除（粒子背景直达主壳）
        assert 'lang="zh-CN"' in (webui_src.parent / "index.html").read_text(
            encoding="utf-8")
        theme = (webui_src / "theme.css").read_text(encoding="utf-8")
        assert "--fw-bg:" in theme
        assert "--fw-brand:" in theme
        # 主题切换契约：html[data-fw-theme] 属性选择器（class="dark" 已废弃）
        assert "data-fw-theme" in theme
        assert "data-fw-theme" in app
        dash = (webui_src / "views" / "DashboardView.vue").read_text(
            encoding="utf-8")
        # 2026-09 仪表盘精简：图表收敛为 RadarScreen + CountUp
        assert "RadarScreen" in dash
        assert "CountUp" in dash
        assert "findings_by_severity" in dash
        assert "findings_by_class" in dash
        assert "危害等级" in dash
        assert "威胁雷达" in dash
        assert "厂商漏洞排行" in dash
        assert "实时扫描日志" in dash
        assert "ProtocolView" in app
        assert "{ index: 'protocol', title: '入口风险评估'" in app
        assert "page === 'protocol'" in app
        assert "{ index: 'protofuzz', title: '协议挖掘'" not in app
        assert "DecryptView" in app
        assert "{ index: 'decrypt', title: '固件解密'" in app
        assert "page === 'decrypt'" in app
        dec = (webui_src / "views" / "DecryptView.vue").read_text(
            encoding="utf-8")
        assert "固件解密" in dec
        assert "/decrypt" in dec
        assert "正在解密" in dec or "解密进行中" in dec
        proto = (webui_src / "views" / "ProtocolView.vue").read_text(
            encoding="utf-8")
        # 2026-09 改版：页面重定位为「入口风险评估」，能力卡收敛为
        # 攻击面评估 / 入口风险排序
        assert "入口风险评估" in proto
        assert "攻击面评估" in proto
        assert "入口风险排序" in proto
        assert "/protocol-reverse" in proto
        assert "PrepareView" in app
        assert "WishView" in app
        assert "快速挖掘" in app
        assert "专家模式" in app
        assert "mode-switch" in app
        wish = (webui_src / "views" / "WishView.vue").read_text(encoding="utf-8")
        assert "buildWishTask" in wish
        assert "uploadFirmware" in wish
        assert "/vulnagent/sessions" in wish
        assert "ProgressRing" in wish
        assert "overallPct" in wish
        assert "inspect" in wish
        pipe = (webui_src / "workbench" / "pipeline.js").read_text(encoding="utf-8")
        assert "WISH_OPTIONS" in pipe
        assert "buildWishTask" in pipe
        assert "pipeProgress" in pipe
        assert "prepare" in app
        assert ":size=\"isNarrow ? '96%' : '58%'\"" in functions
        assert "(max-width: 720px)" in helper
        assert "watch(functionsView, loadPendingFunctionJob)" in app
        assert "EventsView" in app
        assert "index: 'vuln'" not in app
        assert "简易模式" not in app
        prepare = (webui_src / "views" / "PrepareView.vue").read_text(
            encoding="utf-8")
        assert "uploadFirmware" in prepare
        assert "gear-btn" not in prepare
        assert "announceSteps" in prepare
        assert "ProgressRing" in (
            webui_src / "workbench" / "PipelineCard.vue").read_text(
            encoding="utf-8")
        card = (webui_src / "workbench" / "PipelineCard.vue").read_text(
            encoding="utf-8")
        assert "进度播报" in card
        assert "stepPct" in card
        assert "固件解密" in pipe
        assert "STEP_TALK" in pipe
        assert "announceSteps" in pipe
        wb = (webui_src / "workbench" / "WorkbenchView.vue").read_text(
            encoding="utf-8")
        dsh = (webui_src / "workbench" / "dshClient.js").read_text(
            encoding="utf-8")
        assert "huntPrompt" not in wb
        assert "fw_get_identification" not in wb
        assert "src.kind !== 'user'" in dsh
        assert "isInjectedHuntHint" in dsh
        assert "【编排】" in dsh
        assert "只做能力验收" in dsh
        assert "平台已修好" in dsh
        assert "禁止再说缺少平台能力" in dsh
        assert "record_finding" in dsh
        assert "summary.status !== 'running'" in dsh
        assert "data.chunk" in dsh
        assert "blk-${turn}-${step}-${idx}" in dsh
        assert "_seenSeq" in dsh
        assert "feedText" in dsh
        assert "openMux()" in dsh
        assert "Date.now() + 60000" not in dsh
        assert "for (let i = 0; i < 10; i++)" not in dsh
        assert "flushType" in dsh
        assert "typeCaughtUp" in dsh
        assert "document.hidden" in dsh
        assert "TYPE_MS" not in dsh
        assert "job.rest[0]" not in dsh
        assert "markRaw" in dsh
        assert "bindStreamEl" in dsh
        assert "highlightText" in dsh
        assert "lastLine" in dsh
        assert "think-${turn}" in dsh
        assert "expectRunning" in dsh
        ml = (webui_src / "workbench" / "MessageList.vue").read_text(
            encoding="utf-8")
        assert "Deep diving" not in ml
        assert "思考中" in ml
        assert "thinkPreview" in ml
        assert "think-preview" in ml
        assert "think-dock" in ml
        assert "think-glow" in ml
        assert "fx-dot" in ml
        assert "highlightText" in ml
        assert "liveThink" in ml
        assert "bindStreamEl" in ml
        assert "content-visibility: auto" not in ml
        # 历史窗口分批放行（BATCH×reveal），不再一次全量渲染
        assert "revealMore" in ml
        assert "显示更早" in ml
        hl = (webui_src / "highlight.js").read_text(encoding="utf-8")
        assert "highlightText" in hl
        assert "renderMarkdown" in hl
        assert "hl-num" in hl
        mdv = (webui_src / "workbench" / "MarkdownText.vue").read_text(
            encoding="utf-8")
        assert "renderMarkdown" in mdv
        reports = (webui_src / "views" / "ReportsView.vue").read_text(
            encoding="utf-8")
        assert "renderMarkdown" in reports
        assert "DeepAgent" not in ml
        assert "deepagent" not in ml.lower()
        assert ml.count("composer-seat") == 0
        wb = (webui_src / "workbench" / "WorkbenchView.vue").read_text(
            encoding="utf-8")
        assert "composer-seat" in wb
        qd = (webui_src / "workbench" / "QueueDock.vue").read_text(
            encoding="utf-8")
        assert "isInjectedHuntHint" in qd
        assert "scroll-wrap" in wb
        assert "expectRunning: true" in wb
        assert "silent: true" in wb
        assert "20000" in wb
        catalog_js = (webui_src / "workbench" / "catalog.js").read_text(
            encoding="utf-8")
        assert "sameRows" in catalog_js
        assert "silent = false" in catalog_js
        persona = (
            Path(__file__).parents[3] / "vulnagent" / "dsh" / "cordis.patch.yml"
        ).read_text(encoding="utf-8")
        assert "简体中文" in persona
        assert "一次最多并行 2 个工具" in persona
        assert "onStopCurrent" in wb
        assert "onInterruptCurrent" in wb
        assert '@stop="onInterruptCurrent"' in wb
        assert "resumeHunt" in dsh
        assert "/resume" in dsh
        sidebar = (webui_src / "workbench" / "SidebarJobs.vue").read_text(
            encoding="utf-8")
        composer = (webui_src / "workbench" / "Composer.vue").read_text(
            encoding="utf-8")
        assert "session.stop" in sidebar
        assert "session.archive" in sidebar
        assert "session.purgeArchived" in sidebar
        assert "sess-menu" in sidebar
        assert "onStopSession" in wb
        assert "onArchiveSession" in wb
        assert "onPurgeArchived" in wb
        assert "if (running.value)" in composer
        assert "emit('stop')" in composer
        assert "approval.auto" in composer
        assert "approval.ask" in composer
        assert "setApprovalPolicy" in composer
        assert "ok: true" in dsh
        assert "approvalId" in dsh
        assert "setApprovalPolicy" in dsh
        ap = (webui_src / "workbench" / "ApprovalPanel.vue").read_text(
            encoding="utf-8")
        assert "session.approve" in ap
        assert "respond('rejected')" in ap
        assert "respond('allowed-once')" in ap
        assert "chat-home" in app
        assert "/jobs/${jobId.value}/logs" in events or "/jobs/" in events
        assert "parseLogLine" in events
        assert "viewLines" in events
        assert "word-break: break-all" not in events
        assert "挖掘事件" not in events
        assert "goto', 'vuln'" not in app
        assert "VulnlibView" in app
        assert "{ index: 'vulnlib', title: '漏洞库'" in app
        assert "page === 'vulnlib'" in app
        assert "'vulnlib'" in app



class TestCleanLogLines:
    def test_strips_ansi_and_progress_cr(self):
        raw = (
            "\x1bc\x1b[1m[\x1b[0;32m+\x1b[0m] hello\x1b[0m\n"
            "progress 1\rprogress 2\n"
            "a" * 64 + "\n"
        )
        hid = "ab" * 32
        raw += f"id {hid} done\n"
        out = main._clean_log_lines(raw)
        assert out[0] == "[+] hello"
        assert "progress 2" in out
        assert "progress 1" not in out
        assert "\x1b" not in "".join(out)
        assert any(line.startswith("id abababababab…") for line in out)

    def test_drops_emba_todo_list(self):
        raw = (
            "keep-before\n"
            "-----------------------------------------------------------------\n"
            "Current state of your personal todo list:\n"
            "    [✓] Installed EMBA\n"
            "    [-] Spread the word\n"
            "-----------------------------------------------------------------\n"
            "keep-after\n"
        )
        out = main._clean_log_lines(raw)
        assert "keep-before" in out
        assert "keep-after" in out
        assert not any("Installed EMBA" in x for x in out)
        assert not any("todo list" in x.lower() for x in out)

    def test_collapses_blacklisted_modules(self):
        raw = (
            "keep\n"
            "    Blacklisted module: S10_binaries_basic_check\n"
            "    Blacklisted module: S12_binary_protection\n"
            "after\n"
        )
        out = main._clean_log_lines(raw)
        assert out == ["keep", "[*] 已按策略跳过 2 个模块", "after"]
