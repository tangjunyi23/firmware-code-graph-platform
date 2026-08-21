"""Regression tests for the security-hardening pass (S1-S4, M4/M5/M6/M9):

- S1: uvicorn access-log redaction of ?token= credentials
- S2: baseline security response headers middleware
- S3: per-job ownership — job_guard 404s strangers without leaking job
  existence, /jobs list filtering, /graph/query owner check, owner recorded
  at upload, owner backfill on load
- M4: /graph/query cypher op is read-only (write keywords -> 400)
- M5: upload streaming cap (413), disk-headroom check (507),
  DELETE /jobs/{job_id} artifact cleanup
- M6: global decompile semaphore honors env limits
- M9: _save_job is atomic and survives ENOSPC-style failures
- S4: qemu_cov sandbox gate — userns probe, TRACE_ALLOW_ROOT_CHROOT opt-in,
  Chinese warning in run meta, unshare cmdline shape
"""

import json
import logging
import re
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from orchestrator.app import accounts, main
from pipeline.trace import qemu_cov

JOB = "secjob000001"
JOB2 = "secjob000002"
LEGACY = "secjoblegacy"
MD5 = "9e39391af855fd996cdd90437e2eeb7b"


def _session(username, role="user"):
    return accounts.create_session(username, role)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# S1: access-log token redaction
# ---------------------------------------------------------------------------

class TestAccessLogRedaction:
    @staticmethod
    def _record(msg):
        return logging.LogRecord("uvicorn.access", logging.INFO,
                                 __file__, 0, msg, None, None)

    def test_token_rewritten(self):
        f = main._TokenRedactFilter()
        rec = self._record(
            '127.0.0.1 - "GET /cbmui/?token=fwgraph-SECRET123&x=1 HTTP/1.1" 200')
        assert f.filter(rec) is True
        out = rec.getMessage()
        assert "SECRET123" not in out
        assert "token=***" in out
        assert "x=1" in out  # other query params untouched

    def test_multiple_tokens_and_clean_lines(self):
        f = main._TokenRedactFilter()
        rec = self._record('"GET /a?token=t1&token=t2 HTTP/1.1" 404')
        f.filter(rec)
        assert rec.getMessage().count("token=***") == 2
        clean = self._record('"GET /healthz HTTP/1.1" 200')
        f.filter(clean)
        assert clean.getMessage() == '"GET /healthz HTTP/1.1" 200'

    def test_installed_at_startup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
        monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
        monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
        monkeypatch.setattr(main.admin_api, "apply_settings", lambda: None)
        main.startup()
        logger = logging.getLogger("uvicorn.access")
        try:
            assert any(isinstance(f, main._TokenRedactFilter)
                       for f in logger.filters)
        finally:
            logger.filters[:] = [f for f in logger.filters
                                 if not isinstance(f, main._TokenRedactFilter)]


# ---------------------------------------------------------------------------
# S2: security response headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def test_headers_on_api_response(self):
        resp = TestClient(main.app).get("/healthz")
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "SAMEORIGIN"
        assert resp.headers["referrer-policy"] == "no-referrer"


# ---------------------------------------------------------------------------
# S3: per-job ownership
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_env(tmp_path, monkeypatch):
    """ORCH_TOKEN set + isolated accounts store; jobs with distinct owners."""
    monkeypatch.setenv("ORCH_TOKEN", "main-secret")
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    base = {"firmware": "fw.bin", "status": "graphed", "error": None,
            "created_at": "t0", "updated_at": "t0", "size_bytes": 1}
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, **base, "owner": "alice"}
        main._jobs[JOB2] = {"job_id": JOB2, **base, "owner": "bob"}
        main._jobs[LEGACY] = {"job_id": LEGACY, **base}  # owner-less legacy
    yield TestClient(main.app)
    with main._jobs_lock:
        for j in (JOB, JOB2, LEGACY):
            main._jobs.pop(j, None)


class TestOwnerGate:
    def test_owner_admin_and_legacytoken_ok_stranger_404(self, auth_env):
        alice, bob = _session("alice"), _session("bob")
        admin = _session("root", role="admin")
        assert auth_env.get(f"/jobs/{JOB}", headers=_auth(alice)
                            ).status_code == 200
        assert auth_env.get(f"/jobs/{JOB}", headers=_auth(admin)
                            ).status_code == 200
        assert auth_env.get(f"/jobs/{JOB}", headers=_auth(bob)
                            ).status_code == 404
        # legacy main token remains all-powerful
        assert auth_env.get(f"/jobs/{JOB}", headers=_auth("main-secret")
                            ).status_code == 200

    def test_legacy_ownerless_job_visible_to_all(self, auth_env):
        bob = _session("bob")
        assert auth_env.get(f"/jobs/{LEGACY}", headers=_auth(bob)
                            ).status_code == 200

    def test_stranger_404_on_write_endpoint_too(self, auth_env):
        """job_guard runs before any payload validation: a stranger must get
        404 (existence hidden), never a 400 that confirms the job exists."""
        bob = _session("bob")
        resp = auth_env.post(f"/jobs/{JOB}/trace",
                             json={"binary_md5": "0" * 32, "argv": ["x"]},
                             headers=_auth(bob))
        assert resp.status_code == 404

    def test_unknown_job_still_404(self, auth_env):
        alice = _session("alice")
        assert auth_env.get("/jobs/nosuchjob99", headers=_auth(alice)
                            ).status_code == 404

    def test_jobs_list_filtered(self, auth_env):
        alice, bob = _session("alice"), _session("bob")
        admin = _session("root", role="admin")
        ids = lambda r: {j["job_id"] for j in r.json()}
        r = auth_env.get("/jobs", headers=_auth(alice))
        assert JOB in ids(r) and LEGACY in ids(r) and JOB2 not in ids(r)
        r = auth_env.get("/jobs", headers=_auth(bob))
        assert JOB2 in ids(r) and LEGACY in ids(r) and JOB not in ids(r)
        r = auth_env.get("/jobs", headers=_auth(admin))
        assert {JOB, JOB2, LEGACY} <= ids(r)

    def test_graph_query_owner_check(self, auth_env, monkeypatch):
        bob = _session("bob")
        monkeypatch.setattr(main.graph_query, "search",
                            lambda *a, **k: {"total": 0, "results": []})
        ok = auth_env.post("/graph/query",
                           json={"job_id": JOB, "op": "search",
                                 "pattern": "x"},
                           headers=_auth("main-secret"))
        assert ok.status_code == 200
        no = auth_env.post("/graph/query",
                           json={"job_id": JOB, "op": "search",
                                 "pattern": "x"},
                           headers=_auth(bob))
        assert no.status_code == 404


# ---------------------------------------------------------------------------
# M5: upload limits + DELETE /jobs/{job_id}
# ---------------------------------------------------------------------------

class _FakeThread:
    def __init__(self, target=None, args=(), **kwargs):
        self.target, self.args = target, args

    def start(self):  # never run pipeline workers in tests
        pass


@pytest.fixture
def up(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
    monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
    main.FIRMWARE_DIR.mkdir(parents=True)
    main.EXTRACTED_DIR.mkdir(parents=True)
    monkeypatch.setattr(main, "_disk_free_bytes", lambda path: 100 * 1024**3)
    monkeypatch.setattr(main, "threading",
                        SimpleNamespace(Thread=_FakeThread))
    yield TestClient(main.app)


class TestUploadLimits:
    def test_oversize_413(self, up, monkeypatch):
        monkeypatch.setenv("MAX_FIRMWARE_BYTES", "16")
        resp = up.post("/firmware", files={
            "file": ("fw.bin", b"x" * 100, "application/octet-stream")})
        assert resp.status_code == 413
        assert "上限" in resp.json()["detail"]

    def test_low_disk_507(self, up, monkeypatch):
        monkeypatch.setattr(main, "_disk_free_bytes", lambda path: 1)
        resp = up.post("/firmware", files={
            "file": ("fw.bin", b"x" * 10, "application/octet-stream")})
        assert resp.status_code == 507
        assert "磁盘" in resp.json()["detail"]

    def test_owner_recorded_on_upload(self, up, monkeypatch, tmp_path):
        monkeypatch.setenv("ORCH_TOKEN", "main-secret")
        token = _session("carol")
        resp = up.post("/firmware",
                       files={"file": ("fw.bin", b"\x00" * 8)},
                       headers=_auth(token))
        assert resp.status_code == 201
        job_id = resp.json()["job_id"]
        try:
            assert main._jobs[job_id]["owner"] == "carol"
            audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
            assert "firmware_upload" in audit
        finally:
            with main._jobs_lock:
                main._jobs.pop(job_id, None)


@pytest.fixture
def deletable(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "main-secret")
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path / "acct"))
    data = tmp_path / "data"
    monkeypatch.setattr(main, "DATA_DIR", data)
    attrs = ("FIRMWARE_DIR", "EXTRACTED_DIR", "PSEUDOCODE_DIR", "CBM_DIR",
             "TRACES_DIR", "ATTACK_DIR", "ROUTES_DIR", "INPUTS_DIR",
             "FUZZ_DIR", "FRIDA_DIR", "GRAPHEXT_DIR", "SURFACES_DIR")
    names = ("firmware", "extracted", "pseudocode", "cbm", "traces",
             "attack", "routes", "inputs", "fuzz", "frida", "graphext",
             "surfaces")
    for attr, name in zip(attrs, names):
        monkeypatch.setattr(main, attr, data / name)
    job_id = "deljob000001"
    for name in names + ("decompile", "idb"):
        d = data / name / job_id
        d.mkdir(parents=True)
        (d / "marker").write_text("x", encoding="utf-8")
    (data / "extracted" / f"{job_id}.emba.log").write_text("log",
                                                           encoding="utf-8")
    cbm_cache = tmp_path / "cbm-cache"
    cbm_cache.mkdir()
    (cbm_cache / f"fwgraph_{job_id}.db").write_bytes(b"db")
    monkeypatch.setattr(main.graph_ingest, "db_path",
                        lambda proj: cbm_cache / f"{proj}.db")
    with main._jobs_lock:
        main._jobs[job_id] = {"job_id": job_id, "firmware": "fw.bin",
                              "status": "graphed", "error": None,
                              "created_at": "t0", "updated_at": "t0",
                              "size_bytes": 1, "owner": "dave"}
    yield TestClient(main.app), job_id, data, cbm_cache
    with main._jobs_lock:
        main._jobs.pop(job_id, None)


class TestDeleteJob:
    def test_owner_delete_removes_everything(self, deletable, tmp_path):
        http, job_id, data, cbm_cache = deletable
        resp = http.delete(f"/jobs/{job_id}", headers=_auth(_session("dave")))
        assert resp.status_code == 200
        assert resp.json() == {"job_id": job_id, "deleted": True}
        for d in data.iterdir():
            if d.is_dir():
                assert not (d / job_id).exists(), f"leftover: {d / job_id}"
        assert not (data / "extracted" / f"{job_id}.emba.log").exists()
        assert not (cbm_cache / f"fwgraph_{job_id}.db").exists()
        assert job_id not in main._jobs
        audit = (tmp_path / "acct" / "audit.jsonl").read_text(encoding="utf-8")
        last = json.loads(audit.splitlines()[-1])
        assert last["action"] == "job_delete"
        assert last["user"] == "dave" and last["detail"] == job_id

    def test_admin_may_delete(self, deletable):
        http, job_id, _, _ = deletable
        admin = _session("root", role="admin")
        assert http.delete(f"/jobs/{job_id}", headers=_auth(admin)
                           ).status_code == 200

    def test_stranger_404(self, deletable):
        http, job_id, _, _ = deletable
        assert http.delete(f"/jobs/{job_id}", headers=_auth(_session("eve"))
                           ).status_code == 404

    def test_running_409(self, deletable):
        http, job_id, _, _ = deletable
        main._jobs[job_id]["status"] = "decompiling"
        assert http.delete(f"/jobs/{job_id}", headers=_auth(_session("dave"))
                           ).status_code == 409

    def test_unknown_404(self, deletable):
        http, _, _, _ = deletable
        assert http.delete("/jobs/nosuchjob99",
                           headers=_auth(_session("dave"))).status_code == 404


# ---------------------------------------------------------------------------
# M4: cypher read-only whitelist
# ---------------------------------------------------------------------------

@pytest.fixture
def graph_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "")
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "fw.bin",
                           "status": "graphed", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1}
    yield TestClient(main.app)
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


class TestCypherWhitelist:
    def test_read_query_passes(self, graph_env, monkeypatch):
        monkeypatch.setattr(main.graph_query, "cypher",
                            lambda project, q: {"rows": [], "total": 0})
        resp = graph_env.post("/graph/query", json={
            "job_id": JOB, "op": "cypher",
            "query": "MATCH (f:Function) RETURN f.name LIMIT 5"})
        assert resp.status_code == 200

    @pytest.mark.parametrize("bad", [
        "MATCH (n) DELETE n",
        "match (n) set n.x = 1 return n",
        "CREATE (n:Function) RETURN n",
        "MATCH (n) MERGE (m) RETURN m",
        "CALL db.labels() YIELD label RETURN label",
        "LOAD CSV FROM 'x' AS row RETURN row",
        "MATCH (n) REMOVE n.x RETURN n",
        "DROP INDEX foo IF EXISTS",
    ])
    def test_write_query_400(self, graph_env, bad):
        resp = graph_env.post("/graph/query", json={
            "job_id": JOB, "op": "cypher", "query": bad})
        assert resp.status_code == 400
        assert "只读" in resp.json()["detail"]

    def test_offset_is_not_a_false_positive(self, graph_env, monkeypatch):
        # 'OFFSET'/'SKIP' contain no standalone SET keyword
        monkeypatch.setattr(main.graph_query, "cypher",
                            lambda project, q: {"rows": [], "total": 0})
        resp = graph_env.post("/graph/query", json={
            "job_id": JOB, "op": "cypher",
            "query": "MATCH (n) RETURN n SKIP 10 OFFSET 0"})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# M6: global decompile semaphore
# ---------------------------------------------------------------------------

class TestConcurrencyGates:
    def test_decompile_sem_honors_env(self, monkeypatch):
        monkeypatch.setattr(main, "_decompile_sem", None)
        monkeypatch.setenv("DECOMPILE_MAX_JOBS", "3")
        assert main._decompile_semaphore()._value == 3

    def test_defaults(self, monkeypatch):
        monkeypatch.setattr(main, "_decompile_sem", None)
        monkeypatch.delenv("DECOMPILE_MAX_JOBS", raising=False)
        assert main._decompile_semaphore()._value == 2


# ---------------------------------------------------------------------------
# M9: atomic _save_job + S3 owner backfill on load
# ---------------------------------------------------------------------------

class TestSaveJob:
    def test_atomic_write_no_tmp_left(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
        main._save_job({"job_id": "savejob00001", "status": "done"})
        d = tmp_path / "firmware" / "savejob00001"
        assert json.loads((d / "job.json").read_text(
            encoding="utf-8"))["status"] == "done"
        assert not (d / "job.json.tmp").exists()

    def test_oserror_logged_not_raised(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")

        def boom(*a, **k):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(main.os, "replace", boom)
        main._save_job({"job_id": "savejob00002", "status": "done"})
        assert "persist failed" in capsys.readouterr().out

    def test_load_jobs_backfills_owner(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "FIRMWARE_DIR", tmp_path / "firmware")
        d = tmp_path / "firmware" / "oldjob000001"
        d.mkdir(parents=True)
        (d / "job.json").write_text(json.dumps({
            "job_id": "oldjob000001", "firmware": "x.bin", "status": "done",
            "error": None, "created_at": "t", "updated_at": "t"}),
            encoding="utf-8")
        try:
            main._load_jobs()
            assert main._jobs["oldjob000001"]["owner"] == "admin"
            persisted = json.loads((d / "job.json").read_text(encoding="utf-8"))
            assert persisted["owner"] == "admin"  # written back once
        finally:
            with main._jobs_lock:
                main._jobs.pop("oldjob000001", None)


# ---------------------------------------------------------------------------
# Audit + quota on the dynamic-analysis trigger endpoints
# ---------------------------------------------------------------------------

class _DummyLock:
    def acquire(self, blocking=False):
        return True

    def release(self):
        pass


@pytest.fixture
def dyn_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ORCH_TOKEN", "main-secret")
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    monkeypatch.setattr(main, "EXTRACTED_DIR", tmp_path / "extracted")
    monkeypatch.setattr(main, "PSEUDOCODE_DIR", tmp_path / "pseudocode")
    monkeypatch.setattr(main, "FUZZ_DIR", tmp_path / "fuzz")
    (main.EXTRACTED_DIR / JOB).mkdir(parents=True)
    (main.EXTRACTED_DIR / JOB / "manifest.json").write_text(json.dumps(
        {"binaries": [{"md5": MD5, "path": "bin/svc", "arch": "mips"}]}),
        encoding="utf-8")
    (main.PSEUDOCODE_DIR / JOB).mkdir(parents=True)
    (main.PSEUDOCODE_DIR / JOB / "symbols.json").write_text(json.dumps(
        {"binaries": {MD5: {"functions": []}}}), encoding="utf-8")
    monkeypatch.setattr(main, "TRACE_LOCK", _DummyLock())
    monkeypatch.setattr(main, "threading",
                        SimpleNamespace(Thread=_FakeThread))
    with main._jobs_lock:
        main._jobs[JOB] = {"job_id": JOB, "firmware": "fw.bin",
                           "status": "graphed", "error": None,
                           "created_at": "t0", "updated_at": "t0",
                           "size_bytes": 1, "owner": "alice"}
    yield TestClient(main.app), tmp_path
    with main._jobs_lock:
        main._jobs.pop(JOB, None)


class TestTriggerAuditQuota:
    @staticmethod
    def _last_audit(tmp_path):
        audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        return json.loads(audit.splitlines()[-1])

    def test_trace_trigger(self, dyn_env, monkeypatch):
        http, tmp_path = dyn_env
        seen = {}
        monkeypatch.setattr(accounts, "check_quota",
                            lambda j, k: seen.setdefault("quota", (j, k)),
                            raising=False)
        alice = _session("alice")
        resp = http.post(f"/jobs/{JOB}/trace",
                         json={"binary_md5": MD5, "argv": ["svc"]},
                         headers=_auth(alice))
        assert resp.status_code == 202
        assert seen["quota"] == (JOB, "trace")
        last = self._last_audit(tmp_path)
        assert last["action"] == "trace_trigger"
        assert last["user"] == "alice" and last["detail"] == JOB

    def test_fuzz_trigger(self, dyn_env, monkeypatch):
        http, tmp_path = dyn_env
        seen = {}
        monkeypatch.setattr(accounts, "check_quota",
                            lambda j, k: seen.setdefault("quota", (j, k)),
                            raising=False)
        alice = _session("alice")
        resp = http.post(f"/jobs/{JOB}/fuzz",
                         json={"binary_md5": MD5},
                         headers=_auth(alice))
        assert resp.status_code == 202
        assert seen["quota"] == (JOB, "fuzz")
        assert self._last_audit(tmp_path)["action"] == "fuzz_trigger"


# ---------------------------------------------------------------------------
# S4: qemu_cov trace sandbox
# ---------------------------------------------------------------------------

class _FakeProc:
    """Popen stand-in: already-exited process with an unreachable pgid."""

    pid = 2**22
    stdin = None

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


class TestTraceSandbox:
    def test_userns_probe_cached(self, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(qemu_cov.subprocess, "run", fake_run)
        monkeypatch.setattr(qemu_cov, "_USERNS_OK", None)
        assert qemu_cov.userns_available() is True
        assert qemu_cov.userns_available() is True  # cached: one probe only
        assert len(calls) == 1 and calls[0][:2] == ["unshare", "-Urn"]

    def test_gate_requires_explicit_optin(self, monkeypatch):
        monkeypatch.setattr(qemu_cov, "_USERNS_OK", False)
        monkeypatch.delenv("TRACE_ALLOW_ROOT_CHROOT", raising=False)
        with pytest.raises(qemu_cov.QemuError) as exc_info:
            qemu_cov.sandbox_mode()
        assert "TRACE_ALLOW_ROOT_CHROOT" in str(exc_info.value)
        monkeypatch.setenv("TRACE_ALLOW_ROOT_CHROOT", "1")
        assert qemu_cov.sandbox_mode() == "root"

    def test_root_mode_warns_in_meta(self, tmp_path, monkeypatch):
        """Gated root fallback: the Chinese warning lands in the run meta
        (and from there in trace.json)."""
        # 固定走 Phase 2 之前的裁决：docker 可用且沙箱镜像存在时
        # trace_exec_mode 会改判 docker，本用例语义是 root 门控
        monkeypatch.setattr(qemu_cov.sandbox, "backend_for",
                            lambda _component: "userns")
        monkeypatch.setattr(qemu_cov, "_USERNS_OK", False)
        monkeypatch.setenv("TRACE_ALLOW_ROOT_CHROOT", "1")
        monkeypatch.delenv("TRACE_SUDO_PASSWORD", raising=False)
        monkeypatch.delenv("EMBA_SUDO_PASSWORD", raising=False)
        rootfs = tmp_path / "rootfs"
        (rootfs / "tmp").mkdir(parents=True)
        monkeypatch.setattr(
            qemu_cov, "sudo_run",
            lambda *a, **k: SimpleNamespace(returncode=0, stdout="",
                                            stderr=""))
        real_popen = qemu_cov.subprocess.Popen

        def fake_popen(cmd, **kwargs):
            if "-D" not in cmd:  # pass through pkill & friends
                return real_popen(cmd, **kwargs)
            log_rel = cmd[cmd.index("-D") + 1]
            (rootfs / log_rel.lstrip("/")).write_text(
                "Trace 0x1 [0x400290]\n", encoding="utf-8")
            return _FakeProc()

        monkeypatch.setattr(qemu_cov.subprocess, "Popen", fake_popen)
        addrs, meta = qemu_cov.run_coverage(
            rootfs, "/qemu-arm", ["/bin/hello"], "unittest0001",
            run_timeout=1.0)
        assert addrs == [0x400290]
        assert meta["sandbox"] == "root"
        assert "警告" in meta["sandbox_warning"]

    def test_userns_mode_cmdline_shape(self, tmp_path, monkeypatch):
        """userns mode: unshare -Urm, -n for one-shot runs only (service
        runs keep host net so the loopback probe/trigger still works)."""
        # 同上：固定非 docker 后端，保证本用例覆盖 userns 命令行形态
        monkeypatch.setattr(qemu_cov.sandbox, "backend_for",
                            lambda _component: "userns")
        monkeypatch.setattr(qemu_cov, "_USERNS_OK", True)
        rootfs = tmp_path / "rootfs"
        (rootfs / "tmp").mkdir(parents=True)
        seen = {}
        real_popen = qemu_cov.subprocess.Popen

        def fake_popen(cmd, **kwargs):
            if "-c" not in cmd:  # pass through pkill & friends
                return real_popen(cmd, **kwargs)
            seen["cmd"] = list(cmd)
            script = cmd[cmd.index("-c") + 1]
            log_rel = re.search(r"-D (\S+)", script).group(1)
            (rootfs / log_rel.lstrip("/")).write_text(
                "Trace 0x1 [0x400290]\n", encoding="utf-8")
            return _FakeProc()

        monkeypatch.setattr(qemu_cov.subprocess, "Popen", fake_popen)
        addrs, meta = qemu_cov.run_coverage(
            rootfs, "/qemu-arm", ["/bin/hello"], "unittest0002",
            run_timeout=1.0)
        cmd = seen["cmd"]
        assert cmd[:2] == ["unshare", "-Urm"]
        assert "-n" in cmd and "sudo" not in cmd[0]
        assert meta["sandbox"] == "userns"
        assert "sandbox_warning" not in meta

        qemu_cov.run_coverage(rootfs, "/qemu-arm", ["/bin/svc"],
                              "unittest0003", port=8080, probe_port=False,
                              hold_seconds=0.01, run_timeout=1.0)
        assert "-n" not in seen["cmd"]  # service run keeps the host net
