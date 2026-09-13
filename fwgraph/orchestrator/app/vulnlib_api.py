"""漏洞库 API：收录 CVE/CNVD/CNNVD，并按本地固件任务查 N-day。

  GET    /vulnlib                     检索（q/source/severity/vendor/product/cwe）
  GET    /vulnlib/stats               条数与来源/危害分布
  GET    /vulnlib/nday                用可见任务对条目打分（候选，不是判定）
  GET    /vulnlib/{vid}               单条全文
  POST   /vulnlib                     单条收录（201）
  POST   /vulnlib/import              批量导入对象/数组
  PATCH  /vulnlib/{vid}               覆盖更新已有字段
  DELETE /vulnlib/{vid}               删除（管理员）

库在 data/vulnlib/；不联网拉 NVD/CNVD。查询只读本库。
"""

from fastapi import Body, Depends, FastAPI, HTTPException, Query

from pipeline import vulnlib

from . import accounts


def _raise_lib(exc: vulnlib.VulnlibError, status: int = 422):
    raise HTTPException(status_code=status, detail=str(exc)) from exc


def _visible_jobs(principal: dict) -> list:
    from . import main as _main

    with _main._jobs_lock:
        jobs = list(_main._jobs.values())
    return [j for j in jobs if accounts.can_access(principal, j.get("owner"))]


def setup(app: FastAPI, require_token, require_admin) -> None:
    """Register vuln-library routes. Call BEFORE webui.setup."""
    auth = [Depends(require_token)]

    @app.get("/vulnlib/stats", dependencies=auth)
    def lib_stats():
        return vulnlib.stats()

    @app.get("/vulnlib", dependencies=auth)
    def list_advisories(
        q: str = Query(""),
        source: str = Query(""),
        severity: str = Query(""),
        vendor: str = Query(""),
        product: str = Query(""),
        cwe: str = Query(""),
        limit: int = Query(50),
        offset: int = Query(0),
    ):
        return vulnlib.search(
            q=q, source=source, severity=severity, vendor=vendor,
            product=product, cwe=cwe, limit=limit, offset=offset)

    @app.get("/vulnlib/nday", dependencies=auth)
    def nday_lookup(
        principal: dict = Depends(require_token),
        q: str = Query(""),
        vendor: str = Query(""),
        product: str = Query(""),
        source: str = Query(""),
        job_id: str = Query(""),
        limit: int = Query(50),
    ):
        jobs = _visible_jobs(principal)
        if job_id:
            jobs = [j for j in jobs if j.get("job_id") == job_id]
            if not jobs:
                raise HTTPException(status_code=404, detail="job not found")
        return vulnlib.nday(
            jobs, q=q, vendor=vendor, product=product, source=source, limit=limit)

    @app.get("/vulnlib/{vid}", dependencies=auth)
    def get_advisory(vid: str):
        doc = vulnlib.load(vid)
        if doc is None:
            raise HTTPException(status_code=404, detail="advisory not found")
        return doc

    @app.post("/vulnlib", status_code=201)
    def create_advisory(payload: dict = Body(...),
                        principal: dict = Depends(require_token)):
        try:
            existing = None
            if payload.get("id"):
                existing = vulnlib.load(str(payload["id"]))
            doc = vulnlib.normalize(
                payload, owner=principal.get("username") or "", existing=existing)
            vulnlib.save(doc)
        except vulnlib.VulnlibError as exc:
            _raise_lib(exc)
        accounts.audit(principal.get("username") or "?", "vulnlib_upsert",
                       f"id={doc['id']}")
        return doc

    @app.post("/vulnlib/import")
    def import_advisories(payload: dict | list = Body(...),
                          principal: dict = Depends(require_token)):
        try:
            result = vulnlib.ingest(
                payload, owner=principal.get("username") or "")
        except vulnlib.VulnlibError as exc:
            _raise_lib(exc)
        accounts.audit(principal.get("username") or "?", "vulnlib_import",
                       f"imported={result['imported']} errors={len(result['errors'])}")
        return result

    @app.patch("/vulnlib/{vid}")
    def update_advisory(vid: str, payload: dict = Body(...),
                        principal: dict = Depends(require_token)):
        existing = vulnlib.load(vid)
        if existing is None:
            raise HTTPException(status_code=404, detail="advisory not found")
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="条目必须是 JSON 对象")
        merged = dict(existing)
        merged.update(payload)
        merged["id"] = existing["id"]
        try:
            doc = vulnlib.normalize(
                merged, owner=principal.get("username") or "", existing=existing)
            vulnlib.save(doc)
        except vulnlib.VulnlibError as exc:
            _raise_lib(exc)
        accounts.audit(principal.get("username") or "?", "vulnlib_update",
                       f"id={doc['id']}")
        return doc

    @app.delete("/vulnlib/{vid}")
    def delete_advisory(vid: str, principal: dict = Depends(require_admin)):
        if not vulnlib.delete(vid):
            raise HTTPException(status_code=404, detail="advisory not found")
        accounts.audit(principal.get("username") or "?", "vulnlib_delete",
                       f"id={vid}")
        return {"ok": True, "id": vid}
