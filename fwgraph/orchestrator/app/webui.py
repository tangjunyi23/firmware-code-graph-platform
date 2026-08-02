"""M5 web UI support: CBM UI reverse proxy + SPA static hosting.

The CBM web UI (codebase-memory-mcp --ui) hard-binds 127.0.0.1:9749 and
validates the Host header (anti DNS-rebinding), so it cannot be exposed
directly. This module reverse-proxies it under the orchestrator port:

  /cbmui/...  -> http://127.0.0.1:9749/...   (Host rewritten; HTML asset
                                               URLs rewritten to stay under
                                               /cbmui; CSP frame-ancestors
                                               relaxed so the SPA can iframe it)
  /api/...    -> http://127.0.0.1:9749/api/...   (CBM UI's own XHR surface)
  /rpc        -> http://127.0.0.1:9749/rpc       (CBM UI's JSON-RPC endpoint)

CBM UI v0.9.0 uses plain fetch() only — no WebSocket/EventSource — so plain
HTTP proxying is sufficient.

Auth: when ORCH_TOKEN is set, proxy routes accept the bearer header, a
`fwgraph_token` cookie (the SPA sets it at login so the CBM iframe and its
same-origin fetches authenticate), or a `?token=` query param.

SPA hosting: if webui/dist exists it is mounted at "/" LAST, so every API
route registered earlier wins; unknown GET paths fall back to index.html.
"""

import os
import re
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

CBM_UI_URL = os.getenv("CBM_UI_URL", "http://127.0.0.1:9749")
PROXY_TIMEOUT = float(os.getenv("CBM_UI_PROXY_TIMEOUT", "60"))
TOKEN_COOKIE = "fwgraph_token"

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "trailer", "transfer-encoding", "upgrade",
    "content-length", "content-encoding", "host",
})
_PROXY_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def _make_client() -> httpx.AsyncClient:
    """Factory kept tiny so tests can inject an ASGI-transport client."""
    return httpx.AsyncClient(timeout=httpx.Timeout(PROXY_TIMEOUT, connect=5.0),
                             follow_redirects=True)


def proxy_authorized(request: Request) -> bool:
    """Mirror main.require_token semantics, plus cookie/query for browser
    contexts (iframe, CBM UI's own fetches) that cannot set headers."""
    token = os.getenv("ORCH_TOKEN", "")
    if not token:
        return True
    if request.headers.get("authorization") == f"Bearer {token}":
        return True
    if request.cookies.get(TOKEN_COOKIE) == token:
        return True
    if request.query_params.get("token") == token:
        return True
    return False


def _forward_headers(request: Request) -> dict:
    return {k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"}


def _rewrite_csp(value: str) -> str:
    # 'frame-ancestors none' would forbid the SPA iframe; the proxied UI is
    # same-origin with the SPA, so 'self' keeps the intent while embedding.
    if "frame-ancestors" in value:
        value = re.sub(r"frame-ancestors\s+'none'", "frame-ancestors 'self'",
                       value)
    return value


def _rewrite_html(body: bytes) -> bytes:
    """Root-absolute asset URLs (src/href="/...") must stay under /cbmui so
    they hit the proxy instead of the SPA mount."""
    text = body.decode("utf-8", errors="replace")
    text = re.sub(r'(src|href)="/(?!/)', r'\1="/cbmui/', text)
    return text.encode("utf-8")


async def _proxy(request: Request, upstream_path: str, rewrite_html: bool) -> Response:
    if not proxy_authorized(request):
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")
    query = httpx.QueryParams(
        [(k, v) for k, v in request.query_params.multi_items() if k != "token"])
    client = _make_client()
    try:
        upstream = await client.request(
            request.method,
            f"{CBM_UI_URL}{upstream_path}",
            params=query,
            content=await request.body(),
            headers=_forward_headers(request),
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502,
                            detail=f"cbm ui unreachable: {type(exc).__name__}") from exc
    finally:
        await client.aclose()

    content = upstream.content
    headers = {}
    content_type = upstream.headers.get("content-type", "")
    for k, v in upstream.headers.items():
        lk = k.lower()
        if lk in _HOP_BY_HOP:
            continue
        headers[k] = _rewrite_csp(v) if lk == "content-security-policy" else v
    if rewrite_html and content_type.startswith("text/html"):
        content = _rewrite_html(content)
    return Response(content=content, status_code=upstream.status_code,
                    headers=headers, media_type=None)


class SPAStaticFiles(StaticFiles):
    """StaticFiles that falls back to index.html for unknown GET/HEAD paths
    (client-side routing / deep links)."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404 and scope["method"] in ("GET", "HEAD"):
                return await super().get_response("index.html", scope)
            raise


def setup(app: FastAPI, dist_dir: Path | None = None) -> None:
    """Register proxy routes and (if built) the SPA mount. Must be called
    AFTER all API routes so the catch-alls lose to them."""

    @app.get("/cbmui", include_in_schema=False)
    async def cbmui_root():
        return RedirectResponse(url="/cbmui/")

    @app.api_route("/cbmui/{path:path}", methods=_PROXY_METHODS,
                   include_in_schema=False)
    async def cbmui_proxy(request: Request, path: str):
        return await _proxy(request, "/" + path, rewrite_html=True)

    @app.api_route("/api/{path:path}", methods=_PROXY_METHODS,
                   include_in_schema=False)
    async def cbmui_api_proxy(request: Request, path: str):
        return await _proxy(request, "/api/" + path, rewrite_html=False)

    @app.api_route("/rpc", methods=["GET", "POST", "OPTIONS"],
                   include_in_schema=False)
    async def cbmui_rpc_proxy(request: Request):
        return await _proxy(request, "/rpc", rewrite_html=False)

    dist = dist_dir if dist_dir is not None else FWGRAPH_ROOT / "webui" / "dist"
    if dist.is_dir():
        app.mount("/", SPAStaticFiles(directory=str(dist), html=True),
                  name="webui-spa")
