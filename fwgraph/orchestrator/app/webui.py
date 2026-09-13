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

Auth: when ORCH_TOKEN is set, proxy routes accept the bearer header (main
ORCH_TOKEN only, unchanged), a `fwgraph_token` cookie (the SPA sets it at
login so the CBM iframe and its same-origin fetches authenticate; main token
or an `fws-` session token), or a `?token=` query param — session tokens
ONLY. The main ORCH_TOKEN is deliberately rejected in URLs so it never lands
in access logs, browser history or Referer headers.

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

from . import accounts

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


# Session tokens minted by accounts.create_session carry this prefix
# (accounts._TOKEN_PREFIX); only they may authenticate via URL query params.
_SESSION_PREFIX = "fws-"


def _session_token_ok(token: str | None) -> bool:
    """True only for well-formed `fws-` session tokens that resolve."""
    if not token or not token.startswith(_SESSION_PREFIX):
        return False
    return accounts.resolve_session(token) is not None


def proxy_authorized(request: Request) -> bool:
    """Mirror main.require_token semantics, plus cookie/query for browser
    contexts (iframe, CBM UI's own fetches) that cannot set headers.

    S1 URL hardening: the main ORCH_TOKEN works via the Bearer header
    (unchanged) and the login cookie, but NEVER via ?token= — URLs leak into
    access logs / browser history / Referer. Query-string tokens must be
    resolvable `fws-` session tokens (that is also what lets session users
    open the /cbmui iframe, which used to accept the main token only).
    """
    token = os.getenv("ORCH_TOKEN", "")
    if not token:
        return True
    if request.headers.get("authorization") == f"Bearer {token}":
        return True
    cookie = request.cookies.get(TOKEN_COOKIE)
    if cookie is not None and (cookie == token or _session_token_ok(cookie)):
        return True
    return _session_token_ok(request.query_params.get("token"))


def _forward_headers(request: Request) -> dict:
    # 'origin' must not reach the public CBM nginx: it 403s any Origin that
    # is neither empty nor its own :9749 address, and browser module/fetch
    # requests always carry the SPA's :8000 Origin (bug found via CDP).
    return {k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "authorization"
            and k.lower() != "origin"}


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


_STALE_RELOAD_JS = (
    "(function(){try{"
    "if(sessionStorage.getItem('fwgraph_stale_reload'))return;"
    "sessionStorage.setItem('fwgraph_stale_reload','1');"
    "var u=new URL(location.href);u.searchParams.set('_v',Date.now());"
    "location.replace(u);"
    "}catch(e){}})();"
)


def _stale_reload_response() -> Response:
    """Executable stub for a stale build's hashed .js: force one cache-busted
    reload (guarded), so a page built from an old index.html recovers itself
    instead of showing a dead white screen. A fresh page never requests
    missing assets, so this only ever runs for stale clients."""
    return Response(
        content=_STALE_RELOAD_JS,
        media_type="text/javascript; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


class SPAStaticFiles(StaticFiles):
    """StaticFiles that falls back to index.html for unknown GET/HEAD paths
    (client-side routing / deep links).

    Missing assets/ files 404 instead of falling back: serving HTML for a
    stale hashed build's <script> URLs gets blocked by MIME checking and the
    SPA never mounts. index.html itself is sent no-cache so browsers pick up
    new hashed asset names right after a redeploy.

    A browser still holding a PRE-no-cache index.html requests the old build's
    hashed .js, which now 404s and would leave a dead white page. Serve those
    a tiny executable stub that force-reloads once (sessionStorage-guarded),
    healing stale caches without the user having to hard-refresh."""

    async def get_response(self, path: str, scope):
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404 and scope["method"] in ("GET", "HEAD"):
                if path.startswith("assets/") and path.endswith(".js"):
                    return _stale_reload_response()
                if not path.startswith("assets/"):
                    response = await super().get_response("index.html", scope)
                    if str(getattr(response, "path", "")).endswith("index.html"):
                        response.headers["Cache-Control"] = "no-cache"
                    return response
            raise
        if str(getattr(response, "path", "")).endswith("index.html"):
            response.headers["Cache-Control"] = "no-cache"
        return response


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
