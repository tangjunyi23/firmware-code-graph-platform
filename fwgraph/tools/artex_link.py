#!/usr/bin/env python3
"""fwgraph ↔ ARTEX bridge — link emulated firmware devices to ARTEX pentest
tasks and pull ARTEX findings back as fwgraph finding drafts.

Sub-commands
  env-assets <job_id> [--env ENV_ID]   show/emit ARTEX assets for published
                                       emulation envs of the job
  create-task <job_id> [--env ENV_ID]  [--firmware NAME] register assets and
                                       create an ARTEX task in one shot
  pull <task_id> [--out DIR]           pull ARTEX findings, write fwgraph
                                       finding drafts + a summary report

Why drafts, not direct POST: fwgraph findings are server-validated evidence
(call_chain with →, poc, binary_md5 in manifest, observed/verified need a
platform trace_id). ARTEX black-box results carry none of those anchors, so
they land as reviewable drafts next to the job data; a human promotes them
through POST /vulnagent/findings after filling the chain.

Env (both .env files are NOT read here — export explicitly or use the
run wrapper):
  FWGRAPH_BASE_URL / FWGRAPH_TOKEN   orchestrator + bearer
  ARTEX_BASE_URL / ARTEX_PASSWORD    artex API + admin password (default
                                     http://127.0.0.1:8787)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

FW_BASE = os.environ.get("FWGRAPH_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
FW_TOKEN = os.environ.get("FWGRAPH_TOKEN", "")
AX_BASE = os.environ.get("ARTEX_BASE_URL", "http://127.0.0.1:8787").rstrip("/")

# host address ARTEX agents will attack — the machine running the qemu emul
ATTACK_HOST = os.environ.get("ARTEX_ATTACK_HOST", "192.168.108.129")


def _req(method: str, url: str, *, token: str = "", body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        sys.exit(f"HTTP {exc.code} from {url}: {exc.read().decode()[:400]}")
    except (urllib.error.URLError, TimeoutError) as exc:
        sys.exit(f"unreachable {url}: {exc}")


def fw(method: str, path: str, body: dict | None = None):
    return _req(method, FW_BASE + path, token=FW_TOKEN, body=body)


def artex_login() -> str:
    pw = os.environ.get("ARTEX_PASSWORD", "")
    if not pw:
        sys.exit("ARTEX_PASSWORD not set (artex admin password)")
    out = _req("POST", AX_BASE + "/api/auth/login",
               body={"username": "ARTEX", "password": pw})
    return out["token"]


def _envs(job_id: str, env_id: str = "") -> list[dict]:
    envs = fw("GET", f"/emul/envs?job_id={job_id}")
    if not isinstance(envs, list):
        envs = envs.get("envs", [])
    if env_id:
        envs = [e for e in envs if e.get("env_id") == env_id]
    published = [e for e in envs if e.get("status") == "published"]
    if not published:
        sys.exit(f"no published emulation env for job {job_id}"
                 + (f" env {env_id}" if env_id else "")
                 + f" (statuses: {[e.get('status') for e in envs]})")
    return published


def _env_assets(job_id: str, env: dict) -> list[dict]:
    """ARTEX service assets for one published env: every hostfwd port that
    probes alive, plus verified endpoints as named services."""
    assets: list[dict] = []
    seen: set[int] = set()
    for svc in env.get("services") or []:
        if svc.get("status") == "ok" and svc.get("host_port"):
            port = int(svc["host_port"])
            if port in seen:
                continue
            seen.add(port)
            assets.append({
                "type": "service", "ip": ATTACK_HOST, "port": port,
                "service_name": str(svc.get("name") or "firmware-service"),
            })
    for ep in env.get("verified_endpoints") or []:
        port = ep.get("port")
        if port and int(port) not in seen:
            seen.add(int(port))
            assets.append({
                "type": "service", "ip": ATTACK_HOST, "port": int(port),
                "service_name": f"{ep.get('proto') or 'tcp'}-verified",
            })
    return assets


def _firmware_name(job_id: str) -> str:
    for job in fw("GET", "/jobs"):
        if job.get("job_id") == job_id:
            return job.get("firmware") or job_id
    return job_id


GOAL_TMPL = """\
对固件模拟设备开展黑盒渗透验证。设备固件：{fwname}（fwgraph job {job_id}），\
模拟环境 {env_id}，目标 {host}。

约束与指引：
1. 目标仅限上述资产（本机 qemu 模拟的固件设备，禁止触及其他网段）。
2. 已接入 fwgraph MCP 工具（mcp__fwgraph__*）：先 fw_routes 拿固件 HTTP 路由表、\
fw_attack_surface 看打分攻击路径、fw_findings 看已登记的 static-only finding——\
你的任务是把这些静态结论在真实服务上黑盒证实或证伪。
3. 每个结论必须给可复现 PoC（请求/响应证据）；服务名/端口对应的处理函数用 \
fw_search / fw_function_brief 反查，形成"黑盒现象 ↔ 固件代码"对应。
4. 认证类入口先查 fw_read_bytes 看硬编码凭据/鉴权表，再实测。
"""


def cmd_env_assets(args):
    for env in _envs(args.job_id, args.env):
        assets = _env_assets(args.job_id, env)
        print(json.dumps({"env_id": env.get("env_id"), "assets": assets},
                         ensure_ascii=False, indent=2))


def _manual_assets(specs: list[str]) -> list[dict]:
    """--asset host:port[:name] entries, for manually-run qemu labs."""
    assets = []
    for spec in specs:
        parts = spec.split(":")
        if len(parts) < 2:
            sys.exit(f"--asset expects host:port[:name], got {spec!r}")
        host, port, name = parts[0], parts[1], ":".join(parts[2:]) or "manual"
        assets.append({"type": "service", "ip": host, "port": int(port),
                       "service_name": name})
    return assets


def cmd_create_task(args):
    jwt = artex_login()
    if args.asset:
        assets = _manual_assets(args.asset)
        env_label = "manual-lab"
        source_summary = "fwgraph manual assets"
    else:
        env = _envs(args.job_id, args.env)[0]
        assets = _env_assets(args.job_id, env)
        if not assets:
            sys.exit(f"env {env.get('env_id')} has no alive hostfwd services")
        env_label = env.get("env_id")
        source_summary = f"fwgraph emul env {env_label}"
    fwname = args.firmware or _firmware_name(args.job_id)
    out = _req("POST", AX_BASE + "/api/assets", token=jwt,
               body={"task_id": 0, "assets": assets})
    registered = [r for r in out.get("results", []) if r.get("id")]
    errors = out.get("errors") or []
    asset_ids = [r["id"] for r in registered]
    print(f"assets: {len(asset_ids)} registered, {len(errors)} errors")
    for e in errors:
        print("  asset error:", e)
    task = _req("POST", AX_BASE + "/api/tasks", token=jwt, body={
        "name": f"fwgraph {fwname} 模拟设备渗透",
        "description": f"固件 {fwname}（job {args.job_id}）qemu 模拟设备黑盒验证，"
                       f"环境 {env_label}",
        "goal": GOAL_TMPL.format(fwname=fwname, job_id=args.job_id,
                                 env_id=env_label, host=ATTACK_HOST),
        "coverage_enabled": True,
    })
    tid = task.get("id")
    if not tid:
        sys.exit(f"task creation failed: {json.dumps(task, ensure_ascii=False)[:300]}")
    if asset_ids:
        _req("POST", AX_BASE + f"/api/tasks/{tid}/assets", token=jwt,
             body={"asset_ids": asset_ids, "source_summary": source_summary})
    print(f"task {tid} created, {len(asset_ids)} assets attached, "
          f"status={task.get('status')}")
    print(f"UI: {AX_BASE}/  API: GET {AX_BASE}/api/tasks/{tid}")


_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium",
            "low": "low"}


def cmd_pull(args):
    jwt = artex_login()
    out = _req("GET",
               AX_BASE + f"/api/exploration/findings?task={args.task_id}"
                         f"&limit=200&page=1", token=jwt)
    items = out.get("items", out) if isinstance(out, dict) else out
    if not isinstance(items, list):
        items = []
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    outdir = args.out or f"data/artex/task-{args.task_id}"
    os.makedirs(outdir, exist_ok=True)
    drafts, lines = [], [f"# ARTEX 任务 {args.task_id} findings 回流 {stamp}", ""]
    for f in items:
        sev = _SEV_MAP.get(str(f.get("severity") or "low").lower(), "low")
        summary = str(f.get("summary") or f.get("name") or "").strip()
        report = str(f.get("report") or "").strip()
        evidence = f.get("evidence")
        poc = ""
        if isinstance(evidence, str):
            try:
                poc = str((json.loads(evidence) or {}).get("poc") or "")
            except ValueError:
                pass
        elif isinstance(evidence, dict):
            poc = str(evidence.get("poc") or "")
        draft = {
            "job_id": None,  # fill before promoting
            "title": str(f.get("name") or "ARTEX finding"),
            "severity": sev,
            "vuln_class": str(f.get("vulnclass") or "unknown"),
            "cwe": "CWE-000",  # placeholder: assign before promoting
            "binary_md5": None, "binary_path": "",
            "reachability": "static",
            "summary": summary,
            "evidence": [f"ARTEX task {args.task_id} finding "
                         f"{f.get('finding_id') or f.get('id')}",
                         *( [poc] if poc else [] ), report][:8],
            "confidence": 0.5,
            "call_chain": "ARTEX黑盒证据（人工补 → 链）",
            "poc": poc or "(fill: reproduce request from ARTEX traffic)",
            "_artex": {"task": args.task_id,
                       "finding_id": f.get("finding_id") or f.get("id"),
                       "status": f.get("status"), "ts": f.get("ts")},
        }
        drafts.append(draft)
        lines += [f"## {draft['title']} [{sev}] ({f.get('status')})",
                  summary[:300], f"POC: {poc[:200]}", ""]
    (Path := __import__("pathlib").Path)
    Path(outdir, f"findings-draft-{stamp}.json").write_text(
        json.dumps(drafts, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(outdir, f"summary-{stamp}.md").write_text(
        "\n".join(lines), encoding="utf-8")
    print(f"{len(drafts)} findings → {outdir}/findings-draft-{stamp}.json")
    print(f"summary → {outdir}/summary-{stamp}.md")
    print("promote: fill job_id/binary_md5/cwe/call_chain then "
          "POST /vulnagent/findings (Bearer FWGRAPH_TOKEN)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("env-assets"); p1.add_argument("job_id")
    p1.add_argument("--env", default=""); p1.set_defaults(func=cmd_env_assets)
    p2 = sub.add_parser("create-task"); p2.add_argument("job_id")
    p2.add_argument("--env", default=""); p2.add_argument("--firmware", default="")
    p2.add_argument("--asset", action="append", default=[],
                    metavar="HOST:PORT[:NAME]",
                    help="manual asset (repeatable); skips emul env lookup")
    p2.set_defaults(func=cmd_create_task)
    p3 = sub.add_parser("pull"); p3.add_argument("task_id")
    p3.add_argument("--out", default=""); p3.set_defaults(func=cmd_pull)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
