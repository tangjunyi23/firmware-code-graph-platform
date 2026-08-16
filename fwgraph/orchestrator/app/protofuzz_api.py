"""协议模糊测试 API（M-ICS-1/M-ICS-2）。

  GET  /protofuzz/protocols            协议模板库（前端下拉）
  POST /protofuzz                      启动运行（202；acknowledge 强制确认）
  GET  /protofuzz                      我的运行列表（owner 隔离）
  GET  /protofuzz/{run_id}             运行详情（含最近用例与故障）
  POST /protofuzz/{run_id}/stop        停止
  POST /protofuzz/{run_id}/report      生成 md 报告并注册进报告中心

安全闸：
  - acknowledge 必须为 true（对真机 fuzz 可能损坏设备）
  - 目标默认只允许私网/回环地址，公网目标需 PROTOFUZZ_ALLOW_PUBLIC=1
  - 配额 pfuser:<name> 或 job 维度，每日 PROTOFUZZ_DAILY（默认 8）
  - 全程审计（protofuzz_trigger/stop/report，detail 带目标）
"""

import ipaddress
import json
import re
import socket
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException

from pipeline import protofuzz

from . import accounts

_RUN_RE = re.compile(r"^pf-[0-9a-f]{8}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_MONITORS = {"tcp_probe", "icmp_ping", "protocol_probe"}


def _data_dir() -> Path:
    return accounts.data_dir()


def _guard_host(host: str) -> list:
    """解析目标并执行公网闸门；返回解析到的 IP 字符串列表。"""
    if not _HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="目标地址含非法字符")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(status_code=400,
                            detail=f"无法解析目标地址 {host!r}")
    ips = sorted({info[4][0] for info in infos})
    import os
    if os.getenv("PROTOFUZZ_ALLOW_PUBLIC") == "1":
        return ips
    for ip_s in ips:
        try:
            ip = ipaddress.ip_address(ip_s)
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise HTTPException(
                status_code=400,
                detail=f"目标 {ip_s} 是公网地址，默认禁止 fuzz 公网目标"
                       "（确认授权后设 PROTOFUZZ_ALLOW_PUBLIC=1 重启服务）")
    return ips


def _load_checked(run_id: str, principal: dict) -> dict:
    if not _RUN_RE.match(run_id):
        raise HTTPException(status_code=400, detail="bad run id format")
    try:
        detail = protofuzz.get_run(_data_dir(), run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="protofuzz run not found")
    if not accounts.can_access(principal, detail.get("owner")):
        raise HTTPException(status_code=404, detail="protofuzz run not found")
    return detail


def setup(app: FastAPI, require_token) -> None:
    """Register protofuzz routes (call BEFORE webui.setup)."""
    auth = [Depends(require_token)]

    @app.get("/protofuzz/protocols", dependencies=auth)
    def list_protocols():
        return {"protocols": protofuzz.protocols.list_protocols(),
                "monitors": sorted(_MONITORS)}

    @app.post("/protofuzz", status_code=202)
    def start(payload: dict = Body(...),
              principal: dict = Depends(require_token)):
        host = str(payload.get("target_host") or "").strip()
        proto_name = str(payload.get("protocol") or "")
        proto = protofuzz.protocols.get_protocol(proto_name)
        if proto is None:
            raise HTTPException(status_code=400,
                                detail=f"未知协议 {proto_name!r}（先 GET /protofuzz/protocols）")
        if payload.get("acknowledge") is not True:
            raise HTTPException(
                status_code=400,
                detail="协议模糊测试会向真实设备发送畸形报文，可能导致设备异常甚至损坏；"
                       "请确认已获得被测设备授权（acknowledge=true）")
        _guard_host(host)
        try:
            port = int(payload.get("target_port") or proto["default_port"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="端口必须是数字")
        if not 1 <= port <= 65535:
            raise HTTPException(status_code=400, detail="端口范围 1-65535")
        transport = str(payload.get("transport") or proto["transport"])
        if transport not in ("tcp", "udp"):
            raise HTTPException(status_code=400, detail="transport 仅支持 tcp/udp")
        try:
            case_limit = int(payload.get("case_limit") or 300)
            delay_ms = int(payload.get("delay_ms") or 50)
            timeout_ms = int(payload.get("timeout_ms") or 1500)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="数值参数格式错误")
        if not 1 <= case_limit <= 5000:
            raise HTTPException(status_code=400, detail="case_limit 范围 1-5000")
        if not 0 <= delay_ms <= 10000:
            raise HTTPException(status_code=400, detail="delay_ms 范围 0-10000")
        if not 100 <= timeout_ms <= 10000:
            raise HTTPException(status_code=400, detail="timeout_ms 范围 100-10000")
        monitor_names = [m for m in (payload.get("monitors") or ["tcp_probe"])
                         if m in _MONITORS][:4]
        if not monitor_names:
            monitor_names = ["tcp_probe"]
        job_id = payload.get("job_id")
        if job_id:
            from . import main as _main
            if str(job_id) not in _main._jobs:
                raise HTTPException(status_code=400, detail="关联任务不存在")
            job_id = str(job_id)
        accounts.check_quota(job_id or f"pfuser:{principal['username']}",
                             "protofuzz")
        accounts.audit(principal["username"], "protofuzz_trigger",
                       f"{host}:{port}/{transport} {proto_name}"
                       + (f" job={job_id}" if job_id else ""))
        meta = protofuzz.start_run(
            _data_dir(), target_host=host, target_port=port,
            transport=transport, protocol=proto_name,
            owner=principal["username"], job_id=job_id,
            name=str(payload.get("name") or "")[:80],
            case_limit=case_limit, delay_ms=delay_ms, timeout_ms=timeout_ms,
            monitor_names=monitor_names,
            stop_on_fault=bool(payload.get("stop_on_fault")))
        return {"run_id": meta["run_id"], "status": "running"}

    @app.get("/protofuzz", dependencies=auth)
    def list_all(principal: dict = Depends(require_token)):
        runs = [r for r in protofuzz.list_runs(_data_dir())
                if accounts.can_access(principal, r.get("owner"))]
        return {"runs": runs}

    @app.get("/protofuzz/{run_id}", dependencies=auth)
    def detail(run_id: str, principal: dict = Depends(require_token)):
        return _load_checked(run_id, principal)

    @app.post("/protofuzz/{run_id}/stop", dependencies=auth)
    def stop(run_id: str, principal: dict = Depends(require_token)):
        detail = _load_checked(run_id, principal)
        if detail.get("status") == "running":
            protofuzz.stop_run(_data_dir(), run_id)
        accounts.audit(principal["username"], "protofuzz_stop", run_id)
        return {"run_id": run_id, "status": "stopping"}

    @app.post("/protofuzz/{run_id}/report", dependencies=auth)
    def make_report(run_id: str, principal: dict = Depends(require_token)):
        _load_checked(run_id, principal)
        path = protofuzz.build_report(_data_dir(), run_id)
        accounts.audit(principal["username"], "protofuzz_report", run_id)
        return {"run_id": run_id, "report_id": path.stem,
                "size": path.stat().st_size}
