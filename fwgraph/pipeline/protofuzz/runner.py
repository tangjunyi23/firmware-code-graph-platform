"""协议 fuzz 运行器：执行用例、故障判定与复现、落盘与报告（M-ICS-1）。

数据布局（data/protofuzz/<run_id>/）：
  run.json     运行配置+状态+统计（进行中每 case 原子刷新）
  cases.jsonl  每条用例的执行记录
  faults.jsonl 确认的故障（含监视器证据与复现计数）
  STOP         存在即停止

故障模型（纯软件近似博智的电源托管+循环分段）：
  传输层异常（refused/reset/timeout）→ 立即跑监视器；
  监视器确认不可达 → confirmed 故障，复播同一用例 3 次统计复现率；
  监视器仍可达 → suspected（应用层异常或单连接拒绝），记录后继续。
"""

import json
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import engine, monitors, protocols

_RUN_RE = "pf-"
_FUZZABLE_OUTCOMES = {"refused", "reset", "timeout"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def run_dir(data_dir: Path, run_id: str) -> Path:
    return data_dir / "protofuzz" / run_id


def get_run(data_dir: Path, run_id: str, tail: int = 30):
    """运行详情 + 最近 tail 条用例 + 全部故障。KeyError = 不存在。"""
    rdir = run_dir(data_dir, run_id)
    meta = _read_json(rdir / "run.json")
    if meta is None:
        raise KeyError(run_id)
    cases = []
    cases_file = rdir / "cases.jsonl"
    if cases_file.is_file():
        lines = cases_file.read_text(encoding="utf-8").splitlines()
        for line in lines[-tail:]:
            try:
                cases.append(json.loads(line))
            except ValueError:
                continue
    faults = []
    faults_file = rdir / "faults.jsonl"
    if faults_file.is_file():
        for line in faults_file.read_text(encoding="utf-8").splitlines():
            try:
                faults.append(json.loads(line))
            except ValueError:
                continue
    return {**meta, "recent_cases": cases, "faults": faults}


def list_runs(data_dir: Path) -> list:
    root = data_dir / "protofuzz"
    out = []
    if root.is_dir():
        for rdir in root.iterdir():
            meta = _read_json(rdir / "run.json")
            if meta:
                out.append(meta)
    out.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return out


def stop_run(data_dir: Path, run_id: str) -> None:
    (run_dir(data_dir, run_id) / "STOP").write_text("stop", encoding="utf-8")


def _send_case(host, port, transport, payload, timeout) -> dict:
    """发送单条用例，返回 {outcome, resp_len, resp_hex, elapsed_ms}。"""
    started = time.monotonic()
    try:
        if transport == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(payload, (host, port))
                try:
                    data, _ = sock.recvfrom(4096)
                except socket.timeout:
                    return {"outcome": "timeout",
                            "elapsed_ms": _ms(started)}
                return {"outcome": "response" if data else "empty",
                        "resp_len": len(data),
                        "resp_hex": data[:32].hex(), "elapsed_ms": _ms(started)}
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            try:
                data = sock.recv(4096)
            except socket.timeout:
                return {"outcome": "timeout", "elapsed_ms": _ms(started)}
            return {"outcome": "response" if data else "empty",
                    "resp_len": len(data),
                    "resp_hex": data[:32].hex(), "elapsed_ms": _ms(started)}
    except ConnectionRefusedError:
        return {"outcome": "refused", "elapsed_ms": _ms(started)}
    except ConnectionResetError:
        return {"outcome": "reset", "elapsed_ms": _ms(started)}
    except socket.timeout:
        return {"outcome": "timeout", "elapsed_ms": _ms(started)}
    except OSError as exc:
        return {"outcome": f"error:{type(exc).__name__}",
                "elapsed_ms": _ms(started)}


def _ms(started) -> int:
    return int((time.monotonic() - started) * 1000)


def start_run(data_dir: Path, *, target_host: str, target_port: int,
              transport: str, protocol: str, owner: str,
              job_id: str | None = None, name: str = "",
              case_limit: int = 300, delay_ms: int = 50,
              timeout_ms: int = 1500, monitor_names=("tcp_probe",),
              stop_on_fault: bool = False) -> dict:
    """创建运行目录并异步执行；返回初始 run.json 内容。"""
    proto = protocols.get_protocol(protocol)
    if proto is None:
        raise KeyError(f"unknown protocol {protocol}")
    run_id = f"pf-{uuid.uuid4().hex[:8]}"
    rdir = run_dir(data_dir, run_id)
    rdir.mkdir(parents=True, exist_ok=True)
    meta = {
        "run_id": run_id, "name": name or f"{proto['label']} @ {target_host}",
        "engine": "protofuzz", "status": "running",
        "target_host": target_host, "target_port": target_port,
        "transport": transport, "protocol": protocol,
        "protocol_label": proto["label"],
        "job_id": job_id, "owner": owner,
        "case_limit": case_limit, "delay_ms": delay_ms,
        "timeout_ms": timeout_ms, "monitors": list(monitor_names),
        "created_at": _now(), "updated_at": _now(),
        "cases_total": None, "cases_done": 0, "fault_count": 0,
        "outcome_counts": {}, "error": None,
    }
    _atomic_write(rdir / "run.json", json.dumps(meta, ensure_ascii=False, indent=2))

    thread = threading.Thread(
        target=_run_loop, args=(data_dir, run_id, proto), daemon=True)
    thread.start()
    return meta


def _run_loop(data_dir: Path, run_id: str, proto: dict) -> None:
    rdir = run_dir(data_dir, run_id)
    meta = _read_json(rdir / "run.json")
    cases_file = rdir / "cases.jsonl"
    faults_file = rdir / "faults.jsonl"
    try:
        seed = int(run_id[-8:], 16)
        cases = engine.generate_cases(proto, seed=seed,
                                      max_cases=int(meta["case_limit"]))
        meta["cases_total"] = len(cases)
        timeout = meta["timeout_ms"] / 1000.0
        delay = meta["delay_ms"] / 1000.0
        seed_payload = bytes(proto["templates"][0]["packet"])
        outcomes = meta["outcome_counts"]

        for case in cases:
            if (rdir / "STOP").exists():
                meta["status"] = "stopped"
                break
            result = _send_case(meta["target_host"], meta["target_port"],
                                meta["transport"], case["payload"], timeout)
            outcome = result["outcome"]
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
            record = {"seq": case["seq"], "template": case["template"],
                      "field": case["field"], "strategy": case["strategy"],
                      "variant": case["variant"], "outcome": outcome,
                      "resp_len": result.get("resp_len", 0),
                      "elapsed_ms": result["elapsed_ms"]}
            with cases_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

            if outcome in _FUZZABLE_OUTCOMES and case["strategy"] != "baseline":
                fault = _handle_fault(meta, case, result, seed_payload)
                if fault:
                    with faults_file.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(fault, ensure_ascii=False) + "\n")
                    meta["fault_count"] += 1
                    if meta.get("stop_on_fault") and fault["confirmed"]:
                        meta["status"] = "stopped"
                        meta["error"] = "confirmed fault, stop_on_fault"
                        _save_meta(rdir, meta)
                        break

            meta["cases_done"] += 1
            meta["updated_at"] = _now()
            _save_meta(rdir, meta)
            if delay:
                time.sleep(delay)
        else:
            meta["status"] = "done"
        if meta["status"] == "running":
            meta["status"] = "done"
    except Exception as exc:  # noqa: BLE001 - 失败如实落盘
        meta["status"] = "error"
        meta["error"] = f"{type(exc).__name__}: {exc}"
    meta["updated_at"] = _now()
    _save_meta(rdir, meta)


def _save_meta(rdir: Path, meta: dict) -> None:
    _atomic_write(rdir / "run.json",
                  json.dumps(meta, ensure_ascii=False, indent=2))


def _handle_fault(meta: dict, case: dict, result: dict,
                  seed_payload: bytes) -> dict | None:
    """传输层异常后的监视器确认 + 复播复现统计。"""
    checks = monitors.run_monitors(
        meta.get("monitors") or ["tcp_probe"], meta["target_host"],
        meta["target_port"], meta["transport"], seed_payload)
    confirmed = any(c.get("alive") is False for c in checks)
    fault = {
        "seq": case["seq"], "template": case["template"],
        "template_desc": case.get("template_desc", ""),
        "field": case["field"], "strategy": case["strategy"],
        "variant": case["variant"], "outcome": result["outcome"],
        "payload_hex": case["payload"][:64].hex(),
        "payload_len": len(case["payload"]),
        "confirmed": confirmed, "monitors": checks,
        "reproduced": 0, "replay_total": 0,
        "recovered": None, "at": _now(),
    }
    if not confirmed:
        return fault  # suspected：设备仍可达，记录即可
    # 复播 3 次统计复现率（博智循环分段故障定位的软件近似）
    for _ in range(3):
        time.sleep(1.0)
        replay = _send_case(meta["target_host"], meta["target_port"],
                            meta["transport"], case["payload"], 1.5)
        fault["replay_total"] += 1
        if replay["outcome"] in _FUZZABLE_OUTCOMES:
            fault["reproduced"] += 1
    recovery = monitors.tcp_probe(meta["target_host"], meta["target_port"])
    fault["recovered"] = recovery["alive"]
    return fault


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------

def build_report(data_dir: Path, run_id: str) -> Path:
    """生成 markdown 报告到 data/reports/pf-<id>.md，返回路径。"""
    detail = get_run(data_dir, run_id, tail=0)
    lines = []
    a = lines.append
    a(f"# 协议模糊测试报告 · {detail['run_id']}")
    a("")
    a("## 测试目标")
    a("")
    a("| 项 | 值 |")
    a("| --- | --- |")
    a(f"| 名称 | {detail.get('name') or ''} |")
    a(f"| 目标 | {detail['target_host']}:{detail['target_port']} ({detail['transport'].upper()}) |")
    a(f"| 协议 | {detail['protocol_label']} |")
    if detail.get("job_id"):
        a(f"| 关联固件任务 | {detail['job_id']} |")
    a(f"| 执行时间 | {detail.get('created_at', '')} |")
    a(f"| 状态 | {detail.get('status', '')} |")
    a("")
    a("## 执行统计")
    a("")
    a(f"- 用例：{detail.get('cases_done', 0)}/{detail.get('cases_total') or 0}")
    a(f"- 故障：{detail.get('fault_count', 0)} 个")
    counts = detail.get("outcome_counts") or {}
    if counts:
        a("")
        a("| 结果类型 | 次数 |")
        a("| --- | --- |")
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
            a(f"| {k} | {v} |")
    a("")
    a("## 故障明细")
    a("")
    faults = detail.get("faults") or []
    if not faults:
        a("未发现故障。")
    for f in faults:
        level = "确认（监视器判定设备不可达）" if f.get("confirmed") else "疑似（设备仍可达）"
        a(f"### 用例 #{f['seq']} · {f['template']} · {f['field']}")
        a("")
        a(f"- 模板说明：{f.get('template_desc') or '-'}")
        a(f"- 变异：{f['strategy']} / {f['variant']}，报文 {f.get('payload_len', 0)} 字节")
        a(f"- 触发结果：{f['outcome']}，级别：{level}")
        a(f"- 复播复现：{f.get('reproduced', 0)}/{f.get('replay_total', 0)}")
        if f.get("recovered") is not None:
            a(f"- 复播后服务恢复：{'是' if f['recovered'] else '否'}")
        a(f"- 载荷前缀：`{f.get('payload_hex', '')}`")
        checks = [f"{c['monitor']}={'存活' if c.get('alive') else '不可达' if c.get('alive') is False else '未知'}"
                  for c in f.get("monitors", [])]
        if checks:
            a(f"- 监视器：{'; '.join(checks)}")
        a("")
    a("## 结论与建议")
    a("")
    confirmed = [f for f in faults if f.get("confirmed")]
    if confirmed:
        a(f"共确认 {len(confirmed)} 个可致设备服务不可达的畸形报文，"
          "建议将故障用例载荷与固件任务关联分析（协议处理函数定位），"
          "并在修复后回归复测。")
    elif faults:
        a("存在疑似应用层异常用例，建议结合固件攻击面分析人工复核。")
    else:
        a("本轮测试未发现导致设备异常的报文；可扩大用例上限或更换模板复测。")
    a("")
    a("> 本报告由 FWGraph 协议模糊测试模块自动生成；"
      "测试行为已获得授权确认。")
    reports_dir = data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{run_id}.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
