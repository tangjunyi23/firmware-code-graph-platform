"""Deterministic per-job Markdown report (no LLM).

generate_job_report() merges the pipeline artifacts that already exist under
data/ (manifest + checksec, input identification, attack surfaces, attack
paths, fuzz/frida dynamic runs) with the vulnagent findings into one Chinese
综合报告 at data/reports/job-<job_id>.md. Every section degrades to
（无数据） when its artifact is missing, so the report can be generated at
any pipeline stage.

Markdown constructs used (kept in sync with
orchestrator/app/report_export.py's docx converter): headings (#..####),
pipe tables, bullet/ordered lists, **bold**, plain paragraphs.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# fwgraph/pipeline/report.py -> .. = fwgraph/
FWGRAPH_ROOT = Path(__file__).resolve().parents[1]

_SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危",
              "low": "低危", "info": "提示"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_TOP_PATHS = 20
# evidence keywords that trigger the default/hardcoded-credential advice
_CRED_KEYWORDS = ("默认口令", "默认凭据", "硬编码", "弱口令",
                  "default password", "default credential", "hardcoded",
                  "cwe-798", "cwe-259", "cwe-321")


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _vulnagent_home() -> Path:
    return Path(os.getenv("VULNAGENT_HOME",
                          str(FWGRAPH_ROOT.parent / "vulnagent")))


def _cell(text) -> str:
    """Sanitize a value for a pipe-table cell."""
    return str(text if text is not None else "").replace("|", "/") \
        .replace("\n", " ").strip() or "-"


def _base(path: str) -> str:
    return (path or "").rstrip("/").rsplit("/", 1)[-1] or path or "?"


def _clip(text: str, limit: int) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= limit else text[:limit] + "…"


# Markdown structure characters that must not appear at the start of an
# AI-controlled line (heading/list/quote/table forgery).
_MD_LINESTART = ("#", "-", "+", "|", ">")


def _esc(text, in_table: bool = False) -> str:
    """Escape AI-controlled text before splicing it into the Markdown.

    Backslash and ``|`` are escaped anywhere; a leading ``#-+|>`` on any
    line gets a backslash so injected content cannot forge headings,
    lists, quotes or tables. Table cells flatten newlines to spaces;
    body text keeps line breaks (each line escaped at its start).
    """
    s = str(text if text is not None else "")
    s = s.replace("\\", "\\\\").replace("|", "\\|")
    if in_table:
        s = s.replace("\r", " ").replace("\n", " ")
    out = []
    for ln in s.split("\n"):
        stripped = ln.lstrip()
        if stripped[:1] in _MD_LINESTART:
            ln = ln[: len(ln) - len(stripped)] + "\\" + stripped
        out.append(ln)
    return "\n".join(out)


def _fclip(text, limit: int, fid: str, in_table: bool = False) -> str:
    """Escape + clip an AI-controlled finding field; marks truncation."""
    raw = str(text if text is not None else "").strip()
    truncated = len(raw) > limit
    if truncated:
        raw = raw[:limit] + "…"
    out = _esc(raw, in_table=in_table)
    if truncated:
        out += f"（截断，完整见 finding 文件 {fid}）"
    return out


def _conf(f: dict) -> float:
    """finding confidence as float (tolerates strings/None)."""
    try:
        return float(f.get("confidence"))
    except (TypeError, ValueError):
        return 0.0


def _func_label(node: dict) -> str:
    name = node.get("ai_name") or node.get("name") or "?"
    return f"{name} @ {node.get('addr', '?')}"


def _sev_rank(sev: str) -> int:
    try:
        return _SEV_ORDER.index(sev)
    except ValueError:
        return len(_SEV_ORDER)


def _sev_text(sev: str) -> str:
    return f"{_SEV_LABEL.get(sev, sev or '?')}({sev or '?'})"


# ---------------------------------------------------------------------------
# data collection helpers
# ---------------------------------------------------------------------------

def _load_surfaces(job_id: str, data_dir: Path):
    info_dir = data_dir / "surfaces" / job_id / "information"
    surfaces, auth_chains = [], []
    if info_dir.is_dir():
        for f in sorted(info_dir.glob("AS-*.json")):
            doc = _read_json(f)
            if not doc:
                continue
            (auth_chains if f.name.startswith("AS-AUTH") else surfaces)\
                .append(doc)
    return surfaces, auth_chains


def _load_fuzz_runs(job_id: str, data_dir: Path) -> list:
    runs = []
    fuzz_dir = data_dir / "fuzz" / job_id
    if fuzz_dir.is_dir():
        for f in sorted(fuzz_dir.glob("*/fuzz.json")):
            doc = _read_json(f)
            if doc:
                runs.append(doc)
    return runs


def _load_frida_runs(job_id: str, data_dir: Path) -> list:
    runs = []
    frida_dir = data_dir / "frida" / job_id
    if frida_dir.is_dir():
        for f in sorted(frida_dir.glob("*/frida.json")):
            doc = _read_json(f)
            if doc:
                runs.append(doc)
    return runs


def _collect_findings(job_id: str):
    """(findings for this job, findings with no job association)."""
    home = _vulnagent_home()
    findings_dir = home / "findings"
    related, unrelated, seen = [], [], set()
    if findings_dir.is_dir():
        for f in sorted(findings_dir.glob("F-*.json")):
            doc = _read_json(f)
            if not doc or doc.get("status") == "retracted":
                continue
            seen.add(doc.get("id"))
            (related if doc.get("job_id") == job_id else unrelated).append(doc)
    sessions_dir = home / "sessions"
    if sessions_dir.is_dir():
        for sdir in sorted(sessions_dir.iterdir()):
            if not sdir.is_dir():
                continue
            state = _read_json(sdir / "state.json") or {}
            if state.get("job_id") != job_id:
                continue
            for fid in state.get("findings") or []:
                if fid in seen:
                    continue
                doc = _read_json(findings_dir / f"{fid}.json")
                if doc and doc.get("status") != "retracted":
                    seen.add(fid)
                    related.append(doc)
    unrelated = [f for f in unrelated if not f.get("job_id")]
    related.sort(key=lambda f: (_sev_rank(f.get("severity")), -_conf(f)))
    return related, unrelated


def _md5_map(manifest) -> dict:
    out = {}
    for b in (manifest or {}).get("binaries") or []:
        if b.get("md5"):
            out[b["md5"]] = b.get("path") or ""
    return out


# ---------------------------------------------------------------------------
# report sections
# ---------------------------------------------------------------------------

def _summary_section(job_id: str, data_dir: Path, findings: list,
                     lines: list):
    job = _read_json(data_dir / "firmware" / job_id / "job.json") or {}
    firmware = job.get("firmware") or job_id
    manifest = _read_json(data_dir / "extracted" / job_id / "manifest.json")
    idoc = _read_json(data_dir / "inputs" / job_id / "identification.json")
    surfaces, auth_chains = _load_surfaces(job_id, data_dir)
    attack = _read_json(data_dir / "attack" / job_id / "attack_paths.json")
    paths = (attack or {}).get("paths") or []
    sev_count = {}
    for f in findings:
        key = f.get("severity") or "info"
        sev_count[key] = sev_count.get(key, 0) + 1
    sev_desc = "，".join(f"{_SEV_LABEL.get(k, k)} {v} 个"
                        for k, v in sorted(sev_count.items(),
                                           key=lambda kv: _sev_rank(kv[0])))
    if findings:
        # related is sorted by (severity, confidence desc) — the first
        # finding is the top risk point
        top = findings[0]
        top_title = _fclip(top.get("title") or top.get("id"), 60,
                           top.get("id"), in_table=True)
        risk = (f"最高风险点为{_SEV_LABEL.get(top.get('severity'), '?')}发现"
                f"「{top_title}」。")
    elif paths:
        best = max(paths, key=lambda p: p.get("score") or 0)
        risk = (f"最高风险点为攻击路径 "
                f"{_func_label(best.get('source') or {})} → "
                f"{_func_label(best.get('sink') or {})}"
                f"（score {best.get('score')}）。")
    else:
        risk = "未发现明显高风险点。"
    lines += [f"# {firmware} 综合安全分析报告", "",
              "## 一、执行摘要", ""]
    if not any([manifest, idoc, surfaces, paths, findings]):
        lines += ["（无数据）", ""]
        return
    lines.append(
        f"本报告针对固件 {firmware}（任务 {job_id}，状态 "
        f"{job.get('status') or '未知'}，分析时间 "
        f"{job.get('updated_at') or '（无数据）'}）。固件包含 "
        f"{len((manifest or {}).get('binaries') or [])} 个二进制，识别出 "
        f"{len((idoc or {}).get('inputs') or [])} 个公网输入、"
        f"{len(surfaces)} 个攻击面、{len(auth_chains)} 条授权链、"
        f"{len(paths)} 条攻击路径；AI 挖掘发现 {len(findings)} 个"
        f"（{sev_desc or '无'}）。{risk}")
    lines.append("")


def _manifest_section(job_id: str, data_dir: Path, lines: list):
    lines += ["## 二、固件清单统计", ""]
    manifest = _read_json(data_dir / "extracted" / job_id / "manifest.json")
    if not manifest:
        lines += ["（无数据）", ""]
        return
    stats = manifest.get("stats") or {}
    binaries = manifest.get("binaries") or []
    by_arch = stats.get("by_arch") or {}
    lines.append(f"提取文件 {stats.get('extracted_files', '?')} 个，其中"
                 f"可执行二进制 {stats.get('total_binaries', len(binaries))} "
                 f"个。")
    lines += ["", "| 架构 | 二进制数 |", "| --- | --- |"]
    for arch, count in sorted(by_arch.items()):
        lines.append(f"| {_cell(arch)} | {count} |")
    if not by_arch:
        lines.append("| （无数据） | - |")
    libs = sum(1 for b in binaries if ".so" in _base(b.get("path", "")))
    lines += ["",
              f"文件类型分布：可执行程序 {len(binaries) - libs} 个，"
              f"共享库 {libs} 个。", ""]
    checked = [b for b in binaries if b.get("checksec")]
    if checked:
        total = len(checked)

        def cnt(pred):
            return sum(1 for b in checked if pred(b["checksec"]))

        relro_full = cnt(lambda c: str(c.get("relro")).lower() == "full")
        relro_part = cnt(lambda c: str(c.get("relro")).lower() == "partial")
        canary = cnt(lambda c: bool(c.get("canary")))
        nx = cnt(lambda c: bool(c.get("nx")))
        pie = cnt(lambda c: bool(c.get("pie")))
        fort = cnt(lambda c: (c.get("fortified") or 0) > 0)
        lines += ["### 二进制加固（checksec）汇总", "",
                  f"共 {total} 个二进制参与 checksec 检测：", "",
                  "| 防护项 | 开启 | 未开启 |",
                  "| --- | --- | --- |",
                  f"| NX（堆栈不可执行） | {nx} | {total - nx} |",
                  f"| Stack Canary | {canary} | {total - canary} |",
                  f"| PIE（地址无关） | {pie} | {total - pie} |",
                  f"| RELRO（完全） | {relro_full} | {total - relro_full} |",
                  f"| RELRO（部分） | {relro_part} | "
                  f"{total - relro_part} |",
                  f"| FORTIFY_SOURCE | {fort} | {total - fort} |", ""]
        if canary and canary <= 10:
            names = "、".join(_base(b["path"]) for b in checked
                              if b["checksec"].get("canary"))
            lines.append(f"启用 Stack Canary 的二进制：{names}。")
            lines.append("")


def _inputs_section(job_id: str, data_dir: Path, lines: list):
    lines += ["## 三、外部输入识别", ""]
    doc = _read_json(data_dir / "inputs" / job_id / "identification.json")
    inputs = (doc or {}).get("inputs") or []
    meta = (doc or {}).get("metadata") or {}
    if not inputs:
        lines += ["（无数据）", ""]
        return
    lines += ["| ID | 服务 | 协议 | 地址:端口 | 输入类型 | 处理链库 |",
              "| --- | --- | --- | --- | --- | --- |"]
    for inp in inputs:
        addr = f"{inp.get('address', '?')}:{inp.get('port', '?')}"
        types = "; ".join(inp.get("input_types") or [])
        libs = []
        for hop in inp.get("processing_chain") or []:
            libs += [_base(l) for l in hop.get("libs") or []]
        lines.append(f"| {inp.get('id')} | {_cell(inp.get('service'))} "
                     f"| {_cell(inp.get('protocol'))} | {addr} "
                     f"| {_cell(types)} | {_cell(', '.join(libs))} |")
    lines.append("")
    for inp in inputs:
        chain = inp.get("dispatch_chain") or []
        if not chain:
            continue
        lines.append(f"**{inp.get('id')}（{inp.get('service')}）分发链：**")
        lines.append("")
        for hop in chain:
            route = hop.get("route")
            note = _clip(hop.get("note") or "", 120)
            target = _base(hop.get("file") or "")
            head = f"{route} → {target}" if route else target
            lines.append(f"- {head}：{note}" if note else f"- {head}")
        lines.append("")
    excluded = meta.get("excluded") or []
    unreadable = meta.get("unreadable") or []
    note = f"excluded（非公网面，{len(excluded)} 个）；unreadable（{len(unreadable)} 个）。"
    if excluded or unreadable:
        note += "明细见附录。"
    lines += [note, ""]


def _surface_one(s: dict, lines: list):
    sid = s.get("surface_id") or "?"
    entry = s.get("entry") or {}
    proto = entry.get("protocol") or "?"
    addr = f"{entry.get('address', '?')}:{entry.get('port', '?')}"
    transport = entry.get("transport") or ""
    lines += [f"### {sid}:{s.get('service', '?')}"
              f"（{proto} {addr}{'/' + transport if transport else ''}）", ""]
    lines.append(f"- 来源输入：{s.get('source_input') or '（无数据）'}；"
                 f"入口文件：{_base(entry.get('file') or '')}")
    handler = s.get("final_handler") or {}
    hlabel = handler.get("route") or handler.get("function") or "?"
    lines.append(f"- 终点 handler：{hlabel}"
                 f"（{_clip(handler.get('detail') or '', 120)}）")
    refs = s.get("auth_chain_refs") or []
    lines.append(f"- 授权链引用：{', '.join(refs) if refs else '（无）'}")
    lines.append("")
    routing = s.get("routing_path") or []
    if routing:
        lines += ["路由链（listen→accept→parse→normalize→dispatch→handler）：",
                  "", "| 阶段 | 函数 | 详情/证据 |", "| --- | --- | --- |"]
        for hop in routing:
            lines.append(f"| {_cell(hop.get('stage'))} "
                         f"| {_cell(hop.get('function'))} "
                         f"| {_cell(_clip(hop.get('detail') or '', 140))} |")
        lines.append("")
    bindings = s.get("carrier_bindings") or []
    if bindings:
        lines += ["载体绑定：", "",
                  "| 载体 | 落地变量/位置 | 证据 |", "| --- | --- | --- |"]
        for b in bindings:
            lines.append(f"| {_cell(b.get('carrier'))} "
                         f"| {_cell(_clip(b.get('destination') or '', 100))} "
                         f"| {_cell(_clip(b.get('evidence') or '', 100))} |")
        lines.append("")
    if s.get("evidence"):
        lines.append(f"证据：{_clip(s['evidence'], 300)}")
        lines.append("")


def _surfaces_section(job_id: str, data_dir: Path, lines: list):
    lines += ["## 四、攻击面详情", ""]
    surfaces, auth_chains = _load_surfaces(job_id, data_dir)
    if not surfaces and not auth_chains:
        lines += ["（无数据）", ""]
        return
    if not surfaces:
        lines += ["（无攻击面数据）", ""]
    for s in surfaces:
        _surface_one(s, lines)
    if auth_chains:
        lines += ["### 授权链（AS-AUTH）", ""]
        for a in auth_chains:
            applies = ", ".join(a.get("applies_to") or []) or "（无）"
            lines += [f"#### {a.get('surface_id')}（适用于 {applies}）", ""]
            chain = a.get("chain") or []
            if chain:
                lines += ["| 环节 | 函数 | 详情/证据 |",
                          "| --- | --- | --- |"]
                for hop in chain:
                    lines.append(
                        f"| {_cell(hop.get('stage'))} "
                        f"| {_cell(hop.get('function'))} "
                        f"| {_cell(_clip(hop.get('detail') or '', 140))} |")
                lines.append("")
            if a.get("bypass_notes"):
                lines.append(f"绕过备注：{_clip(a['bypass_notes'], 200)}")
                lines.append("")
            if a.get("evidence"):
                lines.append(f"证据：{_clip(a['evidence'], 300)}")
                lines.append("")


def _attack_section(job_id: str, data_dir: Path, lines: list):
    lines += [f"## 五、攻击路径 Top{_TOP_PATHS}", ""]
    doc = _read_json(data_dir / "attack" / job_id / "attack_paths.json")
    paths = (doc or {}).get("paths") or []
    if not paths:
        lines += ["（无数据）", ""]
        return
    md5map = _md5_map(_read_json(data_dir / "extracted" / job_id
                                 / "manifest.json"))
    top = sorted(paths, key=lambda p: p.get("score") or 0,
                 reverse=True)[:_TOP_PATHS]
    summary = (doc or {}).get("summary") or {}
    if summary:
        lines.append(f"候选路径 {summary.get('path_candidates', '?')} 条，"
                     f"source {summary.get('sources', '?')} 个，"
                     f"sink {summary.get('sinks', '?')} 个；"
                     f"以下按 score 排序取前 {len(top)} 条。")
        lines.append("")
    lines += ["| # | score | 二进制 | source | sink | 危险操作 | 路径经过函数 "
              "| 可达性 |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for i, p in enumerate(top, 1):
        sinks = ", ".join((p.get("sink") or {}).get("asink") or [])
        reach = "动态已验证" if p.get("verified_reachable") else "静态"
        chain = p.get("chain") or []
        via = " → ".join(_func_label(n) for n in chain) if len(chain) > 1 \
            else "-"
        binary = _base(md5map.get(p.get("binary_md5") or "",
                                  p.get("binary_md5") or "?"))
        lines.append(f"| {i} | {p.get('score')} | {_cell(binary)} "
                     f"| {_func_label(p.get('source') or {})} "
                     f"| {_func_label(p.get('sink') or {})} "
                     f"| {_cell(sinks)} | {_cell(_clip(via, 120))} "
                     f"| {reach} |")
    lines.append("")


def _dynamic_section(job_id: str, data_dir: Path, findings: list,
                     lines: list):
    lines += ["## 六、动态分析结果", ""]
    fuzz_runs = _load_fuzz_runs(job_id, data_dir)
    frida_runs = _load_frida_runs(job_id, data_dir)
    if not fuzz_runs and not frida_runs:
        lines += ["（无数据）", ""]
        return
    lines += ["### Fuzz 运行记录", ""]
    if fuzz_runs:
        lines += ["| 运行 ID | 目标 | 模式 | 引擎 | 状态 | execs | crashes "
                  "| hangs | 时长(s) |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        for r in fuzz_runs:
            target = _base(r.get("binary_path") or "?")
            if r.get("function"):
                target += f" @ {r['function']}"
            lines.append(f"| {r.get('run_id')} | {_cell(target)} "
                         f"| {_cell(r.get('mode'))} "
                         f"| {_cell(r.get('engine'))} "
                         f"| {_cell(r.get('status'))} "
                         f"| {r.get('execs', 0)} | {r.get('crashes', 0)} "
                         f"| {r.get('hangs', 0)} "
                         f"| {r.get('elapsed_seconds', '?')} |")
        crashes = sum(r.get("crashes") or 0 for r in fuzz_runs)
        ok = sum(1 for r in fuzz_runs if r.get("status") == "ok")
        lines += ["",
                  f"共 {len(fuzz_runs)} 次 fuzz 运行（成功 {ok} 次），"
                  f"累计 crash {crashes} 个。", ""]
        # cross-reference: a crashing run and a finding on the same binary
        # strongly corroborate each other
        by_md5, by_base = {}, {}
        for f in findings:
            if f.get("binary_md5"):
                by_md5.setdefault(f["binary_md5"], []).append(f.get("id"))
            if f.get("binary_path"):
                by_base.setdefault(_base(f["binary_path"]), []) \
                    .append(f.get("id"))
        notes = []
        for r in fuzz_runs:
            if not (r.get("crashes") or 0):
                continue
            ids = by_md5.get(r.get("binary_md5")) \
                or by_base.get(_base(r.get("binary_path") or "")) or []
            if ids:
                notes.append(
                    f"- 运行 {r.get('run_id')} 在 "
                    f"{_base(r.get('binary_path') or '?')} 上产出 "
                    f"{r.get('crashes')} 个 crash，与发现 "
                    f"{', '.join(str(i) for i in ids)} 指向同一二进制，"
                    "建议结合崩溃样本复核这些发现。")
        if notes:
            lines += notes + [""]
    else:
        lines += ["（无数据）", ""]
    lines += ["### Frida 运行记录", ""]
    if frida_runs:
        lines += ["| 运行 ID | 进程 | hook 目标 | hooked | hits | errors "
                  "| 状态 |",
                  "| --- | --- | --- | --- | --- | --- | --- |"]
        for r in frida_runs:
            targets = ", ".join(r.get("targets") or [])
            lines.append(f"| {r.get('run_id')} | {_cell(r.get('process'))} "
                         f"| {_cell(_clip(targets, 80))} "
                         f"| {r.get('hooked', 0)} | {r.get('hits', 0)} "
                         f"| {r.get('errors', 0)} "
                         f"| {_cell(r.get('status'))} |")
        lines.append("")
    else:
        lines += ["（无数据）", ""]


def format_finding_poc_and_chain(f: dict) -> list[str]:
    """Chinese call-chain + PoC block. Empty pieces degrade to an explicit 未给出."""
    fid = f.get("id") or "?"
    chain = str(f.get("call_chain") or "").strip()
    if not chain:
        src = str(f.get("source_summary") or "").strip()
        sink = str(f.get("sink_function") or "").strip()
        if src or sink:
            chain = f"{src or '入口未知'} → {sink or 'sink 未知'}"
    poc = str(f.get("poc") or f.get("exploit_sketch") or "").strip()
    out = ["**调用链**：", "",
           _esc(chain) if chain else "（未给出调用链）", "",
           "**漏洞 PoC**：", ""]
    if poc:
        out += ["```", _fclip(poc.replace("```", "'''"), 800, fid), "```", ""]
    else:
        out += ["（未给出可复现 PoC）", ""]
    return out


def _finding_block(f: dict, index: int, lines: list):
    sev = f.get("severity") or "info"
    fid = f.get("id") or "?"
    title = _esc(f.get("title") or fid, in_table=True)
    lines += [f"### 7.{index}【{_SEV_LABEL.get(sev, sev)}】{title}"
              f"（{fid}）", ""]
    meta = [f"严重级别：{_sev_text(sev)}"]
    if f.get("vuln_class"):
        meta.append(f"漏洞类型：{_esc(f['vuln_class'], in_table=True)}")
    if f.get("cwe"):
        meta.append(f"CWE：{_esc(f['cwe'], in_table=True)}")
    lines.append("- " + "；".join(meta))
    comp = _base(f.get("binary_path") or "")
    func = f.get("function_name") or ""
    addr = f.get("function_addr") or ""
    if comp or func:
        lines.append(f"- 受影响组件：{_esc(comp, in_table=True)}"
                     f"{f' @ {_esc(func, in_table=True)}' if func else ''}"
                     f"{f'（{addr}）' if addr else ''}")
    extra = []
    if f.get("engine"):
        extra.append(f"引擎：{_esc(f['engine'], in_table=True)}")
    if f.get("confidence") is not None:
        extra.append(f"置信度：{f['confidence']}")
    if f.get("reachability"):
        extra.append(f"可达性：{_esc(f['reachability'], in_table=True)}")
    if extra:
        lines.append("- " + "；".join(extra))
    lines.append("")
    if f.get("summary"):
        lines += [f"**分析过程摘要**：{_fclip(f['summary'], 600, fid)}", ""]
    evidence = f.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    if evidence:
        lines += ["**证据**：", ""]
        lines += [f"{i}. {_fclip(str(e), 300, fid)}"
                  for i, e in enumerate(evidence, 1)]
        lines.append("")
    lines += format_finding_poc_and_chain(f)
    if f.get("remediation"):
        lines += [f"**修复建议**：{_fclip(f['remediation'], 500, fid)}", ""]


def _findings_section(job_id: str, lines: list) -> list:
    lines += ["## 七、AI 挖掘发现", ""]
    related, unrelated = _collect_findings(job_id)
    if not related and not unrelated:
        lines += ["（无数据）", ""]
        return []
    if related:
        sev_count = {}
        for f in related:
            key = f.get("severity") or "info"
            sev_count[key] = sev_count.get(key, 0) + 1
        desc = "，".join(f"{_SEV_LABEL.get(k, k)} {v} 个"
                        for k, v in sorted(
                            sev_count.items(),
                            key=lambda kv: _sev_rank(kv[0])))
        lines += [f"关联本任务的发现共 {len(related)} 个（{desc}）：", ""]
        for i, f in enumerate(related, 1):
            _finding_block(f, i, lines)
    else:
        lines += ["（本任务无关联发现）", ""]
    if unrelated:
        # details live in the appendix with a warning, not in the body
        lines.append(f"另有 {len(unrelated)} 个未能关联到本任务的发现，"
                     "已移至附录，仅供参考。")
        lines.append("")
    return related


def _is_default_cred(f: dict) -> bool:
    """Evidence that a finding is about default/hardcoded credentials."""
    blob = " ".join(str(f.get(k) or "")
                    for k in ("title", "vuln_class", "cwe", "summary")).lower()
    return any(k in blob for k in _CRED_KEYWORDS)


def _tier_item(f: dict) -> str:
    item = (f"- {_fclip(f.get('title') or f.get('id'), 80, f.get('id'), in_table=True)}"
            f"（{f.get('id')}，置信度 {f.get('confidence', '?')}）")
    rem = str(f.get("remediation") or "").strip()
    if rem:
        item += f"：{_fclip(rem, 100, f.get('id'), in_table=True)}"
    return item


def _conclusion_section(job_id: str, data_dir: Path, findings: list,
                        lines: list):
    lines += ["## 八、结论与加固建议", ""]
    if findings:
        sev_count = {}
        for f in findings:
            key = f.get("severity") or "info"
            sev_count[key] = sev_count.get(key, 0) + 1
        desc = "，".join(f"{_SEV_LABEL.get(k, k)} {v} 个"
                        for k, v in sorted(
                            sev_count.items(),
                            key=lambda kv: _sev_rank(kv[0])))
        lines += [f"AI 挖掘共发现 {len(findings)} 个漏洞（{desc}），"
                  "建议按以下分档优先级修复并回归验证：", ""]
        urgent = [f for f in findings
                  if f.get("severity") in ("critical", "high")]
        planned = [f for f in findings if f.get("severity") == "medium"]
        watch = [f for f in findings
                 if f.get("severity") in ("low", "info")]
        if urgent:
            lines += [f"**立即修复（严重/高危 {len(urgent)} 个）：**", ""]
            for f in urgent:
                lines.append(_tier_item(f))
            lines.append("")
        if planned:
            lines += [f"**计划修复（中危 {len(planned)} 个）：**", ""]
            for f in planned:
                lines.append(_tier_item(f))
            lines.append("")
        if watch:
            lines += [f"**持续关注（低危/提示 {len(watch)} 个）：**", ""]
            for f in watch:
                lines.append(_tier_item(f))
            lines.append("")
    advice = []
    if any(_is_default_cred(f) for f in findings):
        advice.append("存在默认口令/硬编码凭据类发现：移除固件中的默认口令"
                      "与硬编码凭据，首次启动强制用户设置管理口令。")
    attack = _read_json(data_dir / "attack" / job_id / "attack_paths.json")
    if (attack or {}).get("paths"):
        advice.append("攻击路径分析显示外部输入可直达危险 sink，"
                      "建议在解析层与危险函数调用前统一加长度/格式校验，"
                      "并对命令执行类 sink 改用参数化接口。")
    info_dir = data_dir / "surfaces" / job_id / "information"
    if info_dir.is_dir() and any(info_dir.glob("AS-*.json")):
        advice.append("攻击面清单中的开放服务应做最小化裁剪：关闭非必要"
                      "端口与管理接口，管理面强制认证并绑定内网地址。")
    manifest = _read_json(data_dir / "extracted" / job_id / "manifest.json")
    checked = [b for b in (manifest or {}).get("binaries") or []
               if b.get("checksec")]
    if checked:
        no_canary = sum(1 for b in checked
                        if not b["checksec"].get("canary"))
        no_pie = sum(1 for b in checked if not b["checksec"].get("pie"))
        if no_canary or no_pie:
            advice.append(f"编译加固不足：{no_canary}/{len(checked)} 个二进制"
                          f"未启用 Stack Canary，{no_pie}/{len(checked)} 个"
                          "未启用 PIE；建议统一开启 NX/ASLR/Stack Canary/"
                          "RELRO 编译选项后重新构建固件。")
    if advice:
        lines += [f"{i}. {a}" for i, a in enumerate(advice, 1)]
        lines.append("")
    if not findings and not advice:
        lines += ["（无数据）", ""]


def _appendix_section(job_id: str, data_dir: Path, unrelated: list,
                      lines: list):
    model = os.getenv("LLM_MODEL") or ""
    if not model:
        settings = _read_json(Path(data_dir) / "settings.json") or {}
        model = str(settings.get("LLM_MODEL") or "")
    lines += ["## 九、附录", "",
              "- 分析工具链：EMBA（固件提取）、IDA Pro（反编译/调用图）、"
              "CBM（代码索引）、AFL++ QEMU（模糊测试）、frida（动态插桩）、"
              "dsh vulnagent（AI 漏洞挖掘）",
              f"- AI 模型：{model or '（未配置）'}",
              "- 报告生成方式：确定性规则汇总（未调用 LLM）",
              f"- 报告生成时间:{datetime.now(timezone.utc).isoformat()}",
              "- 平台：FWGraph 固件安全分析平台", ""]
    if unrelated:
        lines += ["### 未关联任务的其他发现", "",
                  "**警示：以下发现未能关联到本固件，仅供参考，"
                  "不作为本固件的分析结论。**", ""]
        for f in unrelated:
            summary = _fclip(f.get("summary") or "", 120, f.get("id"),
                             in_table=True)
            lines.append(
                f"- **{_esc(f.get('title') or f.get('id'), in_table=True)}**"
                f"（{f.get('id')}，"
                f"{_SEV_LABEL.get(f.get('severity'), '?')}）：{summary}")
        lines.append("")
    idoc = _read_json(data_dir / "inputs" / job_id / "identification.json")
    meta = (idoc or {}).get("metadata") or {}
    excluded = meta.get("excluded") or []
    unreadable = meta.get("unreadable") or []
    if excluded or unreadable:
        lines += ["### 输入识别 excluded/unreadable 明细", ""]
        for item in excluded[:50]:
            lines.append(f"- {_esc(_clip(str(item), 160))}")
        if len(excluded) > 50:
            lines.append(f"- …其余 {len(excluded) - 50} 条略")
        for item in unreadable[:50]:
            lines.append(f"- UNREADABLE: {_esc(_clip(str(item), 160))}")
        if len(unreadable) > 50:
            lines.append(f"- …其余 {len(unreadable) - 50} 条略")
        lines.append("")


def generate_job_report(job_id: str, data_dir) -> Path:
    """Write data/reports/job-<job_id>.md and return its path.

    Fully deterministic (no LLM); missing artifacts render as （无数据）.
    """
    data_dir = Path(data_dir)
    lines: list = []
    findings, unrelated = _collect_findings(job_id)
    _summary_section(job_id, data_dir, findings, lines)
    _manifest_section(job_id, data_dir, lines)
    _inputs_section(job_id, data_dir, lines)
    _surfaces_section(job_id, data_dir, lines)
    _attack_section(job_id, data_dir, lines)
    _dynamic_section(job_id, data_dir, findings, lines)
    _findings_section(job_id, lines)
    _conclusion_section(job_id, data_dir, findings, lines)
    _appendix_section(job_id, data_dir, unrelated, lines)
    out = data_dir / "reports" / f"job-{job_id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(chr(10).join(lines), encoding="utf-8")
    return out
