"""Quality fixes in pipeline.report: markdown escaping, unrelated-findings
appendix, evidence-triggered conclusions, fuzz cross-references,
excluded/unreadable details moved to the appendix."""

import json

import pytest

from pipeline import report


def _mk_finding(fid, job_id="job1", **kw):
    base = {"id": fid, "job_id": job_id, "engine": "dsh",
            "title": f"title-{fid}", "severity": "medium",
            "confidence": "0.5",
            "binary_path": "rootfs/bin/httpd", "binary_md5": "a" * 32}
    base.update(kw)
    return base


@pytest.fixture
def vuln_home(tmp_path, monkeypatch):
    home = tmp_path / "vulnagent"
    (home / "findings").mkdir(parents=True)
    (home / "sessions").mkdir(parents=True)
    monkeypatch.setenv("VULNAGENT_HOME", str(home))
    return home


def _write_finding(home, doc):
    (home / "findings" / f"{doc['id']}.json").write_text(
        json.dumps(doc, ensure_ascii=False), encoding="utf-8")


def _gen(job_id, data_dir):
    out = report.generate_job_report(job_id, data_dir)
    return out.read_text(encoding="utf-8")


def _section(md, heading, next_heading):
    return md.split(heading, 1)[1].split(next_heading, 1)[0]


# ---------------------------------------------------------------------------
# markdown 转义
# ---------------------------------------------------------------------------

def test_esc_line_start_pipe_backslash():
    assert report._esc("## forged") == "\\## forged"
    assert report._esc("a|b") == "a\\|b"
    assert report._esc("a\\b") == "a\\\\b"
    assert report._esc("line1\n# head\n- item\n> q") == \
        "line1\n\\# head\n\\- item\n\\> q"
    # table context flattens newlines instead
    assert report._esc("a\n## b", in_table=True) == "a ## b"
    assert report._esc(None) == ""


def test_finding_fields_escaped(vuln_home, tmp_path):
    evil = _mk_finding(
        "F-evil-0001",
        title="x\n\n## 伪造章节",
        summary="sum | pipe \\ backslash",
        evidence=["ev1\n\n## 伪造证据章节", "plain | cell"])
    _write_finding(vuln_home, evil)
    md = _gen("job1", tmp_path / "data")
    # no forged heading lines anywhere
    assert "\n## 伪造章节" not in md
    assert "\n## 伪造证据章节" not in md
    # multi-line evidence keeps the line but escapes its start
    assert "\\## 伪造证据章节" in md
    assert "sum \\| pipe \\\\ backslash" in md


def test_truncation_marked_with_finding_id(vuln_home, tmp_path):
    f = _mk_finding("F-long-0001", summary="A" * 700,
                    evidence=["B" * 400])
    _write_finding(vuln_home, f)
    md = _gen("job1", tmp_path / "data")
    assert md.count("（截断，完整见 finding 文件 F-long-0001）") >= 2


# ---------------------------------------------------------------------------
# 未关联发现 → 附录
# ---------------------------------------------------------------------------

def test_unrelated_findings_moved_to_appendix(vuln_home, tmp_path):
    _write_finding(vuln_home, _mk_finding("F-rel-00001", job_id="job1"))
    _write_finding(vuln_home, _mk_finding("F-unr-00001", job_id="",
                                          title="孤立发现XYZ"))
    md = _gen("job1", tmp_path / "data")
    sec7 = _section(md, "## 七、", "## 八、")
    assert "孤立发现XYZ" not in sec7            # 正文不再出现
    assert "未能关联到本任务" in sec7            # 仅保留指针
    appendix = md.split("## 九、", 1)[1]
    assert "孤立发现XYZ" in appendix
    assert "以下发现未能关联到本固件，仅供参考" in appendix


# ---------------------------------------------------------------------------
# 结论证据触发
# ---------------------------------------------------------------------------

def test_conclusion_no_unconditional_template(vuln_home, tmp_path):
    md = _gen("job1", tmp_path / "data")
    assert "通用加固" not in md
    sec8 = _section(md, "## 八、", "## 九、")
    assert "签名校验" not in sec8               # 无证据不硬凑
    assert "（无数据）" in sec8


def test_conclusion_password_advice_needs_evidence(vuln_home, tmp_path):
    _write_finding(vuln_home, _mk_finding(
        "F-cred-0001", title="httpd 默认管理员口令",
        vuln_class="Use of Default Credentials", cwe="CWE-798",
        remediation="首次启动强制改密"))
    md = _gen("job1", tmp_path / "data")
    sec8 = _section(md, "## 八、", "## 九、")
    assert "默认口令" in sec8
    assert "首次启动强制改密" in sec8            # 分档清单带 remediation
    # 没有凭据类发现时不出该建议
    md2 = _gen("job2", tmp_path / "data")
    sec8b = _section(md2, "## 八、", "## 九、")
    assert "移除固件中的默认口令" not in sec8b


def test_conclusion_confidence_second_sort(vuln_home, tmp_path):
    _write_finding(vuln_home, _mk_finding(
        "F-med-low01", title="中危低置信AAA", confidence="0.3"))
    _write_finding(vuln_home, _mk_finding(
        "F-med-high1", title="中危高置信BBB", confidence="0.9"))
    _write_finding(vuln_home, _mk_finding(
        "F-high-0001", title="高危低置信CCC", severity="high",
        confidence="0.1"))
    md = _gen("job1", tmp_path / "data")
    sec8 = _section(md, "## 八、", "## 九、")
    assert sec8.index("中危高置信BBB") < sec8.index("中危低置信AAA")
    # 执行摘要最高风险点按 (severity, confidence) 选：高危优先
    sec1 = _section(md, "## 一、", "## 二、")
    assert "高危低置信CCC" in sec1


def test_checksec_advice_only_with_gaps(vuln_home, tmp_path):
    data_dir = tmp_path / "data"
    ext = data_dir / "extracted" / "job1"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps({
        "binaries": [{"path": "bin/a", "md5": "a" * 32,
                      "checksec": {"canary": True, "pie": True,
                                   "nx": True, "relro": "full"}}]}),
        encoding="utf-8")
    md = _gen("job1", data_dir)
    assert "编译加固不足" not in md              # 无缺口则无编译加固建议


# ---------------------------------------------------------------------------
# 动态分析章节关联
# ---------------------------------------------------------------------------

def test_dynamic_cross_reference_on_crashes(vuln_home, tmp_path):
    data_dir = tmp_path / "data"
    fz = data_dir / "fuzz" / "job1" / "fz-1"
    fz.mkdir(parents=True)
    (fz / "fuzz.json").write_text(json.dumps({
        "run_id": "fz-1", "job_id": "job1", "binary_path": "rootfs/bin/httpd",
        "binary_md5": "a" * 32, "mode": "binary", "engine": "afl-qemu",
        "status": "ok", "execs": 100, "crashes": 3, "hangs": 0,
        "elapsed_seconds": 5}), encoding="utf-8")
    fz2 = data_dir / "fuzz" / "job1" / "fz-2"
    fz2.mkdir(parents=True)
    (fz2 / "fuzz.json").write_text(json.dumps({
        "run_id": "fz-2", "job_id": "job1", "binary_path": "rootfs/bin/other",
        "binary_md5": "b" * 32, "mode": "binary", "engine": "afl-qemu",
        "status": "ok", "execs": 100, "crashes": 0, "hangs": 0,
        "elapsed_seconds": 5}), encoding="utf-8")
    _write_finding(vuln_home, _mk_finding("F-crash-0001"))
    md = _gen("job1", data_dir)
    assert "指向同一二进制" in md
    assert "F-crash-0001" in md
    # fz-2 has no crashes and no matching finding -> no note for it
    note_lines = [ln for ln in md.splitlines() if "指向同一二进制" in ln]
    assert all("fz-2" not in ln for ln in note_lines)


# ---------------------------------------------------------------------------
# excluded/unreadable 明细 → 附录
# ---------------------------------------------------------------------------

def test_excluded_details_in_appendix(vuln_home, tmp_path):
    data_dir = tmp_path / "data"
    inp = data_dir / "inputs" / "job1"
    inp.mkdir(parents=True)
    (inp / "identification.json").write_text(json.dumps({
        "inputs": [{"id": "IN-001", "service": "httpd", "protocol": "tcp",
                    "address": "0.0.0.0", "port": 80}],
        "metadata": {"excluded": ["EXCLUDED: hostapd (not public)"],
                     "unreadable": ["u1"]}}), encoding="utf-8")
    md = _gen("job1", data_dir)
    sec3 = _section(md, "## 三、", "## 四、")
    assert "excluded（非公网面，1 个）" in sec3
    assert "EXCLUDED: hostapd" not in sec3      # 正文只有计数
    appendix = md.split("## 九、", 1)[1]
    assert "输入识别 excluded/unreadable 明细" in appendix
    assert "EXCLUDED: hostapd" in appendix
    assert "UNREADABLE: u1" in appendix
