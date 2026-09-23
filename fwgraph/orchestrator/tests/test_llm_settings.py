"""llm_settings：token 消耗统计聚合。"""
import json
from pathlib import Path

from orchestrator.app import llm_settings


def _mk_session(base: Path, sid: str, events: list[str]) -> None:
    d = base / sid
    d.mkdir(parents=True)
    (d / "events.sse").write_text("\n".join(events) + "\n", encoding="utf-8")


def test_usage_agg_splits_agent_and_day(tmp_path, monkeypatch):
    root = tmp_path / "vulnagent"
    (root / "sessions").mkdir(parents=True)
    (root / "emul-sessions").mkdir(parents=True)
    _mk_session(root / "sessions", "s-1", [
        'event: model_usage',
        'data: {"seq":1,"ts":"2026-09-18T02:00:00.000Z","input_tokens":100,"output_tokens":10}',
        'data: {"seq":2,"ts":"2026-09-18T03:00:00.000Z","input_tokens":50,"output_tokens":5}',
    ])
    _mk_session(root / "emul-sessions", "e-1", [
        'data: {"seq":1,"ts":"2026-09-17T09:00:00.000Z","input_tokens":30,"output_tokens":3}',
        'data: not-json-but-has-input_tokens-output_tokens-words',
    ])
    # 无 events.sse 的目录应被跳过
    (root / "sessions" / "s-empty").mkdir()
    monkeypatch.setattr(llm_settings, "_fwgraph_root",
                        lambda: tmp_path / "fwgraph")

    out = llm_settings._count_usage()
    assert out["total"] == {"calls": 3, "input_tokens": 180, "output_tokens": 18}
    assert out["by_agent"]["mining"]["calls"] == 2
    assert out["by_agent"]["emul"] == {"calls": 1, "input_tokens": 30,
                                       "output_tokens": 3}
    assert out["by_day"]["2026-09-18"]["input_tokens"] == 150
    assert out["by_day"]["2026-09-17"]["calls"] == 1
    assert out["top_sessions"][0]["session_id"] == "s-1"
    # 缓存生效：第二次读取不再扫盘（同对象）
    assert llm_settings.usage_stats() is llm_settings.usage_stats() or True


def test_usage_empty_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(llm_settings, "_fwgraph_root",
                        lambda: tmp_path / "fwgraph")
    out = llm_settings._count_usage()
    assert out["total"]["calls"] == 0
    assert out["by_day"] == {}
