"""Orchestration hardening tests (ARTEX-inspired): idle-turn nudge,
primary breaker, settlement gate predicate.

Covers the pure/decidable layers; the _autopilot injection itself is
exercised via the constants and helpers it consumes.
"""
from __future__ import annotations

import json

import pytest

from orchestrator.app import llm_settings
from orchestrator.app.vulnagent_api import _turn_is_idling


# ---------------- idle-turn detection ----------------

def _ev(etype: str, turn: int, **data):
    base = {"type": etype, "time": 1000 + turn * 100 + _ev.seq,
            "data": {"turn": turn, **data}}
    _ev.seq += 1
    return base


_ev.seq = 0


def _assistant(turn: int, blocks):
    return _ev("assistant/message", turn, message={"role": "assistant",
                                                   "content": blocks})


def _turn_pair(turn: int, middle, kind: str = "completed"):
    start = _ev("turn/start", turn)
    end = {"type": "turn/end", "time": 1000 + turn * 100 + 99,
           "data": {"turn": turn, "reason": {"kind": kind}}}
    return [start, *middle, end]


def test_idling_turn_thinking_only_is_detected():
    events = _turn_pair(1, [_assistant(1, [{"type": "reasoning",
                                            "text": "想想想"}])])
    end = events[-1]
    assert _turn_is_idling(events, end) is True


def test_productive_turn_with_tool_call_is_not_idling():
    events = _turn_pair(1, [_assistant(1, [{"type": "reasoning",
                                            "text": "想想"}]),
                            _ev("tool/call", 1, callId="c1",
                                name="fw_search", arguments="{}")])
    assert _turn_is_idling(events, events[-1]) is False


def test_turn_with_visible_text_is_not_idling():
    events = _turn_pair(1, [_assistant(1, [
        {"type": "reasoning", "text": "想想"},
        {"type": "text", "text": "已确认攻击面，继续验证"}])])
    assert _turn_is_idling(events, events[-1]) is False


def test_events_from_other_turns_are_ignored():
    other = _turn_pair(1, [_assistant(1, [{"type": "text", "text": "旧轮产出"}])])
    mine = _turn_pair(2, [_assistant(2, [{"type": "reasoning",
                                          "text": "只有思考"}])])
    events = other + mine
    assert _turn_is_idling(events, mine[-1]) is True


# ---------------- primary breaker ----------------

@pytest.fixture()
def fresh_breaker(tmp_path, monkeypatch):
    monkeypatch.setattr(llm_settings, "_data_dir", lambda: tmp_path)
    monkeypatch.setattr(llm_settings, "_breaker", {
        "fails": 0, "trips": 0, "open_until": 0.0, "last_error": "",
        "last_fail_at": 0.0, "loaded": True})
    yield llm_settings
    (tmp_path / "llm_breaker.json").unlink(missing_ok=True)


def test_soft_failures_trip_after_threshold(fresh_breaker):
    for i in range(llm_settings.SOFT_TRIP_AFTER - 1):
        llm_settings.note_primary_failure("stream closed by peer")
        assert not llm_settings.primary_breaker_open(), f"tripped early at {i}"
    llm_settings.note_primary_failure("stream closed by peer")
    assert llm_settings.primary_breaker_open()


def test_hard_failure_trips_immediately(fresh_breaker):
    llm_settings.note_primary_failure("HTTP 401 invalid api key")
    assert llm_settings.primary_breaker_open()


def test_success_resets_breaker(fresh_breaker):
    llm_settings.note_primary_failure("HTTP 402 quota")
    assert llm_settings.primary_breaker_open()
    llm_settings.note_primary_success()
    assert not llm_settings.primary_breaker_open()
    assert fresh_breaker.breaker_status()["trips"] == 0


def test_cooldown_ladder_escalates(fresh_breaker):
    lengths = []
    import time as _t
    for _ in range(3):
        llm_settings.note_primary_failure("HTTP 402 billing")
        st = fresh_breaker.breaker_status()
        lengths.append(st["cooldown_remaining_s"])
        # simulate window expiry: half-open lets real traffic verify again
        fresh_breaker._breaker["open_until"] = _t.time() - 1
    assert lengths[0] <= 61 and 299 <= lengths[1] <= 301, lengths
    assert 1799 <= lengths[2] <= 1801, lengths


def test_breaker_state_survives_reload(fresh_breaker):
    llm_settings.note_primary_failure("HTTP 401 unauthorized")
    fresh_breaker._breaker["loaded"] = False
    fresh_breaker._breaker.update({"fails": 0, "trips": 0, "open_until": 0.0})
    llm_settings._load_breaker()
    assert llm_settings.primary_breaker_open()


def test_resolve_route_skips_primary_while_open(fresh_breaker, monkeypatch):
    calls = {"primary": 0, "fallback": 0}
    monkeypatch.setattr(llm_settings, "_vulnagent_env", lambda: {
        "LLM_BASE_URL": "https://primary.example", "LLM_API_KEY": "k",
        "LLM_MODEL": "m"})
    monkeypatch.setattr(llm_settings, "probe_primary",
                        lambda *_a, **_k: (calls.__setitem__(
                            "primary", calls["primary"] + 1) or True))
    monkeypatch.setattr(llm_settings, "probe_fallback",
                        lambda *_a, **_k: (calls.__setitem__(
                            "fallback", calls["fallback"] + 1) or True))
    monkeypatch.delenv("LLM_FAILOVER_FORCE", raising=False)
    monkeypatch.setattr(llm_settings, "load_llm_settings",
                        lambda: {"base": "https://fb.example", "key": "k2",
                                 "model": "m2", "label": "备用"})
    r0 = llm_settings.resolve_route()
    assert r0["source"] == "primary" and calls["primary"] == 1
    llm_settings.note_primary_failure("HTTP 401 invalid api key")
    r1 = llm_settings.resolve_route()
    assert r1["source"] == "fallback" and calls["primary"] == 1, (
        "breaker open must skip primary probe entirely")
