"""emul janitor：TTL / 磁盘水位 / 孤儿容器回收。"""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pipeline.emul import janitor, store


def _mk_env(data_dir, env_id, status="stopped", age_h=1.0,
            disk=100, workspace=True):
    env = {
        "env_id": env_id, "job_id": "j1", "session_id": "s1",
        "workspace": "", "arch": "mips", "src_rootfs": "/x",
        "disk_quota": 0, "status": status, "services": [
            {"name": "svc", "container": f"fwgraph-emul-c-{env_id}", "status": "ok",
             "guest_port": 1, "host_port": 2}],
        "iterations": 0, "notes": [],
        "created_at": "2026-01-01T00:00:00+00:00",
        "disk_bytes": disk,
    }
    ws = Path(data_dir) / "ws" / env_id
    if workspace:
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "rootfs").mkdir(exist_ok=True)
        (ws / "rootfs" / "bin").write_text("x")
        env["workspace"] = str(ws)
    # save_env 会原地把 updated_at 覆写为当下：先记目标时间，落盘后回写
    aged = (datetime.now(timezone.utc)
            - timedelta(hours=age_h)).isoformat()
    store.save_env(data_dir, env)
    path = store.envs_dir(data_dir) / f"{env_id}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["updated_at"] = aged
    path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    env["updated_at"] = aged
    return env


def test_ttl_purge(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    _mk_env(data, "emul-old", status="stopped", age_h=30)     # 超 24h TTL
    _mk_env(data, "emul-fresh", status="stopped", age_h=1)    # 未过期，保留
    _mk_env(data, "emul-ready", status="ready", age_h=48)     # 活环境不 TTL 清
    monkeypatch.setattr(janitor, "_rm_container", lambda c: True)
    monkeypatch.setattr(janitor, "_orphans", lambda d, e: [])

    stats = janitor.reap_once(data)
    assert stats["envs_purged"] == ["emul-old"]
    # workspace 被删、记录置 purged、其余不动
    assert not (Path(data) / "ws" / "emul-old" / "rootfs" / "bin").exists()
    envs = {e["env_id"]: e for e in store.list_envs(data)}
    assert envs["emul-old"]["status"] == "purged"
    assert envs["emul-old"]["disk_bytes"] == 0
    assert envs["emul-fresh"]["status"] == "stopped"
    assert envs["emul-ready"]["status"] == "ready"

    # 幂等：再跑一遍无新增
    stats2 = janitor.reap_once(data)
    assert stats2["envs_purged"] == []


def test_high_water_purge_oldest_first(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    # 配额压到 1GB、水位 0.5：总量 500MB 超水位，最老的两个 stopped
    monkeypatch.setattr(janitor, "GLOBAL_QUOTA_GB", 1.0)
    monkeypatch.setattr(janitor, "HIGH_WATER", 0.5)
    monkeypatch.setattr(janitor, "_rm_container", lambda c: True)
    monkeypatch.setattr(janitor, "_orphans", lambda d, e: [])
    _mk_env(data, "emul-a", status="stopped", age_h=10, disk=300 * 1024**2)
    _mk_env(data, "emul-b", status="stopped", age_h=2, disk=200 * 1024**2)
    _mk_env(data, "emul-live", status="ready", age_h=1, disk=100 * 1024**2)

    stats = janitor.reap_once(data)
    # 清最老的 e-a 后总量 300MB ≤ 500MB 水位线，e-b 保留
    assert stats["envs_purged"] == ["emul-a"]
    envs = {e["env_id"]: e for e in store.list_envs(data)}
    assert envs["emul-b"]["status"] == "stopped"
    assert envs["emul-live"]["status"] == "ready"


def test_purge_marks_containers_and_services(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    _mk_env(data, "emul-1", status="failed", age_h=100)
    removed = []
    monkeypatch.setattr(janitor, "_rm_container",
                        lambda c: removed.append(c) or True)
    monkeypatch.setattr(janitor, "_orphans", lambda d, e: [])
    janitor.reap_once(data)
    assert removed == ["fwgraph-emul-c-emul-1"]
    env = store.list_envs(data)[0]
    assert env["services"][0]["status"] == "purged"
    assert any("自动清理" in n.get("text", "") for n in env["notes"])


def test_runner_rejects_purged(tmp_path):
    # purged 环境不可 boot/reset（引导至重建）
    from pipeline.emul import runner
    env = {"env_id": "emul-x", "status": "purged", "services": [],
           "workspace": "", "job_id": "j"}
    try:
        runner.reset_env(tmp_path, env)
        raised = False
    except runner.EmulError as exc:
        raised = "自动清理" in str(exc)
    assert raised
