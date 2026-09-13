"""IDA drop-in directory discovery (config.ida_dir)."""

from pathlib import Path

from orchestrator.app import config


def test_explicit_ida_dir_wins_when_valid(tmp_path, monkeypatch):
    root = tmp_path / "myida"
    root.mkdir()
    (root / "idat").write_text("", encoding="utf-8")
    monkeypatch.setenv("IDA_DIR", str(root))
    monkeypatch.delenv("IDA_DROP_DIR", raising=False)
    assert config.ida_dir() == root.resolve()


def test_empty_opt_ida_placeholder_does_not_block_drop(tmp_path, monkeypatch):
    drop = tmp_path / "drop" / "ida-pro-9.1"
    drop.mkdir(parents=True)
    (drop / "libidalib.so").write_text("", encoding="utf-8")
    monkeypatch.setenv("IDA_DIR", "/opt/ida")
    monkeypatch.setenv("IDA_DROP_DIR", str(tmp_path / "drop"))
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path / "data"))
    (tmp_path / "data").mkdir()
    assert config.ida_dir() == drop.resolve()


def test_finds_ida_under_data_ida(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_DIR", raising=False)
    monkeypatch.delenv("IDA_DROP_DIR", raising=False)
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path))
    placed = tmp_path / "ida"
    placed.mkdir()
    (placed / "idat64").write_text("", encoding="utf-8")
    assert config.ida_dir() == placed.resolve()


def test_unset_when_nothing_looks_like_ida(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_DIR", raising=False)
    monkeypatch.setenv("IDA_DROP_DIR", str(tmp_path / "empty"))
    monkeypatch.setenv("FWGRAPH_DATA", str(tmp_path / "data"))
    (tmp_path / "data").mkdir()
    (tmp_path / "empty").mkdir()
    assert config.ida_dir() is None


def test_looks_like_ida_requires_marker(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    assert config.looks_like_ida(d) is False
    (d / "idat").write_text("", encoding="utf-8")
    assert config.looks_like_ida(d) is True
    assert config.find_ida_install(tmp_path) == d.resolve()
