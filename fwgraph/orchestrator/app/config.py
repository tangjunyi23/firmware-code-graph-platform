"""集中式配置层（Phase 1）：env 解析与路径推导的唯一入口。

各模块统一从这里取配置，不再各自 os.getenv(..., 写死的默认值)。
所有取值都在调用时解析（不在 import 时固化），测试可 monkeypatch env。
"""

import os
from pathlib import Path

# fwgraph/orchestrator/app/config.py -> ../../.. = fwgraph/
FWGRAPH_ROOT = Path(__file__).resolve().parents[2]


def env_str(name: str, default: str | None = None) -> str | None:
    """字符串 env；未设置时返回 default。"""
    return os.getenv(name, default)


def env_int(name: str, default: int) -> int:
    """整数 env；未设置或非法值时返回 default（同 accounts.quota_limit 语义）。"""
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    """布尔 env；"1"/"true"/"yes"（大小写不敏感）为真，未设置返回 default。"""
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes")


def data_dir() -> Path:
    """FWGRAPH_DATA -> 默认 fwgraph/data（调用时解析，测试可 monkeypatch）。"""
    return Path(os.getenv("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))


def ida_dir() -> Path | None:
    """IDA 安装目录（IDA_DIR）；未配置时返回 None，由调用方给出报错。"""
    value = os.getenv("IDA_DIR", "").strip()
    return Path(value) if value else None
