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


# 用户把 IDA 整包丢进这些目录即可被识别（含一层子目录，如 ida-pro-9.1/）。
IDA_DROP_DEFAULTS = ("/opt/ida-drop",)
_IDA_MARKERS = ("idat", "idat64", "libidalib.so")


def looks_like_ida(root: Path) -> bool:
    """True if root looks like an IDA install (idat or idalib present)."""
    try:
        if not root.is_dir():
            return False
        return any((root / name).is_file() for name in _IDA_MARKERS)
    except OSError:
        return False


def find_ida_install(root: Path, depth: int = 2) -> Path | None:
    """Return root or a descendant (≤ depth) that looks like IDA."""
    if looks_like_ida(root):
        return root.resolve()
    if depth <= 0:
        return None
    try:
        children = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return None
    for child in children:
        found = find_ida_install(child, depth - 1)
        if found is not None:
            return found
    return None


def ida_drop_dirs() -> list[Path]:
    """Directories the user may drop an IDA tree into."""
    out: list[Path] = []
    extra = os.getenv("IDA_DROP_DIR", "").strip()
    if extra:
        out.append(Path(extra))
    out.append(data_dir() / "ida")
    out.extend(Path(p) for p in IDA_DROP_DEFAULTS)
    # bundled image context (/opt/ida) only if it actually contains IDA
    out.append(Path("/opt/ida"))
    seen: set[str] = set()
    uniq: list[Path] = []
    for path in out:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(path)
    return uniq


def ida_dir() -> Path | None:
    """Resolved IDA install directory.

    Order: valid ``IDA_DIR`` → drop-in folders → explicit ``IDA_DIR`` even if
    empty (tests / 自定义路径) → None. ``/opt/ida`` 空占位不算有效安装。
    """
    explicit = os.getenv("IDA_DIR", "").strip()
    if explicit:
        candidate = Path(explicit)
        if looks_like_ida(candidate):
            return candidate.resolve()
    for root in ida_drop_dirs():
        found = find_ida_install(root)
        if found is not None:
            return found
    if explicit and Path(explicit) != Path("/opt/ida"):
        return Path(explicit)
    return None
