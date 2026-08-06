from __future__ import annotations

import os


def get_module_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def load_local_env(path: str | None = None) -> str | None:
    env_path = path or os.path.join(get_module_dir(), ".env")
    if not os.path.isfile(env_path):
        return None

    with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue

            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]

            os.environ.setdefault(key, value)

    return env_path


def get_configured_ida_dir() -> str | None:
    """IDA install root: IDADIR wins, then IDA_DIR (fwgraph .env)."""
    env_ida = os.environ.get("IDADIR", "").strip()
    if env_ida:
        return env_ida
    env_ida = os.environ.get("IDA_DIR", "").strip()
    if env_ida:
        return env_ida
    return None


def ensure_ida_env() -> str | None:
    ida_dir = get_configured_ida_dir()
    if ida_dir:
        os.environ.setdefault("IDADIR", ida_dir)
    return ida_dir


def get_tools_path() -> str:
    return os.path.abspath(os.path.join(get_module_dir(), "..", ".."))


def get_default_out_base() -> str:
    return os.environ.get(
        "ROOTFS_ELF_OUT", os.path.join(get_module_dir(), "output"))
