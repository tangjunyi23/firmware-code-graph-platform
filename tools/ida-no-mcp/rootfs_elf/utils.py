from __future__ import annotations
import hashlib
import os
import re
from typing import Iterable


_INVALID_PATH_CHARS = re.compile(r"[^0-9a-zA-Z._-]+")


def sha256_file(path: str, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_rel_path(rel_path: str) -> str:
    cleaned = rel_path.replace(os.sep, "_")
    cleaned = _INVALID_PATH_CHARS.sub("_", cleaned)
    return cleaned.strip("_")


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(text)


def append_jsonl(path: str, obj: dict) -> None:
    import json

    with open(path, "a", encoding="utf-8", errors="ignore") as f:
        f.write(json.dumps(obj, ensure_ascii=False))
        f.write("\n")


def write_json(path: str, obj: dict) -> None:
    import json

    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def iter_files(root_dir: str) -> Iterable[str]:
    for base, _, files in os.walk(root_dir):
        for name in files:
            yield os.path.join(base, name)
