from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class RootfsAnalyzeOptions:
    out_dir: str
    workers: int = 1
    resume: bool = True
    force: bool = False
    only_failed: bool = False
    timeout: int = 0
    retry: int = 0
    only_exec: bool = False
    include_so: bool = True
    exclude: Optional[str] = None
    skip_memory: bool = False
    no_decompile_funcs: bool = False
    no_function_index: bool = False
    max_bytes: Optional[int] = None
    progress: bool = False
    progress_every: int = 1000
    checksec_dump: bool = False
    run_ida: bool = False
    ida_log: bool = False


@dataclass(frozen=True)
class ElfInfo:
    path: str
    rel_path: str
    size: int
    sha256: str
    arch: str
    bits: int
    endian: str
    elf_type: str


@dataclass(frozen=True)
class ChecksecInfo:
    raw: Dict[str, Any]
    normalized: Dict[str, Any]
