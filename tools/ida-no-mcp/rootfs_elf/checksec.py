from __future__ import annotations
import json
import os
import subprocess
from typing import Dict, Any, Tuple, Optional


class ChecksecError(RuntimeError):
    def __init__(self, message: str, dump: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.dump = dump


def _resolve_checksec(tools_path: str) -> str:
    candidate = os.path.join(tools_path, "checksec")
    if os.path.isfile(candidate):
        return candidate

    nested = os.path.join(candidate, "checksec")
    if os.path.isfile(nested):
        return nested

    return "checksec"


def _normalize_checksec(raw: Dict[str, Any]) -> Dict[str, Any]:
    def _bool(value: Any) -> int:
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, str):
            v = value.lower()
            if any(x in v for x in ("no ", "disabled", "not found", "none")):
                return 0
            if any(x in v for x in ("yes", "enabled", "found", "present")):
                return 1
            return 0
        return int(bool(value))

    normalized: Dict[str, Any] = {}
    for key in ("canary", "nx", "pie"):
        if key in raw:
            normalized[key] = _bool(raw.get(key))

    relro = raw.get("relro")
    if isinstance(relro, str):
        relro_val = relro.lower()
        if "full" in relro_val:
            normalized["relro"] = "full"
        elif "partial" in relro_val:
            normalized["relro"] = "partial"
        elif "no " in relro_val or "none" in relro_val:
            normalized["relro"] = "none"

    fortified = raw.get("fortified")
    fortifyable = raw.get("fortifyable")
    if fortified is not None:
        try:
            normalized["fortified"] = int(fortified)
        except (TypeError, ValueError):
            normalized["fortified"] = 0
    if fortifyable is not None:
        try:
            normalized["fortifyable"] = int(fortifyable)
        except (TypeError, ValueError):
            normalized["fortifyable"] = 0
    return normalized


def _parse_human_checksec(text: str) -> Dict[str, Any]:
    record: Dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower == "relro":
            record["relro"] = value
        elif key_lower == "stack":
            record["canary"] = value
        elif key_lower == "nx":
            record["nx"] = value
        elif key_lower == "pie":
            record["pie"] = value
        elif key_lower == "fortify":
            # pwntools uses Enabled/Disabled here instead of counts.
            record["fortified"] = 1 if "enabled" in value.lower() else 0
            record["fortifyable"] = 1 if "enabled" in value.lower() else 0
    return record


def _native_checksec(elf_path: str) -> Optional[Dict[str, Any]]:
    """fwgraph's pure-Python checksec (works on sstripped ELFs); None when
    the fwgraph pipeline package is not importable from this checkout."""
    import sys
    fwgraph_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "fwgraph"))
    if fwgraph_root not in sys.path:
        sys.path.insert(0, fwgraph_root)
    try:
        from pipeline.extract.checksec import checksec
    except ImportError:
        return None
    try:
        return checksec(elf_path)
    except Exception:
        return None


def run_checksec(
    elf_path: str,
    tools_path: str,
    *,
    capture_output: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any], Optional[Dict[str, Any]]]:
    native = _native_checksec(elf_path)
    if native is not None:
        # native result doubles as both the raw record and the normalized
        # profile; nothing to dump since no external process ran
        return dict(native), native, None

    checksec_bin = _resolve_checksec(tools_path)
    commands = [
        [checksec_bin, "file", elf_path, "--output", "json"],
        [checksec_bin, "--file", elf_path],
        [checksec_bin, elf_path],
    ]

    last_dump = None
    for cmd in commands:
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ChecksecError(f"checksec not found: {checksec_bin}") from exc

        dump = {
            "cmd": cmd,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }
        last_dump = dump

        if completed.returncode != 0:
            continue

        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        combined = stdout or stderr
        if not combined:
            continue

        payload = None
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            extracted = None
            left = stdout.find("[")
            right = stdout.rfind("]")
            if left != -1 and right != -1 and right > left:
                extracted = stdout[left : right + 1]
            else:
                left = stdout.find("{")
                right = stdout.rfind("}")
                if left != -1 and right != -1 and right > left:
                    extracted = stdout[left : right + 1]

            if extracted is not None:
                try:
                    payload = json.loads(extracted)
                except json.JSONDecodeError:
                    payload = None

        if payload is not None:
            if not isinstance(payload, (dict, list)) or not payload:
                continue

            record = None
            if isinstance(payload, dict):
                record = payload.get(elf_path)
                if record is None and len(payload) == 1:
                    record = next(iter(payload.values()))
            elif isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict) and item.get("name") == elf_path:
                        record = item.get("checks")
                        break
                if record is None and len(payload) == 1 and isinstance(payload[0], dict):
                    record = payload[0].get("checks")

            if record is None:
                continue

            normalized = _normalize_checksec(record)
            out_dump = dump if capture_output else None
            return record, normalized, out_dump

        record = _parse_human_checksec(combined)
        if record:
            normalized = _normalize_checksec(record)
            out_dump = dump if capture_output else None
            return record, normalized, out_dump

    if last_dump is None:
        raise ChecksecError("checksec failed without output")

    if last_dump.get("returncode") == 0:
        raise ChecksecError("invalid checksec output", dump=last_dump)

    raise ChecksecError(
        (last_dump.get("stderr") or last_dump.get("stdout") or "checksec failed").strip(),
        dump=last_dump,
    )
