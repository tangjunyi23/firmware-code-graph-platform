"""IDA 9.1 headless scanner for adjacent route-string/function pointers.

Run through pipeline.routes.runner. The output path is supplied in the
FWGRAPH_ROUTE_OUTPUT environment variable. This script only reads the IDB.
"""

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_nalt
import ida_pro
import ida_segment

FWGRAPH_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if FWGRAPH_ROOT not in sys.path:
    sys.path.insert(0, FWGRAPH_ROOT)

from pipeline.routes.heuristics import classify_route

PRODUCER = "fwgraph.routes.ida.v1"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _read_pointer(ea, pointer_size):
    if pointer_size == 8:
        return ida_bytes.get_qword(ea)
    return ida_bytes.get_dword(ea)


def _string_at(ea):
    if not ea or ida_segment.getseg(ea) is None:
        return None
    raw = ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C)
    if not raw:
        return None
    text = bytes(raw).decode("utf-8", errors="replace")
    if "\ufffd" in text:
        return None
    return text


def _handler_at(ea):
    procname = (ida_ida.inf_get_procname() or "").lower()
    normalized = ea & ~1 if procname.startswith("arm") else ea
    func = ida_funcs.get_func(normalized)
    if func is None or func.start_ea != normalized:
        return None
    return normalized, bool(normalized != ea)


def _candidate(entry_ea, string_ea, handler_ea, order, segment_name):
    text = _string_at(string_ea)
    classified = classify_route(text)
    handler = _handler_at(handler_ea)
    if classified is None or handler is None:
        return None
    normalized, thumb_bit = handler
    return {
        **classified,
        "entry_addr": hex(entry_ea),
        "string_addr": hex(string_ea),
        "handler_addr": hex(normalized),
        "handler_name": ida_name.get_name(normalized) or "",
        "pointer_order": order,
        "segment": segment_name,
        "thumb_bit": thumb_bit,
    }


def scan():
    pointer_size = 8 if ida_ida.inf_is_64bit() else 4
    routes = {}
    segments_scanned = 0
    slots_scanned = 0
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if segment is None or segment.type in (
                ida_segment.SEG_CODE, ida_segment.SEG_BSS,
                ida_segment.SEG_XTRN, ida_segment.SEG_NULL):
            continue
        segments_scanned += 1
        segment_name = ida_segment.get_segm_name(segment)
        start = (segment.start_ea + pointer_size - 1) & ~(pointer_size - 1)
        stop = segment.end_ea - 2 * pointer_size
        for ea in range(start, stop + 1, pointer_size):
            slots_scanned += 1
            first = _read_pointer(ea, pointer_size)
            second = _read_pointer(ea + pointer_size, pointer_size)
            item = _candidate(
                ea, first, second, "string_handler", segment_name)
            if item is not None:
                key = (item["entry_addr"], item["string_addr"],
                       item["handler_addr"], item["route"])
                routes[key] = item
    ordered = sorted(routes.values(), key=lambda item: (
        int(item["entry_addr"], 16), item["route"], item["handler_addr"]))
    for index, item in enumerate(ordered):
        current = int(item["entry_addr"], 16)
        neighbors = sum(
            other["segment"] == item["segment"]
            and other["pointer_order"] == item["pointer_order"]
            and 0 < abs(int(other["entry_addr"], 16) - current)
            <= pointer_size * 8
            for other in ordered)
        item["table_neighbors"] = neighbors
        if neighbors:
            item["confidence"] = min(0.99, item["confidence"] + 0.02)
    return {
        "producer": PRODUCER,
        "generated_at": _now(),
        "meta": {
            "input": ida_nalt.get_input_file_path(),
            "processor": ida_ida.inf_get_procname(),
            "bits": 64 if ida_ida.inf_is_64bit() else 32,
            "endianness": "be" if ida_ida.inf_is_be() else "le",
            "pointer_size": pointer_size,
            "segments_scanned": segments_scanned,
            "slots_scanned": slots_scanned,
        },
        "routes": ordered,
    }


def main():
    started = time.time()
    output = os.environ.get("FWGRAPH_ROUTE_OUTPUT")
    if not output:
        ida_pro.qexit(2)
        return
    payload = {"producer": PRODUCER, "status": "error", "routes": []}
    exit_code = 0
    try:
        ida_auto.auto_wait()
        payload = scan()
        payload["status"] = "ok"
    except Exception as exc:  # noqa: BLE001 - persist diagnostics before exit
        exit_code = 1
        payload["error"] = f"{type(exc).__name__}: {exc}"
        payload["traceback"] = traceback.format_exc()
    payload["elapsed_seconds"] = round(time.time() - started, 2)
    temporary = output + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(temporary, output)
    os.sync()
    ida_pro.qexit(exit_code)


main()
