"""Tests for AS-3 route classification and CBM ROUTE edge injection."""

import json
import sqlite3

from pipeline.routes import heuristics, runner

MD5 = "a" * 32
PROJECT = "fwgraph_routejob"

NODES = """
CREATE TABLE nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    label TEXT NOT NULL,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    file_path TEXT DEFAULT '',
    properties TEXT DEFAULT '{}',
    UNIQUE(project, qualified_name)
)
"""
EDGES = """
CREATE TABLE edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    source_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    properties TEXT DEFAULT '{}'
)
"""


def test_route_classifier_is_conservative():
    assert heuristics.classify_route("POST /goform/login") == {
        "route": "/goform/login", "method": "POST", "confidence": 0.98,
        "evidence": "http_method_path"}
    assert heuristics.classify_route("/api/v1/status")["confidence"] == 0.96
    assert heuristics.classify_route("goform/reboot")["confidence"] == 0.84
    assert heuristics.classify_route("/etc/passwd") is None
    assert heuristics.classify_route("plain text") is None


def _database(tmp_path):
    path = tmp_path / "graph.db"
    db = sqlite3.connect(path)
    db.execute(NODES)
    db.execute(EDGES)
    function_path = f"busybox_{MD5[:8]}/0x1000_sub_1000.c"
    db.execute(
        "INSERT INTO nodes(project,label,name,qualified_name,file_path) "
        "VALUES (?,'Function','sub_1000','f1',?)",
        (PROJECT, function_path))
    db.execute(
        "INSERT INTO nodes(project,label,name,qualified_name,properties) "
        "VALUES (?,'Route','external','external-route','{}')", (PROJECT,))
    db.commit()
    db.close()
    return path


def _symbols():
    return {"binaries": {MD5: {
        "path": "bin/busybox", "arch": "mips", "functions": [{
            "addr": "0x1000", "name": "sub_1000", "decompile_ok": True,
        }]}}}


def _route(handler="0x1000"):
    return {"binary_md5": MD5, "binary_path": "bin/busybox",
            "arch": "mips", "route": "/goform/login", "method": None,
            "confidence": 0.96, "evidence": "absolute_url_path",
            "entry_addr": "0x2000", "string_addr": "0x3000",
            "handler_addr": handler, "handler_name": "sub_1000",
            "pointer_order": "string_handler", "segment": ".data",
            "thumb_bit": False, "table_neighbors": 1}


def test_route_injection_is_idempotent_and_preserves_external_nodes(tmp_path):
    database = _database(tmp_path)
    first = runner.inject_routes(
        database, _symbols(), PROJECT, [_route(), _route("0x9999")])
    second = runner.inject_routes(
        database, _symbols(), PROJECT, [_route(), _route("0x9999")])
    assert first == second
    assert first["inserted"] == 1 and first["unmatched"] == 1
    db = sqlite3.connect(database)
    managed = db.execute(
        "SELECT name,properties FROM nodes WHERE label='Route' AND "
        "json_extract(properties,'$.producer')=?", (runner.PRODUCER,)).fetchall()
    external = db.execute(
        "SELECT count(*) FROM nodes WHERE qualified_name='external-route'").fetchone()[0]
    edges = db.execute(
        "SELECT type,properties FROM edges WHERE type='ROUTE'").fetchall()
    db.close()
    assert len(managed) == 1 and managed[0][0] == "/goform/login"
    assert json.loads(managed[0][1])["handler_addr"] == "0x1000"
    assert external == 1
    assert len(edges) == 1
    assert json.loads(edges[0][1])["producer"] == runner.PRODUCER
