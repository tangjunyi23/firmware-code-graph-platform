"""SQLite name registry + naming_spec.yaml validator (M3).

One registry per job: data/pseudocode/<job>/name_registry.db. It is the
durable state that makes AI renaming resumable: every LLM suggestion is
recorded (accepted / rejected / error), and only `done` rows (applied to the
IDB and re-exported) are skipped on re-run. `accepted` rows survive a crash
between the LLM phase and the IDA phase and are re-applied idempotently.

Arbitration: UNIQUE(md5, addr); a new suggestion for the same address only
replaces an accepted/done row when its confidence is strictly higher
(low confidence yields to high confidence).
"""

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from pipeline.decompile.annotate import load_spec

# first segments that are acceptable besides the closed domain list:
# the spec's recommended verbs plus a few generic nouns
GENERIC_FIRSTS = {
    "main", "entry", "start", "app", "core", "task", "worker", "thread",
    "loop", "run", "exec", "cmd", "command", "file", "dir", "path", "buf",
    "str", "mem", "get", "set", "init", "free", "open", "close", "read",
    "write", "send", "recv", "parse", "build", "check", "verify", "handle",
    "process", "load", "save", "alloc", "copy", "cmp", "encode", "decode",
    "stop",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS name_registry (
    job_id     TEXT NOT NULL,
    md5        TEXT NOT NULL,
    addr       TEXT NOT NULL,
    old_name   TEXT,
    new_name   TEXT,
    confidence REAL,
    reason     TEXT,
    source     TEXT,
    status     TEXT NOT NULL,
    ts         TEXT,
    libc_equiv TEXT,
    domain     TEXT,
    UNIQUE(md5, addr)
)
"""

RESOLVED = ("accepted", "done")
TERMINAL = ("accepted", "done", "rejected")  # never re-sent to the LLM


def _now():
    return datetime.now(timezone.utc).isoformat()


class SpecValidator:
    """Validate and conflict-resolve candidate names per naming_spec.yaml."""

    def __init__(self, spec=None):
        spec = spec or load_spec()
        fmt = spec.get("format", {})
        self.pattern = re.compile(
            fmt.get("pattern", r"^[a-z][a-z0-9]*(_[a-z0-9]+){1,4}$"))
        self.max_length = int(fmt.get("max_length", 40))
        self.banned = [re.compile(p)
                       for p in spec.get("banned", {}).get("patterns", [])]
        self.domains = set(spec.get("domains", []))
        arb = spec.get("arbitration", {})
        self.libc_suffix = arb.get("libc_conflict_suffix", "_impl")
        self.confidence_min = float(arb.get("confidence_min", 0.6))

    def check(self, name):
        """(ok, reason) for a raw candidate name."""
        if not name:
            return False, "empty"
        if len(name) > self.max_length:
            return False, "too_long"
        if not self.pattern.match(name):
            return False, "pattern_mismatch"
        for banned in self.banned:
            if banned.search(name):
                return False, f"banned:{banned.pattern}"
        first = name.split("_", 1)[0]
        if first not in self.domains and first not in GENERIC_FIRSTS:
            return False, "domain_not_in_vocab"
        return True, "ok"

    def resolve(self, name, *, known_names=(), used=()):
        """Conflict-resolve a spec-valid name for one binary.

        known_names: libc/import/existing real symbol names of the binary
                     (collision -> append the libc suffix, e.g. _impl).
        used:        every name already taken in the binary, including rule
                     names and previously accepted AI names (-> _2/_3/...).

        Returns (final_name|None, reason).
        """
        ok, reason = self.check(name)
        if not ok:
            return None, reason
        if name in known_names:
            name += self.libc_suffix
            ok, reason = self.check(name)
            if not ok:
                return None, f"libc_suffix_{reason}"
        base, n = name, 2
        while name in used:
            name = f"{base}_{n}"
            n += 1
            if not self.check(name)[0]:
                return None, "uniqueness_exhausted"
        return name, "ok"


class Registry:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self):
        """Add columns introduced after the first deployed schema."""
        cols = {r["name"] for r in
                self.conn.execute("PRAGMA table_info(name_registry)")}
        if "libc_equiv" not in cols:
            self.conn.execute(
                "ALTER TABLE name_registry ADD COLUMN libc_equiv TEXT")
        if "domain" not in cols:
            self.conn.execute(
                "ALTER TABLE name_registry ADD COLUMN domain TEXT")

    def close(self):
        self.conn.close()

    def lookup(self, md5, addr):
        row = self.conn.execute(
            "SELECT * FROM name_registry WHERE md5=? AND addr=?",
            (md5, addr)).fetchone()
        return dict(row) if row else None

    def is_resolved(self, md5, addr):
        """True when a usable name (accepted or done) already exists."""
        row = self.conn.execute(
            "SELECT 1 FROM name_registry WHERE md5=? AND addr=? AND "
            "status IN ('accepted','done')", (md5, addr)).fetchone()
        return row is not None

    def is_terminal(self, md5, addr):
        """True for accepted/done/rejected: the LLM is not called again.
        Only 'error' rows (transient failures) are retried on re-run."""
        row = self.conn.execute(
            "SELECT 1 FROM name_registry WHERE md5=? AND addr=? AND "
            "status IN ('accepted','done','rejected')", (md5, addr)).fetchone()
        return row is not None

    def record(self, job_id, md5, addr, old_name, new_name, confidence,
               reason, source, status, libc_equiv=None, domain=None):
        """Insert or replace one row; returns True when stored.

        An accepted/done row is only replaced by a strictly higher
        confidence suggestion.
        """
        existing = self.lookup(md5, addr)
        if existing and existing["status"] in RESOLVED \
                and status not in ("done",):
            if (existing["confidence"] or 0.0) >= (confidence or 0.0):
                return False
        self.conn.execute(
            "INSERT OR REPLACE INTO name_registry "
            "(job_id, md5, addr, old_name, new_name, confidence, reason, "
            " source, status, ts, libc_equiv, domain) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, md5, addr, old_name, new_name, confidence, reason,
             source, status, _now(), libc_equiv, domain))
        self.conn.commit()
        return True

    def mark_done(self, md5):
        self.conn.execute(
            "UPDATE name_registry SET status='done', ts=? "
            "WHERE md5=? AND status='accepted'", (_now(), md5))
        self.conn.commit()

    def pending_apply(self, md5):
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM name_registry WHERE md5=? AND "
            "status='accepted'", (md5,)).fetchone()
        return int(row["n"])

    def renames(self, md5):
        rows = self.conn.execute(
            "SELECT addr, new_name FROM name_registry WHERE md5=? AND "
            "status IN ('accepted','done')", (md5,)).fetchall()
        return {r["addr"]: r["new_name"] for r in rows if r["new_name"]}

    def taken_names(self, md5):
        rows = self.conn.execute(
            "SELECT new_name FROM name_registry WHERE md5=? AND "
            "status IN ('accepted','done')", (md5,)).fetchall()
        return {r["new_name"] for r in rows if r["new_name"]}

    def backfill_libc_equiv(self, updates):
        """Batch-set libc_equiv on rows that still lack it; rows touched are
        marked source='backfill'. updates: [(libc_equiv, md5, addr), ...].
        Returns the number of rows actually updated."""
        cur = self.conn.executemany(
            "UPDATE name_registry SET libc_equiv=?, source='backfill' "
            "WHERE md5=? AND addr=? AND (libc_equiv IS NULL OR libc_equiv='')",
            updates)
        self.conn.commit()
        return cur.rowcount

    def rows(self, status=None):
        sql = "SELECT * FROM name_registry"
        args = ()
        if status:
            sql += " WHERE status=?"
            args = (status,)
        return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def stats(self):
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS n, AVG(confidence) AS avg_conf "
            "FROM name_registry GROUP BY status").fetchall()
        out = {"accepted": 0, "done": 0, "rejected": 0, "error": 0,
               "avg_confidence_accepted": None}
        for r in rows:
            out[r["status"]] = int(r["n"])
        avg = self.conn.execute(
            "SELECT AVG(confidence) AS c FROM name_registry "
            "WHERE status IN ('accepted','done')").fetchone()["c"]
        if avg is not None:
            out["avg_confidence_accepted"] = round(float(avg), 3)
        out["total"] = sum(out[s] for s in ("accepted", "done", "rejected", "error"))
        out["libc_equiv"] = int(self.conn.execute(
            "SELECT COUNT(*) AS n FROM name_registry WHERE "
            "libc_equiv IS NOT NULL AND libc_equiv != ''").fetchone()["n"])
        out["domain"] = int(self.conn.execute(
            "SELECT COUNT(*) AS n FROM name_registry WHERE "
            "domain IS NOT NULL AND domain != ''").fetchone()["n"])
        return out

    def samples(self, n=10):
        rows = self.conn.execute(
            "SELECT md5, addr, old_name, new_name, confidence, reason, "
            "status, libc_equiv, domain "
            "FROM name_registry WHERE status IN ('accepted','done') "
            "ORDER BY confidence DESC LIMIT ?", (n,)).fetchall()
        return [dict(r) for r in rows]


def dumps_stats(db_path):
    """Convenience for the GET endpoint: stats without keeping a handle."""
    if not Path(db_path).is_file():
        return None
    reg = Registry(db_path)
    try:
        return {"stats": reg.stats(), "samples": reg.samples(10)}
    finally:
        reg.close()
