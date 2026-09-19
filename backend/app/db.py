"""SQLite storage layer (stdlib only, zero external ORM).

One file DB with two tables: ``events`` (the unified event base) and ``journal``
(the audit trail). Indexes on the hot columns give us the "scalability" story.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from .config import DB_PATH
from .schema import CanonicalEvent

_lock = threading.Lock()

# JSON-encoded / boolean / numeric columns need (de)serialization on the way out.
_JSON_COLS = {"tags", "explain"}
_BOOL_COLS = {"is_anomaly"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id             TEXT,
    content_hash         TEXT,
    ingest_time          TEXT,
    event_time           TEXT,
    source_name          TEXT,
    source_format        TEXT,
    batch                TEXT,
    raw_type             TEXT,
    host                 TEXT,
    src_ip               TEXT,
    dst_ip               TEXT,
    user                 TEXT,
    action               TEXT,
    protocol             TEXT,
    port                 INTEGER,
    status               TEXT,
    raw_severity         INTEGER DEFAULT 0,
    kill_chain_stage     TEXT,
    message              TEXT,
    tags                 TEXT DEFAULT '[]',
    category             TEXT,
    anomaly_score        REAL DEFAULT 0,
    is_anomaly           INTEGER DEFAULT 0,
    correlation_group_id INTEGER,
    priority             TEXT,
    priority_score       REAL DEFAULT 0,
    priority_reason      TEXT,
    explain              TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_time     ON events(event_time);
CREATE INDEX IF NOT EXISTS idx_events_srcip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
CREATE INDEX IF NOT EXISTS idx_events_hash     ON events(content_hash);

CREATE TABLE IF NOT EXISTS journal (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT,
    actor   TEXT,
    action  TEXT,
    details TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_journal_ts ON journal(ts);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db() -> None:
    with _lock, _connect() as conn:
        conn.executescript(_SCHEMA)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for c in _JSON_COLS:
        if c in d and isinstance(d[c], str):
            try:
                d[c] = json.loads(d[c])
            except Exception:
                d[c] = [] if c == "tags" else {}
    for c in _BOOL_COLS:
        if c in d:
            d[c] = bool(d[c])
    return d


# --- writes ---------------------------------------------------------------
_INSERT_COLS = [
    "event_id", "content_hash", "ingest_time", "event_time", "source_name",
    "source_format", "batch", "raw_type", "host", "src_ip", "dst_ip", "user",
    "action", "protocol", "port", "status", "raw_severity", "kill_chain_stage",
    "message", "tags",
]


def insert_events(events: Iterable[CanonicalEvent], dedup: bool = True) -> dict[str, int]:
    """Insert normalized events, skipping duplicates by content_hash.

    Returns counts: {"inserted": n, "duplicates": m}.
    """
    inserted = duplicates = 0
    with _lock, _connect() as conn:
        seen = set()
        if dedup:
            for r in conn.execute("SELECT content_hash FROM events"):
                if r["content_hash"]:
                    seen.add(r["content_hash"])
        placeholders = ",".join("?" for _ in _INSERT_COLS)
        sql = f"INSERT INTO events ({','.join(_INSERT_COLS)}) VALUES ({placeholders})"
        for ev in events:
            if ev.ingest_time is None:
                ev.ingest_time = _now()
            if dedup and ev.content_hash and ev.content_hash in seen:
                duplicates += 1
                continue
            if ev.content_hash:
                seen.add(ev.content_hash)
            conn.execute(sql, (
                ev.event_id, ev.content_hash, ev.ingest_time, ev.event_time,
                ev.source_name, ev.source_format, ev.batch, ev.raw_type, ev.host,
                ev.src_ip, ev.dst_ip, ev.user, ev.action, ev.protocol, ev.port,
                ev.status, ev.raw_severity, ev.kill_chain_stage, ev.message,
                json.dumps(ev.tags, ensure_ascii=False),
            ))
            inserted += 1
        conn.commit()
    return {"inserted": inserted, "duplicates": duplicates}


def update_enrichment(rows: list[dict[str, Any]]) -> None:
    """Bulk-update computed columns (category/anomaly/correlation/priority)."""
    cols = [
        "category", "anomaly_score", "is_anomaly", "correlation_group_id",
        "priority", "priority_score", "priority_reason", "explain",
    ]
    with _lock, _connect() as conn:
        for r in rows:
            conn.execute(
                f"UPDATE events SET {', '.join(f'{c}=?' for c in cols)} WHERE id=?",
                (
                    r.get("category"), float(r.get("anomaly_score", 0)),
                    1 if r.get("is_anomaly") else 0, r.get("correlation_group_id"),
                    r.get("priority"), float(r.get("priority_score", 0)),
                    r.get("priority_reason"),
                    json.dumps(r.get("explain", {}), ensure_ascii=False),
                    r["id"],
                ),
            )
        conn.commit()


# --- reads ----------------------------------------------------------------
def fetch_events(
    limit: Optional[int] = None,
    offset: int = 0,
    category: Optional[str] = None,
    priority: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    correlation_group_id: Optional[int] = None,
    order_by: str = "event_time",
    order_dir: str = "ASC",
) -> list[dict[str, Any]]:
    where, params = [], []
    if category:
        where.append("category = ?"); params.append(category)
    if priority:
        where.append("priority = ?"); params.append(priority)
    if is_anomaly is not None:
        where.append("is_anomaly = ?"); params.append(1 if is_anomaly else 0)
    if correlation_group_id is not None:
        where.append("correlation_group_id = ?"); params.append(correlation_group_id)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    order_dir = "DESC" if order_dir.upper() == "DESC" else "ASC"
    if order_by not in {"event_time", "priority_score", "anomaly_score", "id", "raw_severity"}:
        order_by = "event_time"
    sql = f"SELECT * FROM events {clause} ORDER BY {order_by} {order_dir}"
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"; params += [limit, offset]
    with _connect() as conn:
        return [_row_to_dict(r) for r in conn.execute(sql, params)]


def fetch_event(event_pk: int) -> Optional[dict[str, Any]]:
    with _connect() as conn:
        r = conn.execute("SELECT * FROM events WHERE id=?", (event_pk,)).fetchone()
        return _row_to_dict(r) if r else None


def count_events() -> int:
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]


def clear_events() -> None:
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM events")
        conn.commit()


# --- journal --------------------------------------------------------------
def add_journal(actor: str, action: str, details: dict[str, Any] | None = None) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO journal (ts, actor, action, details) VALUES (?,?,?,?)",
            (_now(), actor, action, json.dumps(details or {}, ensure_ascii=False)),
        )
        conn.commit()


def fetch_journal(limit: int = 200) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM journal ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d["details"])
        except Exception:
            d["details"] = {}
        out.append(d)
    return out
