"""Pipeline orchestrator: anomaly -> correlation -> classification -> priority.

Loads the unified event base, runs every analytical stage in dependency order,
persists the enrichment back to the DB, caches correlation-group metadata, and
records timing so the UI can display processing speed.
"""
from __future__ import annotations

import time
from typing import Any

from .. import db
from ..config import get_config
from . import anomaly, classify, correlate, priority, repetition

# in-memory cache of the latest correlation-group metadata (for the graph view)
_GROUPS: dict[int, dict] = {}
_LAST_RUN: dict[str, Any] = {}


def get_groups() -> dict[int, dict]:
    return _GROUPS


def get_last_run() -> dict[str, Any]:
    return _LAST_RUN


def ensure_analyzed(actor: str = "system") -> None:
    """Rebuild in-memory caches (groups / last-run) after a restart if events
    exist but nothing has been analyzed in this process yet."""
    if not _LAST_RUN and db.count_events() > 0:
        run_pipeline(actor)


def run_pipeline(actor: str = "system") -> dict[str, Any]:
    global _GROUPS, _LAST_RUN
    cfg = get_config()
    t0 = time.perf_counter()

    rows = db.fetch_events(order_by="event_time", order_dir="ASC")
    if not rows:
        _LAST_RUN = {"events": 0, "message": "no events to analyze"}
        return _LAST_RUN

    timings: dict[str, float] = {}

    def _stage(name, fn, *args):
        s = time.perf_counter()
        result = fn(*args)
        timings[name] = round((time.perf_counter() - s) * 1000, 1)
        return result

    _stage("repetition", repetition.tag, rows, cfg)
    _stage("anomaly", anomaly.detect, rows, cfg)
    groups = _stage("correlation", correlate.correlate, rows, cfg)
    _stage("classification", classify.classify, rows, cfg)
    _stage("priority", priority.score, rows, cfg, groups)

    db.update_enrichment(rows)
    _GROUPS = groups

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    summary = {
        "events": len(rows),
        "anomalies": sum(1 for r in rows if r.get("is_anomaly")),
        "correlation_groups": len(groups),
        "categories": _tally(rows, "category"),
        "priorities": _tally(rows, "priority"),
        "elapsed_ms": elapsed_ms,
        "throughput_eps": round(len(rows) / (elapsed_ms / 1000), 1) if elapsed_ms else None,
        "stage_ms": timings,
    }
    _LAST_RUN = summary
    db.add_journal(actor, "pipeline_run", summary)
    return summary


def _tally(rows: list[dict], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        v = r.get(field) or "unknown"
        out[v] = out.get(v, 0) + 1
    return out
