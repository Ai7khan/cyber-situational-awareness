"""REST API for the cyber situational-awareness prototype."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Body, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse

from .. import db
from ..config import DATA_DIR, get_config, reset_config, update_config
from ..ingestion import parse_bytes, parse_file
from ..pipeline import run_pipeline
from ..pipeline.features import epoch
from ..pipeline.run import ensure_analyzed, get_groups, get_last_run
from ..reports import build_report, situation_level

router = APIRouter(prefix="/api")

SYN_DIR = DATA_DIR / "synthetic"
DEMO_FILES = ["auth_gateway.csv", "ids_sensor.json", "host_agent.log"]


# --------------------------------------------------------------------------
# ingestion
# --------------------------------------------------------------------------
@router.post("/ingest/demo")
def ingest_demo(analyze: bool = Query(True)):
    if not SYN_DIR.exists() or not (SYN_DIR / DEMO_FILES[0]).exists():
        raise HTTPException(404, "Demo dataset not found. Run: python -m data.generate")
    db.clear_events()
    results = []
    for fn in DEMO_FILES:
        path = SYN_DIR / fn
        if path.exists():
            evs = parse_file(str(path), batch="demo")
            r = db.insert_events(evs)
            r["source"] = fn
            results.append(r)
            db.add_journal("user", "ingest_demo", {"file": fn, **r})
    summary = run_pipeline("user") if analyze else None
    return {"ingested": results, "total": db.count_events(), "analysis": summary}


@router.post("/ingest/upload")
async def ingest_upload(files: list[UploadFile] = File(...),
                        replace: bool = Query(False), analyze: bool = Query(True)):
    if replace:
        db.clear_events()
    results = []
    for f in files:
        content = await f.read()
        evs = parse_bytes(content, f.filename, batch="upload")
        r = db.insert_events(evs)
        r["source"] = f.filename
        r["format"] = evs[0].source_format if evs else "unknown"
        results.append(r)
        db.add_journal("user", "ingest_upload", {"file": f.filename, **r})
    summary = run_pipeline("user") if analyze else None
    return {"ingested": results, "total": db.count_events(), "analysis": summary}


@router.post("/analyze")
def analyze():
    if db.count_events() == 0:
        raise HTTPException(400, "No events ingested yet.")
    return run_pipeline("user")


@router.delete("/events")
def clear():
    db.clear_events()
    db.add_journal("user", "clear_events", {})
    return {"ok": True, "total": 0}


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------
@router.get("/events")
def list_events(
    limit: int = Query(100, le=1000), offset: int = 0,
    category: Optional[str] = None, priority: Optional[str] = None,
    is_anomaly: Optional[bool] = None, correlation_group_id: Optional[int] = None,
    order_by: str = "event_time", order_dir: str = "DESC",
):
    rows = db.fetch_events(limit=limit, offset=offset, category=category,
                           priority=priority, is_anomaly=is_anomaly,
                           correlation_group_id=correlation_group_id,
                           order_by=order_by, order_dir=order_dir)
    return {"total": db.count_events(), "count": len(rows), "events": rows}


@router.get("/events/{event_pk}")
def get_event(event_pk: int):
    ev = db.fetch_event(event_pk)
    if not ev:
        raise HTTPException(404, "event not found")
    return ev


# --------------------------------------------------------------------------
# dashboard stats
# --------------------------------------------------------------------------
@router.get("/stats")
def stats():
    ensure_analyzed()
    rows = db.fetch_events(order_by="event_time", order_dir="ASC")
    summary = get_last_run()
    groups = get_groups()
    level = situation_level(summary) if summary else {"code": "stable", "label": "—", "color": "#888"}

    cats = _tally(rows, "category")
    pris = _tally(rows, "priority")
    timeseries = _timeseries(rows, buckets=48)
    top = sorted(rows, key=lambda r: (r.get("priority_score") or 0), reverse=True)[:8]

    return {
        "total": len(rows),
        "anomalies": sum(1 for r in rows if r.get("is_anomaly")),
        "correlation_groups": len(groups),
        "critical": pris.get("critical", 0),
        "high": pris.get("high", 0),
        "situation": level,
        "categories": cats,
        "priorities": pris,
        "timeseries": timeseries,
        "top_events": [_slim(r) for r in top],
        "last_run": summary,
    }


@router.get("/correlations")
def correlations():
    ensure_analyzed()
    groups = get_groups()
    rows = {r["id"]: r for r in db.fetch_events()}
    out = []
    for g in sorted(groups.values(), key=lambda x: (x.get("max_severity", 0), x["size"]), reverse=True):
        members = [rows[i] for i in g["member_ids"] if i in rows]
        members.sort(key=lambda r: r["event_time"])
        nodes = [{
            "id": r["id"], "label": r["raw_type"], "time": r["event_time"],
            "src_ip": r["src_ip"], "dst_ip": r["dst_ip"], "priority": r["priority"],
            "stage": r["kill_chain_stage"], "is_anomaly": r["is_anomaly"],
            "severity": r["raw_severity"],
        } for r in members]
        # chain edges between consecutive members
        edges = [{"source": members[i]["id"], "target": members[i + 1]["id"]}
                 for i in range(len(members) - 1)]
        out.append({"meta": g, "nodes": nodes, "edges": edges})
    return {"groups": out}


@router.get("/anomalies")
def anomalies(limit: int = 50):
    rows = db.fetch_events(is_anomaly=True, order_by="anomaly_score", order_dir="DESC", limit=limit)
    return {"count": len(rows), "anomalies": rows}


# --------------------------------------------------------------------------
# journal / config / report
# --------------------------------------------------------------------------
@router.get("/journal")
def journal(limit: int = 200):
    return {"entries": db.fetch_journal(limit)}


@router.get("/config")
def config_get():
    return get_config()


@router.patch("/config")
def config_patch(patch: dict[str, Any] = Body(...), reanalyze: bool = Query(True)):
    before = get_config()
    cfg = update_config(patch)
    db.add_journal("user", "config_update", {"patch": patch})
    result = run_pipeline("user") if (reanalyze and db.count_events()) else None
    return {"config": cfg, "reanalyzed": result is not None, "analysis": result}


@router.post("/config/reset")
def config_reset(reanalyze: bool = Query(True)):
    cfg = reset_config()
    db.add_journal("user", "config_reset", {})
    result = run_pipeline("user") if (reanalyze and db.count_events()) else None
    return {"config": cfg, "analysis": result}


@router.get("/report", response_class=HTMLResponse)
def report():
    ensure_analyzed()
    rows = db.fetch_events(order_by="event_time", order_dir="ASC")
    summary = get_last_run()
    if not rows or not summary:
        raise HTTPException(400, "Nothing to report — ingest and analyze first.")
    db.add_journal("user", "report_generated", {"events": len(rows)})
    return HTMLResponse(build_report(rows, get_groups(), summary))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _tally(rows, field):
    out: dict[str, int] = {}
    for r in rows:
        v = r.get(field) or "unknown"
        out[v] = out.get(v, 0) + 1
    return out


def _timeseries(rows, buckets=48):
    if not rows:
        return []
    ts = [epoch(r["event_time"]) for r in rows]
    t0, t1 = min(ts), max(ts)
    span = max(t1 - t0, 1)
    width = span / buckets
    agg = defaultdict(lambda: {"total": 0, "anomaly": 0, "critical": 0, "high": 0})
    for r, t in zip(rows, ts):
        b = min(int((t - t0) / width), buckets - 1)
        agg[b]["total"] += 1
        if r.get("is_anomaly"):
            agg[b]["anomaly"] += 1
        if r.get("priority") == "critical":
            agg[b]["critical"] += 1
        elif r.get("priority") == "high":
            agg[b]["high"] += 1
    out = []
    for b in range(buckets):
        t = t0 + b * width
        d = agg.get(b, {"total": 0, "anomaly": 0, "critical": 0, "high": 0})
        out.append({"t": datetime.utcfromtimestamp(t).strftime("%H:%M"), **d})
    return out


def _slim(r):
    return {k: r.get(k) for k in (
        "id", "event_time", "raw_type", "src_ip", "dst_ip", "host", "user",
        "category", "priority", "priority_score", "priority_reason",
        "is_anomaly", "anomaly_score", "correlation_group_id", "kill_chain_stage")}
