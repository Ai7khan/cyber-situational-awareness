"""Ingestion & normalization: heterogeneous sources -> CanonicalEvent.

Supports CSV, JSON (flat or nested/ECS), and RFC5424-ish syslog, plus a
best-effort key=value fallback for arbitrary logs. Field names are mapped to the
canonical schema via an alias table, unknown fields are preserved as ``tags``,
and each event gets a semantic ``content_hash`` used for de-duplication.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from ..schema import CanonicalEvent

# Canonical field  ->  possible source keys (lowercased, dot-flattened).
FIELD_ALIASES: dict[str, list[str]] = {
    "event_time": ["event_time", "timestamp", "@timestamp", "time", "ts", "datetime", "date"],
    "event_id": ["event_id", "id", "event.id", "uid", "uuid"],
    "src_ip": ["src_ip", "src", "source.ip", "source_ip", "srcip", "sourceaddress", "source"],
    "dst_ip": ["dst_ip", "dst", "destination.ip", "dest_ip", "dstip", "destinationaddress", "destination"],
    "user": ["user", "account", "username", "user.name", "user_name", "usr"],
    "action": ["action", "event.action", "act"],
    "raw_type": ["raw_type", "type", "event.type", "event_type", "signature", "alert", "eventtype"],
    "protocol": ["protocol", "proto", "network.protocol"],
    "port": ["port", "dst_port", "destination.port", "dport", "destport"],
    "status": ["status", "result", "outcome", "event.outcome"],
    "raw_severity": ["raw_severity", "severity", "severity_num", "sev", "priority_num", "score", "level"],
    "host": ["host", "hostname", "host.name", "device", "computer"],
    "kill_chain_stage": ["kill_chain_stage", "stage", "kill_chain_phase", "threat.kill_chain_phase", "phase"],
    "message": ["message", "detail", "msg", "description", "text", "summary"],
}
# reverse lookup: source key -> canonical field
_ALIAS_LOOKUP = {alias: canon for canon, aliases in FIELD_ALIASES.items() for alias in aliases}

_SEV_LABELS = {
    "info": 10, "informational": 10, "low": 25, "notice": 25, "medium": 50,
    "med": 50, "warning": 50, "warn": 50, "high": 75, "error": 75, "err": 75,
    "critical": 95, "crit": 95, "alert": 90, "emergency": 100,
}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _flatten(d: dict, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, f"{key}."))
        else:
            out[key] = v
    return out


def _coerce_severity(val: Any) -> int:
    if val is None or val == "":
        return 0
    if isinstance(val, (int, float)):
        return max(0, min(100, int(val)))
    s = str(val).strip().lower()
    if s in _SEV_LABELS:
        return _SEV_LABELS[s]
    try:
        return max(0, min(100, int(float(s))))
    except ValueError:
        return 0


def _coerce_time(val: Any) -> str:
    if not val:
        return datetime.now(timezone.utc).isoformat()
    s = str(val).strip()
    for fmt in (None,):  # try fromisoformat first
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            break
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return datetime.now(timezone.utc).isoformat()


def _content_hash(fields: dict[str, Any]) -> str:
    key = "|".join(str(fields.get(k, "")) for k in
                   ("event_time", "src_ip", "dst_ip", "user", "raw_type", "action", "port", "message"))
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def _build_event(raw: dict[str, Any], source_name: str, source_format: str,
                 batch: Optional[str]) -> CanonicalEvent:
    """Map an arbitrary flat record into a CanonicalEvent."""
    mapped: dict[str, Any] = {}
    extras: list[str] = []
    for key, value in raw.items():
        canon = _ALIAS_LOOKUP.get(str(key).lower())
        if canon and (canon not in mapped or not mapped[canon]):
            mapped[canon] = value
        elif value not in (None, "", "-"):
            extras.append(f"{key}={value}")

    fields = {
        "event_id": str(mapped.get("event_id") or uuid.uuid4()),
        "event_time": _coerce_time(mapped.get("event_time")),
        "source_name": source_name,
        "source_format": source_format,
        "batch": batch,
        "raw_type": _clean(mapped.get("raw_type")),
        "host": _clean(mapped.get("host")),
        "src_ip": _clean(mapped.get("src_ip")),
        "dst_ip": _clean(mapped.get("dst_ip")),
        "user": _clean(mapped.get("user")),
        "action": _clean(mapped.get("action")),
        "protocol": _clean(mapped.get("protocol")),
        "port": _coerce_int(mapped.get("port")),
        "status": _clean(mapped.get("status")),
        "raw_severity": _coerce_severity(mapped.get("raw_severity")),
        "kill_chain_stage": _clean(mapped.get("kill_chain_stage")),
        "message": _clean(mapped.get("message")),
        "tags": extras,
    }
    # Infer a raw_type when the source doesn't label one (e.g. auth CSV only
    # carries action=login, result=failure).
    if not fields["raw_type"]:
        act, st = fields["action"], fields["status"]
        if act and st:
            fields["raw_type"] = f"{act}_{st}".lower()
        elif act:
            fields["raw_type"] = act.lower()
        else:
            fields["raw_type"] = "generic"

    fields["content_hash"] = _content_hash(fields)
    return CanonicalEvent(**fields)


def _clean(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return None if s in ("", "-", "None", "null") else s


def _coerce_int(v: Any) -> Optional[int]:
    try:
        return int(float(v)) if v not in (None, "", "-") else None
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------
# format-specific parsers
# --------------------------------------------------------------------------
def _parse_csv(text: str, source_name, batch) -> list[CanonicalEvent]:
    reader = csv.DictReader(io.StringIO(text))
    return [_build_event(row, source_name, "csv", batch) for row in reader if any(row.values())]


def _parse_json(text: str, source_name, batch) -> list[CanonicalEvent]:
    data = json.loads(text)
    if isinstance(data, dict):
        # could be {"events":[...]} or a single record
        for key in ("events", "records", "data", "hits", "results"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = [data]
    out = []
    for rec in data:
        if isinstance(rec, dict):
            out.append(_build_event(_flatten(rec), source_name, "json", batch))
    return out


_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>\d?\s*(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>\[.*?\]|-)\s*(?P<msg>.*)$"
)
_KV_RE = re.compile(r'(\w+)="([^"]*)"')


def _parse_syslog(text: str, source_name, batch) -> list[CanonicalEvent]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _SYSLOG_RE.match(line)
        if m:
            rec: dict[str, Any] = {
                "timestamp": m.group("ts"), "host": m.group("host"),
                "message": m.group("msg"),
            }
            rec.update(dict(_KV_RE.findall(m.group("sd"))))
        else:
            # fallback: bare key=value line
            rec = dict(_KV_RE.findall(line)) or {"message": line}
        out.append(_build_event(rec, source_name, "syslog", batch))
    return out


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------
def detect_format(filename: str, text: str) -> str:
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return "csv"
    if name.endswith(".json"):
        return "json"
    if name.endswith((".log", ".syslog", ".txt")):
        return "syslog"
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return "json"
    if stripped.startswith("<") and ">" in stripped[:8]:
        return "syslog"
    if "," in stripped.splitlines()[0] if stripped else False:
        return "csv"
    return "syslog"


def parse_bytes(content: bytes, filename: str, batch: Optional[str] = None) -> list[CanonicalEvent]:
    text = content.decode("utf-8", errors="replace")
    fmt = detect_format(filename, text)
    source_name = filename or f"upload-{fmt}"
    if fmt == "csv":
        return _parse_csv(text, source_name, batch)
    if fmt == "json":
        return _parse_json(text, source_name, batch)
    return _parse_syslog(text, source_name, batch)


def parse_file(path: str, batch: Optional[str] = None) -> list[CanonicalEvent]:
    import os
    with open(path, "rb") as f:
        return parse_bytes(f.read(), os.path.basename(path), batch)
