"""Canonical event schema — the single shape everything in the system speaks.

Ingested sources are normalized into ``CanonicalEvent`` rows; the pipeline then
enriches each row with ``category``, ``anomaly_score``, ``correlation_group_id``,
``priority`` and an ``explain`` blob that powers the "why?" drill-down.
"""
from __future__ import annotations

import enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Category(str, enum.Enum):
    INFORMATIONAL = "informational"          # информационные события
    NEEDS_ANALYSIS = "needs_analysis"        # требующие доп. анализа
    ANOMALOUS = "anomalous"                  # аномальные
    REPEATING = "repeating"                  # повторяющиеся
    CORRELATED = "correlated"                # потенциально взаимосвязанные


class Priority(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordered kill-chain stages used for correlation ordering + priority weighting.
KILL_CHAIN_STAGES = [
    "recon",
    "delivery",
    "exploitation",
    "installation",
    "command_control",
    "lateral_movement",
    "exfiltration",
]
KILL_CHAIN_INDEX = {name: i for i, name in enumerate(KILL_CHAIN_STAGES)}


class CanonicalEvent(BaseModel):
    """One normalized security event. `id` is assigned by the DB on insert."""

    id: Optional[int] = None
    event_id: str                                   # source-provided or generated uuid
    content_hash: Optional[str] = None              # for de-duplication
    ingest_time: Optional[str] = None               # ISO-8601, when we received it
    event_time: str                                 # ISO-8601, when it happened
    source_name: str = "unknown"
    source_format: str = "unknown"                  # csv | json | syslog | ...
    batch: Optional[str] = None                     # ingestion batch id

    # --- normalized security fields ---------------------------------------
    raw_type: Optional[str] = None                  # e.g. auth_failure, port_scan
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    status: Optional[str] = None                    # success | failure | ...
    raw_severity: int = 0                           # 0..100 as reported by source
    kill_chain_stage: Optional[str] = None
    message: Optional[str] = None
    tags: list[str] = Field(default_factory=list)   # unmapped extras land here

    # --- computed by the pipeline -----------------------------------------
    category: Optional[str] = None
    anomaly_score: float = 0.0                       # 0..1 normalized
    is_anomaly: bool = False
    correlation_group_id: Optional[int] = None
    priority: Optional[str] = None
    priority_score: float = 0.0                      # 0..1
    priority_reason: Optional[str] = None
    explain: dict[str, Any] = Field(default_factory=dict)


# Column order for the SQLite table / CSV export. Keep in sync with db.py.
EVENT_COLUMNS = [
    "id", "event_id", "content_hash", "ingest_time", "event_time",
    "source_name", "source_format", "batch",
    "raw_type", "host", "src_ip", "dst_ip", "user", "action", "protocol",
    "port", "status", "raw_severity", "kill_chain_stage", "message", "tags",
    "category", "anomaly_score", "is_anomaly", "correlation_group_id",
    "priority", "priority_score", "priority_reason", "explain",
]
