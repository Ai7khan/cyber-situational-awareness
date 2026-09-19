"""Repetition tagging (assignment §7.3 "повторяющиеся события").

Runs first so later stages can reason about how periodic an event is: anomaly
detection dampens known recurring low-severity patterns, and classification uses
the count directly.
"""
from __future__ import annotations

from typing import Any

from . import features as F


def tag(rows: list[dict[str, Any]], cfg: dict[str, Any]) -> None:
    F.add_epochs(rows)
    counts = F.repeat_counts(rows, float(cfg["repeat_window_sec"]))
    for r in rows:
        r["_repeat_count"] = counts.get(r["id"], 1)
