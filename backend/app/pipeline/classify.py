"""Classification (assignment §7.3): assign each event a transparent category.

Categories (precedence high -> low):
  anomalous  > repeating > correlated > needs_analysis > informational

The rules are deliberately simple and inspectable so the "why" is obvious and
the thresholds can be tuned live from the UI.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ..schema import Category
from . import features as F


def classify(rows: list[dict[str, Any]], cfg: dict[str, Any]) -> None:
    if not rows:
        return
    repeat_min = int(cfg["repeat_min_count"])
    needs_sev = int(cfg["needs_analysis_severity"])

    for r in rows:
        rc = int(r.get("_repeat_count", 1))   # set by the repetition stage
        reasons = []
        if r.get("is_anomaly"):
            cat = Category.ANOMALOUS.value
            reasons.append("flagged anomalous by intelligent analysis")
        elif rc >= repeat_min:
            cat = Category.REPEATING.value
            reasons.append(f"signature repeated {rc}x within window")
        elif r.get("correlation_group_id"):
            cat = Category.CORRELATED.value
            reasons.append(f"member of correlation group #{r['correlation_group_id']}")
        elif (r.get("raw_severity") or 0) >= needs_sev or \
                (r.get("status") or "").lower() in ("failure", "fail", "denied", "deny"):
            cat = Category.NEEDS_ANALYSIS.value
            reasons.append(f"severity/outcome warrants review (sev={r.get('raw_severity')})")
        else:
            cat = Category.INFORMATIONAL.value
            reasons.append("routine event")

        r["category"] = cat
        r.setdefault("explain", {})["classification"] = {
            "category": cat, "repeat_count": rc, "reasons": reasons,
        }
