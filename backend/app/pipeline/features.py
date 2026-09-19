"""Shared feature-engineering helpers used across pipeline stages."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any


def epoch(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def add_epochs(rows: list[dict[str, Any]]) -> None:
    for r in rows:
        r["_t"] = epoch(r["event_time"])


def signature(r: dict[str, Any]) -> str:
    """Stable signature of an event's *kind*, ignoring time — used for repeats."""
    return "|".join(str(r.get(k) or "") for k in
                    ("raw_type", "src_ip", "dst_ip", "user", "action", "port"))


def repeat_counts(rows: list[dict[str, Any]], window: float) -> dict[int, int]:
    """Per event: how many times its *signature* recurred within the trailing window."""
    by_sig: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_sig[signature(r)].append(r)
    out: dict[int, int] = {}
    for group in by_sig.values():
        group.sort(key=lambda r: r["_t"])
        times = [r["_t"] for r in group]
        lo = 0
        for i, r in enumerate(group):
            while times[i] - times[lo] > window:
                lo += 1
            out[r["id"]] = i - lo + 1
    return out


def rate_within(rows: list[dict[str, Any]], key: str, window: float) -> dict[int, int]:
    """For each event id, how many events share `key`'s value within +/- window sec.

    Two-pointer sweep per bucket -> near-linear.
    """
    buckets: dict[Any, list[dict]] = defaultdict(list)
    for r in rows:
        v = r.get(key)
        if v:
            buckets[v].append(r)
    counts: dict[int, int] = {}
    for group in buckets.values():
        group.sort(key=lambda r: r["_t"])
        times = [r["_t"] for r in group]
        lo = 0
        hi = 0
        n = len(group)
        for i, r in enumerate(group):
            while times[lo] < times[i] - window:
                lo += 1
            if hi < i:
                hi = i
            while hi + 1 < n and times[hi + 1] <= times[i] + window:
                hi += 1
            counts[r["id"]] = hi - lo + 1
    return counts


def unique_dst_within(rows: list[dict[str, Any]], window: float) -> dict[int, int]:
    """Per event: number of distinct dst_ip:port pairs the same src_ip touched in-window."""
    buckets: dict[Any, list[dict]] = defaultdict(list)
    for r in rows:
        if r.get("src_ip"):
            buckets[r["src_ip"]].append(r)
    out: dict[int, int] = {}
    for group in buckets.values():
        group.sort(key=lambda r: r["_t"])
        for i, r in enumerate(group):
            seen = set()
            for other in group:
                if abs(other["_t"] - r["_t"]) <= window:
                    seen.add((other.get("dst_ip"), other.get("port")))
            out[r["id"]] = len(seen)
    return out
