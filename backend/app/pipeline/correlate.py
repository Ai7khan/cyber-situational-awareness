"""Correlation engine (assignment §7.4): link related events into groups.

Builds an undirected graph whose edges encode *why* two events are related:
  * shared identity (src_ip / user) within a short burst window   -> sessions
  * a longer "campaign" window over notable events of one source  -> multi-stage
  * pivot edges where one event's src_ip is another's dst_ip       -> lateral move
Connected components with >= min_group members become correlation groups.
Each event stores the reasons it was linked, for explainability.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx

from . import features as F


def _candidate(r: dict[str, Any], min_sev: int) -> bool:
    return (
        (r.get("raw_severity") or 0) >= min_sev
        or (r.get("status") or "").lower() in ("failure", "fail", "denied", "deny")
        or r.get("kill_chain_stage")
        or r.get("is_anomaly")
    )


def correlate(rows: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[int, dict]:
    """Annotate rows with correlation_group_id; return per-group metadata."""
    if not rows:
        return {}
    F.add_epochs(rows)
    window = float(cfg["correlation_window_sec"])
    campaign_win = float(cfg["campaign_window_sec"])
    min_sev = int(cfg["correlation_min_severity"])
    campaign_sev = int(cfg["campaign_min_severity"])
    min_group = int(cfg["correlation_min_group"])

    cand = [r for r in rows if _candidate(r, min_sev)]
    by_id = {r["id"]: r for r in rows}
    G = nx.Graph()
    G.add_nodes_from(r["id"] for r in cand)

    def link(a, b, reason):
        if a == b:
            return
        if G.has_edge(a, b):
            G[a][b]["reasons"].add(reason)
        else:
            G.add_edge(a, b, reasons={reason})

    # 1) burst/session edges: same source IP, consecutive within a short window.
    # (source IP is the strong identity signal; linking by user alone bleeds
    #  unrelated sources together, so we do not use it here.)
    buckets = defaultdict(list)
    for r in cand:
        if r.get("src_ip"):
            buckets[r["src_ip"]].append(r)
    for val, group in buckets.items():
        group.sort(key=lambda r: r["_t"])
        for a, b in zip(group, group[1:]):
            if b["_t"] - a["_t"] <= window:
                link(a["id"], b["id"], f"src_ip={val} within {int(window)}s")

    # 2) campaign edges: notable events from one source over a long window
    camp = defaultdict(list)
    for r in cand:
        if r.get("src_ip") and _candidate(r, campaign_sev):
            camp[r["src_ip"]].append(r)
    for val, group in camp.items():
        group.sort(key=lambda r: r["_t"])
        for a, b in zip(group, group[1:]):
            if b["_t"] - a["_t"] <= campaign_win:
                stages = f" ({a.get('kill_chain_stage')}→{b.get('kill_chain_stage')})" \
                    if a.get("kill_chain_stage") and b.get("kill_chain_stage") else ""
                link(a["id"], b["id"], f"campaign src={val}{stages}")

    # 3) pivot edges: src_ip of one == dst_ip of another, close in time
    dst_index = defaultdict(list)
    for r in cand:
        if r.get("dst_ip"):
            dst_index[r["dst_ip"]].append(r)
    for r in cand:
        s = r.get("src_ip")
        if s and s in dst_index:
            for other in dst_index[s]:
                if 0 <= r["_t"] - other["_t"] <= campaign_win:
                    link(other["id"], r["id"], f"pivot via {s}")

    # assign group ids to non-trivial components
    groups: dict[int, dict] = {}
    gid = 0
    for comp in nx.connected_components(G):
        if len(comp) < min_group:
            continue
        gid += 1
        members = [by_id[i] for i in comp]
        members.sort(key=lambda r: r["_t"])
        reasons = set()
        for a, b in G.subgraph(comp).edges():
            reasons |= G[a][b]["reasons"]
        stages = [m["kill_chain_stage"] for m in members if m.get("kill_chain_stage")]
        span = members[-1]["_t"] - members[0]["_t"]
        meta = {
            "id": gid,
            "size": len(members),
            "src_ips": sorted({m["src_ip"] for m in members if m.get("src_ip")}),
            "users": sorted({m["user"] for m in members if m.get("user")}),
            "hosts": sorted({m["host"] for m in members if m.get("host")}),
            "kill_chain": _dedup_stages(stages),
            "span_sec": int(span),
            "start": members[0]["event_time"],
            "end": members[-1]["event_time"],
            "max_severity": max((m.get("raw_severity") or 0) for m in members),
            "anomalies": sum(1 for m in members if m.get("is_anomaly")),
            "reasons": sorted(reasons)[:6],
            "member_ids": [m["id"] for m in members],
        }
        groups[gid] = meta
        for m in members:
            m["correlation_group_id"] = gid
            m.setdefault("explain", {})["correlation"] = {
                "group_id": gid, "group_size": len(members),
                "reasons": meta["reasons"], "kill_chain": meta["kill_chain"],
            }
    return groups


def _dedup_stages(stages: list[str]) -> list[str]:
    out: list[str] = []
    for s in stages:
        if not out or out[-1] != s:
            out.append(s)
    return out
