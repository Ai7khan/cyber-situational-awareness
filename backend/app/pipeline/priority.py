"""Priority scoring (assignment §7.6): transparent weighted formula.

priority_score = w1*severity + w2*anomaly + w3*correlation + w4*repetition + w5*kill_chain
(each term normalized to 0..1; weights live in config and are editable in the UI).
The score maps to low / medium / high / critical via configurable cutoffs, and
every event keeps a human-readable breakdown so the rating is fully explainable.
"""
from __future__ import annotations

from typing import Any

from ..schema import KILL_CHAIN_INDEX, Priority


def _kill_chain_norm(stage: str | None) -> float:
    if not stage or stage not in KILL_CHAIN_INDEX:
        return 0.0
    return KILL_CHAIN_INDEX[stage] / (len(KILL_CHAIN_INDEX) - 1)


def score(rows: list[dict[str, Any]], cfg: dict[str, Any], groups: dict[int, dict]) -> None:
    w = cfg["weights"]
    cut = cfg["priority_cutoffs"]

    for r in rows:
        sev = float(r.get("raw_severity") or 0) / 100.0
        anom = float(r.get("anomaly_score") or 0.0)
        gid = r.get("correlation_group_id")
        gsize = groups.get(gid, {}).get("size", 0) if gid else 0
        corr = min(gsize / 8.0, 1.0)              # saturates at 8 members
        rc = int(r.get("_repeat_count", 1))
        rep = min((rc - 1) / 10.0, 1.0)           # saturates at 11 repeats
        kc = _kill_chain_norm(r.get("kill_chain_stage"))

        terms = {
            "raw_severity": w["raw_severity"] * sev,
            "anomaly": w["anomaly"] * anom,
            "correlation": w["correlation"] * corr,
            "repetition": w["repetition"] * rep,
            "kill_chain": w["kill_chain"] * kc,
        }
        total = round(sum(terms.values()), 4)

        if total >= cut["critical"]:
            label = Priority.CRITICAL.value
        elif total >= cut["high"]:
            label = Priority.HIGH.value
        elif total >= cut["medium"]:
            label = Priority.MEDIUM.value
        else:
            label = Priority.LOW.value

        # dominant contributors, for the "why this priority?" explanation
        ranked = sorted(terms.items(), key=lambda kv: kv[1], reverse=True)
        top = [f"{name} (+{val:.2f})" for name, val in ranked if val > 0.01][:3]
        reason = "; ".join(top) if top else "no significant risk factors"

        r["priority"] = label
        r["priority_score"] = total
        r["priority_reason"] = reason
        r.setdefault("explain", {})["priority"] = {
            "score": total, "label": label,
            "components": {k: round(v, 4) for k, v in terms.items()},
            "inputs": {"severity": round(sev, 3), "anomaly": round(anom, 3),
                       "correlation_group_size": gsize, "repeat_count": rc,
                       "kill_chain_stage": r.get("kill_chain_stage")},
            "weights": w, "cutoffs": cut,
        }
