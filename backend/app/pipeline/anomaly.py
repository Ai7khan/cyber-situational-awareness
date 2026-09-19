"""Intelligent analysis (assignment §7.5): ML anomaly detection with reasons.

Combines three complementary, *explainable* signals:
  1. IsolationForest over engineered behavioural features (unsupervised outliers)
  2. a burst-rate rule (brute-force / scan spikes)
  3. Markov sequence-rarity per source (rare event *ordering* -> hidden sequences)

Every event receives a normalized anomaly_score in [0,1], an is_anomaly flag,
and a list of human-readable factors so the UI can answer "why is this anomalous?".
Results are recommendations, never automatic decisions.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from . import features as F

_OFF_HOURS = set(range(0, 7)) | {22, 23}   # 22:00–06:59 considered off-hours


def _hour(iso: str) -> int:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).hour
    except Exception:
        return 12


def detect(rows: list[dict[str, Any]], cfg: dict[str, Any]) -> None:
    """Annotate rows in place with anomaly_score / is_anomaly / explain['anomaly']."""
    if not rows:
        return
    F.add_epochs(rows)
    window = float(cfg["burst_window_sec"])

    src_rate = F.rate_within(rows, "src_ip", window)
    fanout = F.unique_dst_within(rows, window)
    type_freq = Counter(r.get("raw_type") for r in rows)
    n = len(rows)

    # --- build feature matrix ---------------------------------------------
    feats, meta = [], []
    for r in rows:
        rid = r["id"]
        rate = src_rate.get(rid, 1)
        fan = fanout.get(rid, 1)
        rarity = -math.log((type_freq[r.get("raw_type")] + 1) / (n + 1))
        is_fail = 1.0 if (r.get("status") or "").lower() in ("failure", "fail", "denied", "deny") else 0.0
        off = 1.0 if _hour(r["event_time"]) in _OFF_HOURS else 0.0
        sev = float(r.get("raw_severity") or 0)
        row_feat = [sev, rate, fan, rarity, is_fail, off, float(r.get("port") or 0)]
        feats.append(row_feat)
        meta.append({"rate": rate, "fan": fan, "rarity": rarity, "fail": is_fail,
                     "off": off, "sev": sev})

    X = np.array(feats, dtype=float)
    contamination = min(max(float(cfg["anomaly_contamination"]), 0.005), 0.5)

    # IsolationForest needs enough samples to model "normal". On tiny datasets it
    # overfits and invents anomalies, so below a floor we rely on rules/sequence only.
    MIN_SAMPLES = 30
    if n >= MIN_SAMPLES:
        iso = IsolationForest(contamination=contamination, random_state=42, n_estimators=200)
        iso.fit(X)
        raw = iso.decision_function(X)      # higher = more normal
        lo, hi = float(raw.min()), float(raw.max())
        inv = (hi - raw) / (hi - lo) if hi > lo else np.zeros_like(raw)
        method = "IsolationForest + burst/scan rules"
    else:
        inv = np.zeros(n)
        method = "rule-based (dataset too small for ML model)"

    # population stats for explainability (z-scores)
    means = X.mean(axis=0)
    stds = X.std(axis=0) + 1e-9
    feat_names = ["severity", "src_rate", "dst_fanout", "type_rarity", "failed", "off_hours", "port"]

    threshold = float(cfg["anomaly_threshold"])
    repeat_min = int(cfg["repeat_min_count"])
    for i, r in enumerate(rows):
        score = float(inv[i])
        m = meta[i]

        # rule boosts (transparent, catch textbook attacks IF might rank mid)
        boosts = []
        if m["rate"] >= 15 and m["fail"]:
            score = max(score, 0.9); boosts.append(f"burst of {m['rate']} failed attempts in {int(window)}s")
        elif m["rate"] >= 25:
            score = max(score, 0.8); boosts.append(f"{m['rate']} events from one source in {int(window)}s")
        if m["fan"] >= 20:
            score = max(score, 0.85); boosts.append(f"contacted {m['fan']} distinct targets (scan-like)")

        # top statistical factors
        z = (X[i] - means) / stds
        order = np.argsort(z)[::-1]
        factors = list(boosts)
        for j in order[:3]:
            if z[j] > 1.2:
                factors.append(f"{feat_names[j]} unusually high ({X[i][j]:.0f}, z={z[j]:.1f})")

        # dampen known recurring low-severity patterns (not a spiky attack)
        rc = int(r.get("_repeat_count", 1))
        if rc >= 2 * repeat_min and m["sev"] < 60 and not boosts:
            score = min(score, 0.35)
            factors = [f"known recurring pattern ({rc}x) — treated as baseline"]

        r["anomaly_score"] = round(score, 4)
        r["is_anomaly"] = bool(score >= threshold)
        r.setdefault("explain", {})["anomaly"] = {
            "score": round(score, 4),
            "method": method,
            "factors": factors or ["within normal behavioural range"],
        }

    _sequence_rarity(rows, cfg)


def _sequence_rarity(rows: list[dict[str, Any]], cfg: dict[str, Any]) -> None:
    """Markov transition rarity per source -> flags abnormal event *ordering*.

    Learns P(next_type | prev_type) from the whole dataset, then flags rare
    transitions (hidden multi-step sequences) and folds them into the score.
    """
    thresh = float(cfg["sequence_rarity_threshold"])
    trans = defaultdict(Counter)
    seqs = defaultdict(list)
    for r in sorted(rows, key=lambda r: r["_t"]):
        key = r.get("src_ip") or r.get("host") or "global"
        seqs[key].append(r)
    for key, seq in seqs.items():
        for a, b in zip(seq, seq[1:]):
            trans[a.get("raw_type")][b.get("raw_type")] += 1

    for key, seq in seqs.items():
        for a, b in zip(seq, seq[1:]):
            total = sum(trans[a.get("raw_type")].values())
            p = trans[a.get("raw_type")][b.get("raw_type")] / total if total else 1.0
            if p <= thresh and total >= 3:
                b["anomaly_score"] = round(max(b.get("anomaly_score", 0.0), 0.75), 4)
                b["is_anomaly"] = True
                exp = b.setdefault("explain", {}).setdefault("anomaly", {"factors": []})
                exp.setdefault("factors", []).append(
                    f"rare transition {a.get('raw_type')} → {b.get('raw_type')} (p={p:.2%})")
                exp["score"] = b["anomaly_score"]
