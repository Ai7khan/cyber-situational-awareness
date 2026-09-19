"""Central, editable configuration for the analysis pipeline.

Everything the assignment calls "transparent and adjustable criteria" lives here:
classification thresholds, correlation windows, and priority weights. The values
are persisted to ``config.json`` so edits made through the API survive restarts
and can be journaled.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent          # backend/
PROJECT_DIR = BASE_DIR.parent                              # repo root
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / "cyber.db"
CONFIG_PATH = BASE_DIR / "config.json"

DATA_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Default, human-readable analysis parameters. Every number here is surfaced in
# the UI so a judge can see *why* the system scored an event the way it did.
# ---------------------------------------------------------------------------
DEFAULTS: dict[str, Any] = {
    # --- classification -----------------------------------------------------
    "repeat_min_count": 15,         # same signature seen >= N times -> "repeating"
    "repeat_window_sec": 3600,      # ...within this rolling window
    "needs_analysis_severity": 50,  # raw_severity >= this -> at least "needs analysis"

    # --- correlation --------------------------------------------------------
    "correlation_window_sec": 120,   # burst/session temporal edge threshold
    "correlation_min_group": 2,      # min members to be a "correlated group"
    "correlation_min_severity": 20,  # ignore low-value chatter when correlating
    "campaign_window_sec": 1800,     # long window linking multi-stage campaigns
    "campaign_min_severity": 50,     # only "notable" events join a campaign

    # --- anomaly detection --------------------------------------------------
    "anomaly_contamination": 0.08,  # expected fraction of anomalies (IsolationForest)
    "anomaly_threshold": 0.60,      # normalized score >= this -> is_anomaly=True
    "burst_window_sec": 60,         # sliding window for rate features
    "sequence_rarity_threshold": 0.03,  # transition prob <= this -> rare sequence

    # --- priority scoring (transparent weighted sum, weights sum ~= 1) -------
    "weights": {
        "raw_severity": 0.35,
        "anomaly": 0.30,
        "correlation": 0.15,
        "repetition": 0.10,
        "kill_chain": 0.10,
    },
    # priority_score (0..1) -> label cutoffs
    "priority_cutoffs": {"critical": 0.62, "high": 0.45, "medium": 0.28},
}

_lock = threading.Lock()


def _load() -> dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            stored = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            merged = {**DEFAULTS, **stored}
            # deep-merge nested dicts so new defaults are not lost
            for k in ("weights", "priority_cutoffs"):
                merged[k] = {**DEFAULTS[k], **stored.get(k, {})}
            return merged
        except Exception:
            pass
    return json.loads(json.dumps(DEFAULTS))  # deep copy


_settings: dict[str, Any] = _load()


def get_config() -> dict[str, Any]:
    """Return a copy of the current live configuration."""
    with _lock:
        return json.loads(json.dumps(_settings))


def update_config(patch: dict[str, Any]) -> dict[str, Any]:
    """Shallow/nested-merge a patch into the live config and persist it."""
    with _lock:
        for key, value in patch.items():
            if key in ("weights", "priority_cutoffs") and isinstance(value, dict):
                _settings[key] = {**_settings.get(key, {}), **value}
            else:
                _settings[key] = value
        CONFIG_PATH.write_text(
            json.dumps(_settings, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return json.loads(json.dumps(_settings))


def reset_config() -> dict[str, Any]:
    with _lock:
        globals()["_settings"] = json.loads(json.dumps(DEFAULTS))
        if CONFIG_PATH.exists():
            CONFIG_PATH.unlink()
        return json.loads(json.dumps(_settings))
