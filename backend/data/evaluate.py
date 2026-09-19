"""End-to-end check: ingest synthetic sources, run pipeline, score vs ground truth.

Run from backend/:  python -m data.evaluate
"""
from __future__ import annotations

import json
from pathlib import Path

from app import db
from app.ingestion import parse_file
from app.pipeline import run_pipeline
from app.pipeline.run import get_groups

SYN = Path(__file__).resolve().parent / "synthetic"
FILES = ["auth_gateway.csv", "ids_sensor.json", "host_agent.log"]


def main():
    db.init_db()
    db.clear_events()

    total_in = 0
    for fn in FILES:
        evs = parse_file(str(SYN / fn), batch="eval")
        res = db.insert_events(evs)
        total_in += res["inserted"]
        print(f"ingest {fn:20s}: +{res['inserted']} (dup {res['duplicates']})")
    print(f"total ingested: {total_in}\n")

    summary = run_pipeline(actor="eval")
    print("PIPELINE:", json.dumps({k: summary[k] for k in
          ("events", "anomalies", "correlation_groups", "elapsed_ms", "throughput_eps")}, indent=2))
    print("categories:", summary["categories"])
    print("priorities:", summary["priorities"])

    gt = json.loads((SYN / "ground_truth.json").read_text(encoding="utf-8"))
    rows = db.fetch_events()

    # --- accuracy metrics --------------------------------------------------
    cat_ok = cat_tot = 0
    anom_tp = anom_fp = anom_fn = 0
    for r in rows:
        g = gt["events"].get(r["event_id"])
        if not g:
            continue
        cat_tot += 1
        # treat correlated/anomalous/repeating as the "interesting" labels
        if _cat_match(r["category"], g["category"]):
            cat_ok += 1
        pred_a, true_a = bool(r["is_anomaly"]), bool(g["anomaly"])
        if pred_a and true_a:
            anom_tp += 1
        elif pred_a and not true_a:
            anom_fp += 1
        elif not pred_a and true_a:
            anom_fn += 1

    prec = anom_tp / (anom_tp + anom_fp) if (anom_tp + anom_fp) else 0
    rec = anom_tp / (anom_tp + anom_fn) if (anom_tp + anom_fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    print(f"\nCategory accuracy: {cat_ok}/{cat_tot} = {cat_ok/cat_tot:.1%}")
    print(f"Anomaly detection: precision={prec:.1%} recall={rec:.1%} F1={f1:.1%} "
          f"(TP={anom_tp} FP={anom_fp} FN={anom_fn})")

    # --- correlation: did we recover the planted groups? -------------------
    groups = get_groups()
    print(f"\nCorrelation groups found: {len(groups)}")
    for scenario, ids in gt["correlation_groups"].items():
        # which found group best covers this scenario's events?
        best_gid, best_overlap = None, 0
        pk_of = {r["event_id"]: r["correlation_group_id"] for r in rows}
        gids = [pk_of.get(eid) for eid in ids if pk_of.get(eid)]
        if gids:
            from collections import Counter
            best_gid, best_overlap = Counter(gids).most_common(1)[0]
        cover = best_overlap / len(ids) if ids else 0
        print(f"  {scenario:12s}: {len(ids)} planted -> group #{best_gid} "
              f"covers {best_overlap}/{len(ids)} = {cover:.0%}")


def _cat_match(pred: str, truth: str) -> bool:
    if pred == truth:
        return True
    # anomalous events are also acceptably flagged correlated (both are "alert-worthy")
    alertish = {"anomalous", "correlated"}
    return pred in alertish and truth in alertish


if __name__ == "__main__":
    main()
