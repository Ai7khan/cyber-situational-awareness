# Intelligent Cyber Situational Awareness System — Implementation Plan

> DefenceTech Hackathon — Task #9: *"Разработка интеллектуальной системы анализа и мониторинга киберобстановки"*
> A training-environment mini-SIEM that turns individual security events into one coherent, explainable picture and helps a human decide what matters.

## 1. Problem summary

Given a synthetic stream of information-security events from mixed sources and formats, the prototype must:
`Sources → collection & normalization → classification → correlation → intelligent (AI) analysis → priority scoring → visualization → analytical report`
plus two cross-cutting modules: **audit journal** and **report generation**.

### Hard requirements from the assignment
- **AI must solve a real sub-task** (anomalies + correlation + hidden sequences), not be a bolted-on gimmick.
- **Human-in-the-loop**: AI output is a *recommendation*; the system must never auto-decide.
- **Explainability is graded** — every priority / anomaly verdict must show *why*.
- **Web interface is mandatory**, with drill-down from the big picture to a single event.
- **Synthetic / anonymized data only**; no connection to real systems.

### Judging criteria (10)
Functionality · Analysis accuracy · Anomaly detection · Correlation · Processing speed · Visualization quality · Explainability · Scalability · Practical applicability · Innovation (effective AI use).

## 2. Stack (chosen)

| Layer | Choice | Why |
|---|---|---|
| Backend/API | **Python + FastAPI** | ML lives in Python; async API |
| Data/ML | pandas, scikit-learn (IsolationForest/DBSCAN), networkx | fast, explainable models |
| Storage | **SQLite** (single file) | zero-setup, indexable, scalability story via indexes |
| Frontend | **React (Vite)** + Recharts + **Cytoscape.js** | best visuals; interactive correlation graph |
| Reports | Jinja2 → HTML → PDF | timeline + stats + AI findings |

Team: **solo**. Dataset: judges likely won't provide one → we ship our own **synthetic generator with ground truth**, informed by open-source event taxonomies.

## 3. Canonical event schema

Normalize every source into one row (ECS-inspired):

```
event_id, ingest_time, event_time, source_name, source_format,
raw_type, host, src_ip, dst_ip, user, action, protocol, port,
status, raw_severity, message, tags[]            # ingested
+ category, anomaly_score, is_anomaly,
  correlation_group_id, priority, priority_reason, explain{}   # computed
```

## 4. Phases

- **Phase 0 — Skeleton.** Monorepo (`/backend`, `/frontend`, `/data`, `/ml`, `/reports`). Canonical schema as Pydantic + SQLite table, indexes on `event_time`, `src_ip`, `category`.
- **Phase 1 — Synthetic data generator (critical, early).** Plant known ground truth: baseline normal events, repeating events, anomalous bursts (brute force), correlated kill-chains (recon → exploit → lateral move), subtle multi-step sequences. Export the same logical data as **CSV / JSON / syslog** to prove multi-format ingestion. Keep hidden `ground_truth.json` for accuracy measurement.
- **Phase 2 — Ingestion & normalization.** Pluggable parsers per format → canonical schema; unknown fields → `tags`. Record `ingest_time`, preserve history, support upload + "load prepared source."
- **Phase 3 — Unified store, dedup & grouping.** Dedup by content hash; group by configurable keys (host/ip/user) = single event base.
- **Phase 4 — Classification.** Editable rule engine → categories: informational / needs-analysis / anomalous / repeating / potentially-correlated. Transparent, adjustable criteria.
- **Phase 5 — Correlation engine.** networkx graph: edges on temporal proximity, shared attributes, sequence/kill-chain order, repetition. Connected components = correlated groups. Store edge reasons for explainability.
- **Phase 6 — Intelligent analysis / AI (graded core).** IsolationForest on engineered features (event rate, unique dst per src, failure ratio, off-hours, rarity) → `anomaly_score` + top contributing features. Sequence anomaly via Markov/n-gram rarity for hidden sequences. DBSCAN for anomalous groups. All output = recommendations with reasons.
- **Phase 7 — Priority scoring.** Transparent weighted formula: `w1·raw_severity + w2·anomaly_score + w3·corr_group_size + w4·repetition + w5·kill_chain_stage` → low/medium/high/critical. Store `priority_reason`; weights editable in UI.
- **Phase 8 — Audit journal.** Log ingested events, processing results, user actions, parameter/weight changes, generated recommendations.
- **Phase 9 — Report generation.** Jinja2 HTML/PDF: timeline, anomalies, correlated groups, top events, AI findings, statistics, final situation assessment.
- **Phase 10 — API layer.** REST: upload, `/events`, `/stats`, `/correlations`, `/anomalies`, `/priorities`, `/journal`, `/report`, `/config` (weights/rules).
- **Phase 11 — Dashboard (graded core).** KPIs, category distribution, events-over-time timeline, top events, interactive Cytoscape correlation graph, anomalies list, situation-change indicator. Drill-down to event detail with *why*. Live config panel to edit weights/rules and re-run.
- **Phase 12 — Demo, accuracy & performance polish.** Measure accuracy vs `ground_truth.json`; time the pipeline (show in UI); rehearse the §8 demo flow end to end.

## 5. Demo flow (assignment §8)
ingest → structure → classify → correlate → detect anomalies → prioritize → dashboard → report.

## 6. Scope guardrails
- **Must-have for a passing demo:** multi-format ingestion → classification → correlation graph → ≥1 working ML anomaly detector → priority scoring → dashboard with drill-down → report. Covers all 8 demo steps.
- **Explainability is non-optional** — bake "why" into classification, anomaly, and priority from the start.
