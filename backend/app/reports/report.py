"""Analytical report generation (assignment §7.9).

Builds a self-contained HTML report (printable to PDF from the browser) with the
event timeline, detected anomalies, correlated groups, most significant events,
AI findings, statistics, and an auto-generated situational assessment.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(["html"]),
)

_PRIORITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_CAT_RU = {
    "informational": "Информационные", "needs_analysis": "Требуют анализа",
    "anomalous": "Аномальные", "repeating": "Повторяющиеся", "correlated": "Взаимосвязанные",
}
_PRI_RU = {"low": "Низкий", "medium": "Средний", "high": "Высокий", "critical": "Критический"}


def situation_level(summary: dict[str, Any]) -> dict[str, str]:
    p = summary.get("priorities", {})
    if p.get("critical"):
        return {"code": "critical", "label": "КРИТИЧЕСКАЯ", "color": "#c0455a"}
    if p.get("high"):
        return {"code": "high", "label": "ПОВЫШЕННАЯ", "color": "#c07a34"}
    if p.get("medium"):
        return {"code": "medium", "label": "УМЕРЕННАЯ", "color": "#b39237"}
    return {"code": "stable", "label": "СТАБИЛЬНАЯ", "color": "#3f8f6b"}


def _assessment(summary, groups, level) -> str:
    parts = [
        f"По результатам анализа {summary['events']} учебных событий информационная "
        f"обстановка оценивается как «{level['label']}»."
    ]
    if summary.get("anomalies"):
        parts.append(f"Выявлено аномальных событий: {summary['anomalies']}.")
    if groups:
        chained = [g for g in groups.values() if len(g.get("kill_chain", [])) >= 2]
        parts.append(f"Обнаружено взаимосвязанных групп событий: {len(groups)}"
                     + (f", из них с признаками многоэтапной атаки: {len(chained)}." if chained else "."))
    crit = summary.get("priorities", {}).get("critical", 0)
    if crit:
        parts.append(f"Требуют немедленного реагирования событий критического уровня: {crit}.")
    parts.append("Итоговое решение остаётся за оператором; результаты интеллектуального "
                 "анализа носят рекомендательный характер.")
    return " ".join(parts)


def build_report(rows: list[dict[str, Any]], groups: dict[int, dict],
                 summary: dict[str, Any]) -> str:
    level = situation_level(summary)

    top_events = sorted(rows, key=lambda r: (r.get("priority_score") or 0), reverse=True)[:15]
    anomalies = sorted([r for r in rows if r.get("is_anomaly")],
                       key=lambda r: (r.get("anomaly_score") or 0), reverse=True)[:15]
    group_list = sorted(groups.values(),
                        key=lambda g: (g.get("max_severity", 0), g.get("size", 0)), reverse=True)

    # compact timeline: significant events only, chronological
    timeline = sorted(
        [r for r in rows if (r.get("priority") in ("high", "critical")) or r.get("is_anomaly")],
        key=lambda r: r["event_time"],
    )[:40]

    ctx = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "summary": summary,
        "level": level,
        "assessment": _assessment(summary, groups, level),
        "categories": [(_CAT_RU.get(k, k), v) for k, v in
                       sorted(summary.get("categories", {}).items(), key=lambda x: -x[1])],
        "priorities": [(_PRI_RU.get(k, k), v, k) for k, v in
                       sorted(summary.get("priorities", {}).items(),
                              key=lambda x: -_PRIORITY_ORDER.get(x[0], 0))],
        "top_events": top_events,
        "anomalies": anomalies,
        "groups": group_list,
        "timeline": timeline,
        "cat_ru": _CAT_RU,
        "pri_ru": _PRI_RU,
    }
    return _env.get_template("report.html.j2").render(**ctx)
