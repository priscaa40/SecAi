from __future__ import annotations

import json
from typing import Any


def apply(conn: Any) -> None:
    """Normalize existing reports using content already produced by their agents."""
    rows = conn.execute(
        "select id, title, recommended_action_json from incidents order by id"
    ).fetchall()
    for row in rows:
        action = _object(row["recommended_action_json"])
        raw_sections = action.get("report_sections")
        sections: dict[str, Any] = raw_sections if isinstance(raw_sections, dict) else {}
        raw_summary = sections.get("owner_summary")
        existing_summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        raw_recommendation = action.get("owner_recommendation")
        existing_recommendation: dict[str, Any] = (
            raw_recommendation if isinstance(raw_recommendation, dict) else {}
        )
        recommendation_steps = existing_recommendation.get("steps")
        if not isinstance(recommendation_steps, list):
            recommendation_steps = action.get("app_specific_next_steps")
        if not isinstance(recommendation_steps, list):
            recommendation_steps = []

        summary_text = _text(sections.get("summary"), action.get("investigation_summary"), row["title"])
        what_happened = _text(sections.get("what_happened"), summary_text)
        why_it_matters = _text(sections.get("why_it_matters"), summary_text)
        recommended_next_step = _text(
            sections.get("recommended_next_step"),
            existing_recommendation.get("title"),
            action.get("reason"),
            summary_text,
        )
        owner_summary = {
            "title": _text(existing_summary.get("title"), row["title"]),
            "potential_impact": _text(existing_summary.get("potential_impact"), why_it_matters),
            "evidence": _text(existing_summary.get("evidence"), what_happened),
            "recommended_action": _text(existing_summary.get("recommended_action"), recommended_next_step),
        }
        owner_recommendation = {
            "title": _text(existing_recommendation.get("title"), recommended_next_step),
            "explanation": _text(existing_recommendation.get("explanation"), why_it_matters),
            "steps": [str(step) for step in recommendation_steps if str(step).strip()][:4],
        }
        if not owner_recommendation["steps"]:
            owner_recommendation["steps"] = [recommended_next_step]

        action["report_sections"] = {**sections, "owner_summary": owner_summary}
        action["owner_recommendation"] = owner_recommendation
        conn.execute(
            "update incidents set title = ?, recommended_action_json = ? where id = ?",
            (owner_summary["title"], json.dumps(action), row["id"]),
        )


def _object(raw: Any) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _text(*values: Any) -> str:
    for value in values:
        rendered = str(value or "").strip()
        if rendered:
            return rendered
    return "Open the report and review the available evidence."
