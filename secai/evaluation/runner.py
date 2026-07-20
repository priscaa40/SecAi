from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

CASES_PATH = Path(__file__).with_name("cases.json")


def load_cases() -> list[dict[str, Any]]:
    return json.loads(CASES_PATH.read_text())


def score_predictions(cases: list[dict[str, Any]], predictions: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate compact user-friendly incident and classification metrics."""
    by_name = {prediction["name"]: prediction for prediction in predictions}
    true_positive = false_positive = false_negative = true_negative = profile_matches = 0
    expected_profiles = 0
    for case in cases:
        prediction = by_name[case["name"]]
        expected = bool(case["expected_incident"])
        actual = bool(prediction.get("incident_created"))
        if expected and actual:
            true_positive += 1
        elif expected:
            false_negative += 1
        elif actual:
            false_positive += 1
        else:
            true_negative += 1
        if case.get("expected_profile"):
            expected_profiles += 1
            profile_matches += int(prediction.get("profile") == case["expected_profile"])
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    return {
        "cases": len(cases),
        "incident_precision": round(precision, 3),
        "incident_recall": round(recall, 3),
        "false_positive_rate": round(false_positive / max(1, false_positive + true_negative), 3),
        "profile_accuracy": round(profile_matches / max(1, expected_profiles), 3),
        "confusion": {"tp": true_positive, "fp": false_positive, "fn": false_negative, "tn": true_negative},
    }


def run_qwen_evaluation(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """Run the corpus through the real Qwen/LangGraph workflow in an isolated SQLite database."""
    if not os.getenv("DASHSCOPE_API_KEY"):
        raise RuntimeError("DASHSCOPE_API_KEY is required because SecAi evaluations use the real Qwen workflow.")
    temporary_directory = tempfile.TemporaryDirectory(prefix="secai-evaluation-")
    os.environ["DATABASE_URL"] = f"sqlite:///{Path(temporary_directory.name) / 'evaluation.db'}"

    from secai import database
    from secai.agent.workflow import process_event
    from secai.event_sources.normalizer import normalize_event
    from secai.event_sources.relevance import is_event_relevant
    from secai.security.redaction import sanitize_event
    from secai.settings import get_settings

    get_settings.cache_clear()
    database.init_db()
    predictions = []
    for case in cases:
        evidence_source = "alibaba_autopilot" if case["source_contract"] == "alibaba_sls" else "browser"
        site = database.create_site(f"Evaluation: {case['name']}", None, evidence_source)
        event = sanitize_event(normalize_event({**case["event"], "site_id": site["site_id"]}))
        if not is_event_relevant(event):
            predictions.append(
                {
                    "name": case["name"],
                    "source_contract": case["source_contract"],
                    "incident_created": False,
                    "profile": None,
                    "filtered": True,
                    "qwen_calls": 0,
                }
            )
            continue
        stored = database.insert_event(event)
        incident = process_event(stored)
        case_usage = database.summarize_qwen_usage_for_sites([site["site_id"]])
        if int(case_usage["calls"]) < 1:
            raise RuntimeError(f"Evaluation case {case['name']} reached investigation without recorded Qwen usage")
        predictions.append(
            {
                "name": case["name"],
                "source_contract": case["source_contract"],
                "incident_created": bool(incident),
                "profile": incident.get("recommended_action", {}).get("security_profile_id") if incident else None,
                "confidence": incident.get("confidence") if incident else None,
                "filtered": False,
                "qwen_calls": case_usage["calls"],
            }
        )
    metrics = score_predictions(cases, predictions)
    qwen_predictions = [prediction for prediction in predictions if not prediction["filtered"]]
    qwen_names = {prediction["name"] for prediction in qwen_predictions}
    qwen_cases = [case for case in cases if case["name"] in qwen_names]
    metrics["filter"] = {
        "filtered_cases": len(predictions) - len(qwen_predictions),
        "qwen_cases": len(qwen_predictions),
    }
    metrics["qwen_only"] = score_predictions(qwen_cases, qwen_predictions)
    metrics["qwen_usage"] = database.summarize_qwen_usage_for_sites([site["site_id"] for site in database.list_sites()])
    temporary_directory.cleanup()
    return {"mode": "qwen", "metrics": metrics, "predictions": predictions}


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate SecAi's Qwen workflow against its security corpus.")
    parser.add_argument("--output", type=Path, help="Optionally write the JSON result to this path.")
    args = parser.parse_args()
    result = run_qwen_evaluation(load_cases())
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    main()
