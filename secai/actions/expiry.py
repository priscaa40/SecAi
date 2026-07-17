from __future__ import annotations

import logging
import threading

from secai import database
from secai.actions import remediation
from secai.settings import get_settings

logger = logging.getLogger(__name__)
_stop_event = threading.Event()
_worker: threading.Thread | None = None


def start_policy_expiry() -> None:
    """Start the singleton-in-process policy expiry reconciler."""
    global _worker
    if get_settings().secai_policy_expiry_interval_seconds <= 0:
        return
    if _worker and _worker.is_alive():
        return
    _stop_event.clear()
    _worker = threading.Thread(target=_expiry_loop, name="secai-policy-expiry", daemon=True)
    _worker.start()


def stop_policy_expiry() -> bool:
    """Stop the policy expiry reconciler."""
    _stop_event.set()
    if _worker and _worker.is_alive():
        _worker.join(timeout=5)
    return not bool(_worker and _worker.is_alive())


def expire_due_policies() -> dict[str, int]:
    """Revoke due Alibaba rules and retain failures for the next reconciliation."""
    result = {"seen": 0, "expired": 0, "failed": 0}
    while True:
        policy = database.claim_due_policy()
        if not policy:
            break
        result["seen"] += 1
        incident_id = policy.get("incident_id")
        incident = database.get_incident(incident_id) if isinstance(incident_id, int) else None
        if not incident:
            result["failed"] += 1
            logger.error("Cannot expire policy %s because its incident is missing", policy["id"])
            break
        try:
            expired = remediation.revoke_policy_for_incident(incident, final_status="expired")
        except Exception:
            result["failed"] += 1
            logger.exception("Failed to expire remediation policy %s", policy["id"])
            break
        if expired:
            result["expired"] += 1
        else:
            result["failed"] += 1
            break
    return result


def _expiry_loop() -> None:
    interval = max(10, get_settings().secai_policy_expiry_interval_seconds)
    expire_due_policies()
    while not _stop_event.wait(interval):
        expire_due_policies()
