from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any

TEMPORARY_BLOCK_DURATION_SECONDS = 3600


def protection_presentation(
    incident: dict[str, Any],
    policy: dict[str, Any] | None = None,
    *,
    action_job: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the owner-facing protection state from the live policy."""
    action = incident.get("recommended_action") or {}
    if action.get("action") != "apply_temporary_ip_block":
        saved = action.get("protection_status") or {}
        return {
            "state": saved.get("state", "not_required"),
            "title": saved.get("title", "No traffic change needed"),
            "description": saved.get(
                "explanation",
                "This report does not recommend changing your website traffic.",
            ),
            "target": None,
            "duration_seconds": None,
            "duration_label": None,
            "expires_at": None,
            "human_action": None,
            "can_retry": False,
            "can_unblock": False,
            "can_reapply": False,
        }

    target = display_ip(policy.get("target") if policy else action.get("target"))
    parameters = (policy or {}).get("parameters") or {}
    duration_seconds = int(
        parameters.get("duration_seconds")
        or action.get("duration_seconds")
        or TEMPORARY_BLOCK_DURATION_SECONDS
    )
    duration = duration_label(duration_seconds)
    expires_at = policy.get("expires_at") if policy else None
    state = policy.get("status") if policy else _policy_state_from_action_job(action_job)
    window_open = _is_future(expires_at, now=now)

    if incident.get("status") == "rejected":
        title = f"{target} was not blocked"
        description = "You chose not to change traffic from this address."
        human_action = f"You chose not to block {target}."
    elif state == "not_started":
        title = f"Block {target} for {duration}?"
        description = (
            "SecAi can temporarily stop requests from this address while you investigate. "
            "Nothing changes until you approve."
        )
        human_action = None
    elif state == "pending":
        title = "Your block is queued"
        description = f"SecAi is preparing to block {target}."
        human_action = f"You approved a {duration} block for {target}."
    elif state == "applying":
        title = f"Blocking {target}"
        description = "SecAi is waiting for Alibaba Cloud to confirm the block."
        human_action = f"You approved a {duration} block for {target}."
    elif state == "active":
        title = f"{target} is blocked"
        description = "Alibaba Cloud is dropping requests from this address."
        human_action = f"You blocked {target} for {duration}."
    elif state == "revoking":
        title = f"Unblocking {target}"
        description = "SecAi is waiting for Alibaba Cloud to remove the block."
        human_action = f"You chose to unblock {target}."
    elif state == "revoked":
        title = f"{target} is unblocked"
        description = (
            f"Requests from this address are allowed again. You can block it again until {format_expiry(expires_at)}."
            if window_open
            else "Requests from this address are allowed again."
        )
        human_action = f"You unblocked {target}."
    elif state == "expired":
        title = "The temporary block has ended"
        description = f"{target} is no longer blocked."
        human_action = f"The {duration} block you approved has ended."
    elif state == "failed":
        title = "The block was not applied"
        description = "Alibaba Cloud did not confirm the block. Retry it or review the error below."
        human_action = f"You approved blocking {target}, but Alibaba Cloud did not apply it."
    else:
        title = "Protection status unavailable"
        description = "Open the report again to refresh the current protection state."
        human_action = None

    return {
        "state": state,
        "title": title,
        "description": description,
        "target": target,
        "duration_seconds": duration_seconds,
        "duration_label": duration,
        "expires_at": expires_at,
        "human_action": human_action,
        "can_retry": state in {"pending", "failed"},
        "can_unblock": state == "active",
        "can_reapply": state == "revoked" and window_open,
    }


def _policy_state_from_action_job(action_job: dict[str, Any] | None) -> str:
    status = str((action_job or {}).get("status") or "")
    return {
        "awaiting_approval": "not_started",
        "queued": "pending",
        "running": "applying",
        "failed": "failed",
        "rejected": "not_started",
    }.get(status, "not_started")


def display_ip(value: Any) -> str:
    """Render a single-address CIDR as the address owners recognize."""
    text = str(value or "").strip()
    if not text:
        return "the source address"
    try:
        if "/" in text:
            network = ip_network(text, strict=False)
            if network.num_addresses == 1:
                return str(network.network_address)
        return str(ip_address(text))
    except ValueError:
        return text


def duration_label(seconds: int) -> str:
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"
    return f"{seconds} seconds"


def format_expiry(value: str | None) -> str:
    parsed = _parse_time(value)
    if not parsed:
        return "the temporary window ends"
    return parsed.strftime("%b %-d at %-I:%M %p UTC")


def temporary_window_open(value: str | None, *, now: datetime | None = None) -> bool:
    """Return whether an owner can reapply a manually removed temporary block."""
    return _is_future(value, now=now)


def _is_future(value: str | None, *, now: datetime | None = None) -> bool:
    parsed = _parse_time(value)
    return bool(parsed and parsed > (now or datetime.now(UTC)))


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
