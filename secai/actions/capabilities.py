from __future__ import annotations

from dataclasses import dataclass

from secai.models import RemediationAction


@dataclass(frozen=True)
class ActionSpec:
    """Application-owned contract for one Qwen-selectable executable action."""

    name: RemediationAction
    tool_name: str
    requires_approval: bool
    provider: str


ACTION_SPECS: dict[RemediationAction, ActionSpec] = {
    "collect_follow_up_cloud_evidence": ActionSpec(
        name="collect_follow_up_cloud_evidence",
        tool_name="collect_follow_up_cloud_evidence",
        requires_approval=False,
        provider="alibaba_sls",
    ),
    "send_owner_alert": ActionSpec(
        name="send_owner_alert",
        tool_name="send_owner_security_alert",
        requires_approval=False,
        provider="configured_report_channel",
    ),
    "apply_temporary_ip_block": ActionSpec(
        name="apply_temporary_ip_block",
        tool_name="apply_temporary_ip_block",
        requires_approval=True,
        provider="alibaba_security_group",
    ),
}


def action_spec(action: str) -> ActionSpec:
    """Return the canonical executable contract for an internal action name."""
    try:
        return ACTION_SPECS[action]  # type: ignore[index]
    except KeyError as exc:
        raise ValueError(f"Unsupported SecAi action: {action}") from exc


def requires_approval(action: str) -> bool:
    return action_spec(action).requires_approval


def tool_name_for_action(action: str) -> str:
    return action_spec(action).tool_name
