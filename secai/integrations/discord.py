from __future__ import annotations

import httpx

from secai import database
from secai.settings import get_settings


def notify_incident(incident: dict) -> bool:
    """Send an incident notification through the site's selected channels."""
    sent = False
    for channel in database.list_report_channels(incident["site_id"]):
        config = channel["config"]
        if channel["channel"] == "discord":
            if config.get("channel_id") and get_settings().discord_bot_token:
                sent = _notify_discord_bot(incident, config["channel_id"], get_settings().discord_bot_token) or sent
    return sent


def _approval_urls(incident: dict) -> dict[str, str]:
    """Build review, approve, and reject URLs for an incident."""
    settings = get_settings()
    token = incident.get("approval_token")
    review_url = f"{settings.frontend_base_url}/?incident={incident['id']}"
    if not token or incident.get("status") != "needs_review":
        return {
            "review": review_url,
            "approve": review_url,
            "reject": review_url,
        }
    return {
        "review": review_url,
        "approve": f"{settings.public_base_url}/approval/{token}/approve?redirect=true",
        "reject": f"{settings.public_base_url}/approval/{token}/reject?redirect=true",
    }


def _message(incident: dict) -> str:
    """Build the human-readable incident alert text."""
    recommendation = incident.get("recommended_action", {})
    next_steps = recommendation.get("app_specific_next_steps") or []
    rendered_next_steps = ""
    if next_steps:
        rendered_next_steps = "\nApp-specific next steps:\n" + "\n".join(f"- {step}" for step in next_steps[:3])
    content = (
        f"SecAi report: {incident['title']}\n"
        f"Severity: {incident['severity']} | Status: {incident['status']}\n"
        f"Route: {incident.get('affected_route') or 'unknown'}\n"
        f"Recommended action: {recommendation.get('action', 'review')}\n"
        f"{rendered_next_steps}\n"
        f"Approve or reject directly from this message."
    )
    return content[:1900]


def _discord_payload(incident: dict) -> dict:
    """Build a Discord message payload with approval links."""
    urls = _approval_urls(incident)
    components = [
        {
            "type": 1,
            "components": [
                {"type": 2, "style": 5, "label": "Approve", "url": urls["approve"]},
                {"type": 2, "style": 5, "label": "Reject", "url": urls["reject"]},
                {"type": 2, "style": 5, "label": "Open report", "url": urls["review"]},
            ],
        }
    ]
    return {"content": _message(incident), "components": components}


def _notify_discord_bot(incident: dict, channel_id: str, bot_token: str) -> bool:
    """Send an incident alert to Discord through SecAi's bot."""
    try:
        response = httpx.post(
            f"https://discord.com/api/v10/channels/{channel_id}/messages",
            json=_discord_payload(incident),
            headers={"Authorization": f"Bot {bot_token}"},
            timeout=10,
        )
        response.raise_for_status()
        return True
    except Exception:
        return False
