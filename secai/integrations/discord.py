from __future__ import annotations

import hashlib
import logging
import secrets
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from secai import database
from secai.actions.protection_presentation import protection_presentation
from secai.settings import get_settings

logger = logging.getLogger(__name__)


def notify_incident(incident: dict) -> bool:
    """Send an incident notification through the site's selected channels."""
    sent = False
    for channel in database.list_report_channels(incident["site_id"]):
        config = channel["config"]
        bot_token = get_settings().discord_bot_token
        if channel["channel"] == "discord" and config.get("channel_id") and bot_token:
            sent = _notify_discord_bot(incident, config["channel_id"], bot_token) or sent
    return sent


def notify_decision_result(
    incident: dict,
    decision: str,
    *,
    result: dict | None = None,
    error: str | None = None,
) -> bool:
    """Tell the connected Discord channel whether its decision took effect."""
    stored_incident = (result or {}).get("incident") or database.get_incident(incident["id"]) or incident
    policy = (result or {}).get("policy")
    if policy is None:
        policy = database.get_policy_for_incident(incident["id"])
    presentation = protection_presentation(stored_incident, policy)
    target = presentation.get("target") or "the source address"
    duration = presentation.get("duration_label") or "1 hour"

    if error and decision == "approve" and stored_incident.get("status") == "approved":
        content = f"❌ Your approval for {target} was saved, but SecAi could not finish the action. {error}"
    elif error:
        content = f"❌ SecAi could not save your decision for {target}. {error}"
    elif decision == "reject":
        content = f"✅ You chose not to block {target}. No traffic was changed."
    elif policy and policy.get("status") == "active":
        content = f"✅ {target} was blocked for {duration}. Alibaba Cloud confirmed the block."
    elif policy and policy.get("status") == "failed":
        content = f"⚠️ You approved blocking {target}, but Alibaba Cloud did not apply it. Open the report to retry."
    else:
        content = f"⚠️ Your approval was saved, but the block for {target} is not active yet. Open the report for details."

    payload = {
        "content": content,
        "components": [
            {
                "type": 1,
                "components": [
                    {
                        "type": 2,
                        "style": 5,
                        "label": "Open report",
                        "url": f"{get_settings().frontend_base_url}/?incident={incident['id']}",
                    }
                ],
            }
        ],
    }
    return _notify_site_discord(incident["site_id"], payload)


def setup_code_hash(code: str) -> str:
    """Return a one-way digest for a short-lived Discord channel setup code."""
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


def create_channel_setup(site_id: str) -> dict[str, str]:
    """Replace any pending Discord binding with a fresh one-time setup."""
    setup_code = secrets.token_urlsafe(6)
    expires_at = (datetime.now(UTC) + timedelta(hours=24)).isoformat()
    database.save_report_channel(
        site_id,
        "discord",
        True,
        {
            "status": "pending_bot_connection",
            "setup_code_hash": setup_code_hash(setup_code),
            "setup_expires_at": expires_at,
        },
    )
    return {
        "channel": "discord",
        "setup_code": setup_code,
        "invite_url": invite_url(),
        "expires_at": expires_at,
    }


def invite_url() -> str:
    """Return the bot/application-command invite URL for the configured Discord app."""
    application_id = get_settings().discord_application_id
    if not application_id:
        return ""
    return (
        "https://discord.com/oauth2/authorize"
        f"?client_id={application_id}&permissions=3072&scope=bot%20applications.commands"
    )


def discord_is_configured() -> bool:
    """Return whether notification, command, and interaction credentials are present."""
    settings = get_settings()
    return bool(
        settings.discord_bot_token and settings.discord_application_id and settings.discord_application_public_key
    )


def setup_readiness_error() -> str | None:
    """Return a client-safe reason Discord setup cannot work from this deployment."""
    settings = get_settings()
    if not discord_is_configured():
        return "Discord credentials are not configured for this deployment."
    parsed = urlparse(settings.public_base_url)
    if parsed.scheme != "https" or parsed.hostname in {None, "localhost", "127.0.0.1", "::1"}:
        return "Discord requires a public HTTPS API address before a report channel can be connected."
    if not settings.discord_auto_register_commands:
        return "Discord command registration is disabled for this deployment."
    return None


def verify_interaction_signature(signature: str, timestamp: str, body: bytes) -> None:
    """Verify an incoming Discord interaction using the application Ed25519 key."""
    public_key = get_settings().discord_application_public_key
    if not public_key:
        raise ValueError("DISCORD_APPLICATION_PUBLIC_KEY is not configured")
    try:
        if abs(time.time() - int(timestamp)) > 300:
            raise ValueError("Discord interaction timestamp is stale")
        verifier = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        verifier.verify(bytes.fromhex(signature), timestamp.encode("utf-8") + body)
    except (ValueError, InvalidSignature) as exc:
        if str(exc) == "Discord interaction timestamp is stale":
            raise
        raise ValueError("Invalid Discord interaction signature") from exc


def connect_interaction(payload: dict) -> dict:
    """Handle /connect and confirm a successful server-channel binding."""
    data = payload.get("data") or {}
    if data.get("name") != "connect":
        return _interaction_message("Unknown SecAi command.")
    options = {item.get("name"): item.get("value") for item in data.get("options") or []}
    code = str(options.get("code") or "").strip()
    channel_id = str(payload.get("channel_id") or "").strip()
    guild_id = str(payload.get("guild_id") or "").strip() or None
    if not guild_id:
        return _interaction_message("Run `/connect` in the private server channel where reports should arrive.")
    if not code or not channel_id:
        return _interaction_message(
            "Run `/connect code:<your setup code>` inside the server channel that should receive reports."
        )
    connected = database.connect_discord_setup_code(setup_code_hash(code), channel_id, guild_id)
    if not connected:
        return _interaction_message(
            "That setup code is invalid, expired, or already used. Generate a new setup from SecAi."
        )
    return _interaction_message(
        "Connected. Security reports for "
        f"`{connected['site_id']}` will be delivered here.",
        ephemeral=False,
    )


def register_commands() -> bool:
    """Register the dedicated Discord application command used during channel setup."""
    settings = get_settings()
    if not settings.discord_bot_token or not settings.discord_application_id:
        return False
    response = httpx.put(
        f"https://discord.com/api/v10/applications/{settings.discord_application_id}/commands",
        headers={"Authorization": f"Bot {settings.discord_bot_token}"},
        json=[
            {
                "name": "connect",
                "description": "Connect this Discord channel to a SecAi website",
                "contexts": [0],
                "options": [
                    {
                        "name": "code",
                        "description": "Short setup code shown by SecAi",
                        "type": 3,
                        "required": True,
                    }
                ],
            }
        ],
        timeout=15,
    )
    response.raise_for_status()
    return True


def verify_application_configuration() -> None:
    """Reject channel setup when Discord cannot route commands to this API."""
    settings = get_settings()
    try:
        response = httpx.get(
            "https://discord.com/api/v10/oauth2/applications/@me",
            headers={"Authorization": f"Bot {settings.discord_bot_token}"},
            timeout=15,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError("Discord application settings could not be verified. Try again in a moment.") from exc
    configured_url = str(response.json().get("interactions_endpoint_url") or "").rstrip("/")
    expected_url = f"{settings.public_base_url.rstrip('/')}/api/integrations/discord/interactions"
    if configured_url != expected_url:
        raise RuntimeError(
            "Discord Interactions Endpoint URL must be set to "
            f"{expected_url} before Discord reports can be enabled."
        )


def _interaction_message(content: str, *, ephemeral: bool = True) -> dict:
    data: dict[str, object] = {"content": content}
    if ephemeral:
        data["flags"] = 64
    return {"type": 4, "data": data}


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
    response_plan = incident.get("recommended_action", {})
    report_sections = response_plan.get("report_sections") or {}
    summary = report_sections.get("owner_summary") or {}
    protection = protection_presentation(incident, database.get_policy_for_incident(incident["id"]))
    closing = (
        "Review the temporary protection below. No traffic will change until it is approved."
        if incident.get("status") == "needs_review" and incident.get("approval_token")
        else "Open the report for supporting evidence and investigation details."
    )
    content = (
        f"Security report: {incident['title']}\n"
        f"Risk: {str(incident['severity']).title()} | Route: {incident.get('affected_route') or 'Not recorded'}\n\n"
        f"{summary.get('potential_impact', '')}\n\n"
        f"{summary.get('evidence', '')}\n"
        f"Recommended action: {summary.get('recommended_action', 'Open the report and review the evidence.')}\n\n"
        f"Protection status\n{protection.get('title', 'Open the report for the current status')}\n"
        f"{protection.get('description', '')}\n\n"
        f"{closing}"
    )
    return content[:1900]


def _discord_payload(incident: dict) -> dict:
    """Build a Discord message payload with approval links."""
    urls = _approval_urls(incident)
    buttons = [{"type": 2, "style": 5, "label": "Open report", "url": urls["review"]}]
    if incident.get("status") == "needs_review" and incident.get("approval_token"):
        buttons = [
            {"type": 2, "style": 5, "label": "Block for 1 hour", "url": urls["approve"]},
            {"type": 2, "style": 5, "label": "Don't block", "url": urls["reject"]},
            *buttons,
        ]
    components = [{"type": 1, "components": buttons}]
    return {"content": _message(incident), "components": components}


def _notify_discord_bot(incident: dict, channel_id: str, bot_token: str) -> bool:
    """Send an incident alert to Discord through SecAi's bot."""
    return _post_discord_payload(channel_id, bot_token, _discord_payload(incident))


def _notify_site_discord(site_id: str, payload: dict) -> bool:
    sent = False
    bot_token = get_settings().discord_bot_token
    if not bot_token:
        return False
    for channel in database.list_report_channels(site_id):
        config = channel["config"]
        if channel["channel"] == "discord" and config.get("channel_id"):
            sent = _post_discord_payload(config["channel_id"], bot_token, payload) or sent
    return sent


def _post_discord_payload(channel_id: str, bot_token: str, payload: dict) -> bool:
    """Post one bot message without allowing Discord failures to affect protection."""
    try:
        response = httpx.post(
            f"https://discord.com/api/v10/channels/{channel_id}/messages",
            json=payload,
            headers={"Authorization": f"Bot {bot_token}"},
            timeout=10,
        )
        response.raise_for_status()
        return True
    except Exception:
        logger.exception("Could not send Discord incident alert to channel %s", channel_id)
        return False
