from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request

from secai.integrations import discord

router = APIRouter(prefix="/api/integrations/discord", tags=["discord"])


@router.post("/interactions")
async def interactions(request: Request) -> dict:
    """Verify and process Discord application-command interactions."""
    body = await request.body()
    signature = request.headers.get("x-signature-ed25519", "")
    timestamp = request.headers.get("x-signature-timestamp", "")
    try:
        discord.verify_interaction_signature(signature, timestamp, body)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid Discord interaction JSON") from exc
    if payload.get("type") == 1:
        return {"type": 1}
    if payload.get("type") == 2:
        return discord.connect_interaction(payload)
    return {"type": 4, "data": {"content": "Unsupported Discord interaction.", "flags": 64}}
