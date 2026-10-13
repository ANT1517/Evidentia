import hashlib
import json
import re
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from app.api_models import CheckText, Detail, MessageDetail
from app.db import SessionLocal
from app.deps import current_user
from app.models import User
from app.services.messages import message_detail
from app.services.pipeline import process_message, process_raw_email
from shared.schemas import NormalizedMessage

router = APIRouter(tags=["check"])
MAX_EML = 2 * 1024 * 1024
_URL = re.compile(r"https?://[^\s<>\"')]+")

_BODY = {"requestBody": {"required": True, "content": {
    "application/json": {"schema": CheckText.model_json_schema()},
    "multipart/form-data": {"schema": {
        "type": "object", "required": ["file"],
        "properties": {"file": {"type": "string", "format": "binary", "description": ".eml, max 2 MB"}}}},
}}}


def _id(user_id: int, *parts: bytes) -> str:
    h = hashlib.sha256(str(user_id).encode())
    for p in parts:
        h.update(b"|" + p)
    h.update(b"|" + str(time.time_ns()).encode())
    return h.hexdigest()


def _store_text(user_id: int, body: CheckText) -> dict:
    msg = NormalizedMessage(
        user_id=user_id, channel=body.channel,
        external_id=_id(user_id, body.sender.encode(), body.text.encode()),
        sender=body.sender, body_text=body.text, urls=list(dict.fromkeys(u.rstrip(".,;:!?") for u in _URL.findall(body.text))),
        attachments=[], headers={}, received_at=datetime.now(timezone.utc),
    )
    with SessionLocal() as db:
        m, a = process_message(db, msg, source="check")
        return message_detail(db, m, a)


def _store_eml(user_id: int, raw: bytes) -> dict:
    with SessionLocal() as db:
        m, a = process_raw_email(db, raw, user_id, _id(user_id, raw), source="check")
        return message_detail(db, m, a)


@router.post("/check", response_model=MessageDetail, openapi_extra=_BODY,
             responses={401: {"model": Detail}, 413: {"model": Detail}, 415: {"model": Detail},
                        422: {"model": Detail}},
             summary="Check a pasted SMS/WhatsApp message (JSON) or an uploaded .eml (multipart, field 'file')")
async def check(request: Request, user: User = Depends(current_user)):
    ctype = request.headers.get("content-type", "")
    if ctype.startswith("application/json"):
        try:
            body = CheckText.model_validate(await request.json())
        except ValidationError as e:
            raise RequestValidationError(e.errors())
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise HTTPException(422, "invalid JSON")
        return await run_in_threadpool(_store_text, user.id, body)

    if ctype.startswith("multipart/form-data"):
        if int(request.headers.get("content-length") or 0) > MAX_EML + 100_000:
            raise HTTPException(413, "file too large (max 2 MB)")
        f = (await request.form()).get("file")
        if f is None or not hasattr(f, "read"):
            raise HTTPException(422, "file: field required")
        raw = await f.read(MAX_EML + 1)
        if len(raw) > MAX_EML:
            raise HTTPException(413, "file too large (max 2 MB)")
        return await run_in_threadpool(_store_eml, user.id, raw)

    raise HTTPException(415, "send JSON or a multipart .eml upload")
