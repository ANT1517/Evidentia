import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from google.auth.exceptions import RefreshError
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.api_models import (
    Band, Channel, Detail, EscalateIn, EscalationOut, FeedbackIn, FeedbackOut, MeOut, MePatch,
    MessageDetail, MessageList, ScanOut,
)
from app.db import get_db
from app.deps import current_user
from app.models import Feedback, User
from app.services.directory import normalize_phone
from app.services.escalation import EscalationFailed, escalate_message
from app.services.messages import get_own_message, list_messages, message_detail
from app.workers.gmail_poller import poll_user

log = logging.getLogger(__name__)
router = APIRouter(tags=["me"])
AUTH = {401: {"model": Detail, "description": "Not signed in"}}
NOT_FOUND = {**AUTH, 404: {"model": Detail, "description": "No such message (or not yours)"}}


def _me(u: User) -> dict:
    return {
        "id": u.id, "name": u.name, "email": u.email, "title": u.title,
        "gmail_connected": bool(u.gmail_refresh_token_enc),
        "whatsapp_number": u.whatsapp_number,
    }


@router.get("/me", response_model=MeOut, responses=AUTH, summary="Current employee")
def get_me(user: User = Depends(current_user)):
    return _me(user)


@router.patch("/me", response_model=MeOut, summary="Set or clear the WhatsApp number",
              responses={**AUTH, 409: {"model": Detail}, 422: {"model": Detail}})
def patch_me(body: MePatch, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if body.whatsapp_number and body.whatsapp_number.strip():
        num = normalize_phone(body.whatsapp_number)
        if not num:
            raise HTTPException(422, "invalid phone number")
        taken = db.scalar(select(User.id).where(User.whatsapp_number == num, User.id != user.id))
        if taken:
            raise HTTPException(409, "number already registered")
        user.whatsapp_number = num
    else:
        user.whatsapp_number = None
    db.commit()
    return _me(user)


@router.post("/scan", response_model=ScanOut, summary="Check my Gmail now",
             responses={**AUTH, 409: {"model": Detail, "description": "Gmail not connected or revoked"},
                        502: {"model": Detail}})
def scan(user: User = Depends(current_user)):
    if not user.gmail_refresh_token_enc:
        raise HTTPException(409, "gmail not connected")
    try:
        return {"new_messages": poll_user(user.id)}
    except RefreshError:
        raise HTTPException(409, "gmail access was revoked, please reconnect")
    except Exception as e:
        log.warning("scan failed user=%s err=%s", user.id, type(e).__name__)
        raise HTTPException(502, "could not reach Gmail")


@router.get("/me/messages", response_model=MessageList, responses=AUTH,
            summary="My messages, riskiest first (URGENT, REVIEW, INSUFFICIENT_DATA, LOW, then newest)")
def my_messages(
    band: Band | None = None, channel: Channel | None = None,
    limit: int = Query(25, ge=1, le=100), cursor: str | None = None,
    user: User = Depends(current_user), db: Session = Depends(get_db),
):
    return list_messages(db, user, band, channel, limit, cursor)


@router.get("/me/reports", response_model=MessageList, responses=AUTH,
            summary="Messages I submitted via Check a message or WhatsApp, newest first")
def my_reports(
    band: Band | None = None, channel: Channel | None = None,
    limit: int = Query(25, ge=1, le=100), cursor: str | None = None,
    user: User = Depends(current_user), db: Session = Depends(get_db),
):
    return list_messages(db, user, band, channel, limit, cursor, reports_only=True)


@router.get("/me/messages/{message_id}", response_model=MessageDetail, responses=NOT_FOUND,
            summary="One message as plain text, with reasons, evidence and what to do")
def my_message(message_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return message_detail(db, get_own_message(db, user, message_id))


@router.post("/me/messages/{message_id}/escalate", response_model=EscalationOut,
             responses={**NOT_FOUND, 502: {"model": Detail, "description": "Email failed; nothing saved, retry"}},
             summary="Report to IT (idempotent: a second call returns the first escalation and sends nothing)")
def escalate(message_id: int, body: EscalateIn | None = None,
             user: User = Depends(current_user), db: Session = Depends(get_db)):
    m = get_own_message(db, user, message_id)
    note = (body.note.strip() or None) if body and body.note else None
    try:
        return escalate_message(db, user, m, note)[0]
    except EscalationFailed:
        raise HTTPException(502, "could not send the report to IT, please try again")


@router.post("/me/messages/{message_id}/feedback", response_model=FeedbackOut, responses=NOT_FOUND,
             summary='Mark "This is fine" (one per message, repeat calls just overwrite)')
def feedback(message_id: int, body: FeedbackIn, user: User = Depends(current_user),
             db: Session = Depends(get_db)):
    m = get_own_message(db, user, message_id)
    db.execute(pg_insert(Feedback).values(message_id=m.id, user_id=user.id, verdict=body.verdict)
               .on_conflict_do_update(index_elements=["user_id", "message_id"], set_={"verdict": body.verdict}))
    db.commit()
    return {"message_id": m.id, "verdict": body.verdict}
