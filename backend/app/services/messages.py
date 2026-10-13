"""Queries and serializers behind the /me/* and /check responses."""
import base64
import json
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import case, exists, or_, select
from sqlalchemy.orm import Session

from app.models import Assessment, Escalation, Feedback, Message, User

BAND_RANK = {"URGENT": 0, "REVIEW": 1, "INSUFFICIENT_DATA": 2, "LOW": 3}
UNREADABLE_PREVIEW = "Couldn't read this email"

WHAT_TO_DO = {
    "URGENT": ["Don't click any links", "Don't reply or send money", "Report this to IT"],
    "REVIEW": ["Verify with the sender another way, like a phone call",
               "Don't enter passwords from this message"],
    "INSUFFICIENT_DATA": ["We couldn't fully check this. Ask IT if you're unsure"],
    "LOW": ["No warning signs found. Stay alert anyway"],
}


def encode_cursor(*parts) -> str:
    return base64.urlsafe_b64encode(json.dumps(parts).encode()).decode()


def decode_cursor(cursor: str) -> list:
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()))
    except Exception:
        raise HTTPException(400, "invalid cursor")


def preview(m: Message) -> str:
    subject = (m.subject or "").strip()
    if subject and not (not m.readable and subject == "unknown"):
        return subject
    body = " ".join((m.body_text or "").split())[:120]
    return body or UNREADABLE_PREVIEW


def _escalated():
    return exists().where(Escalation.message_id == Message.id).label("escalated")


def _item(m: Message, a: Assessment, escalated: bool) -> dict:
    return {
        "id": m.id, "channel": m.channel, "source": m.source, "sender": m.sender,
        "sender_display_name": m.sender_display_name, "preview": preview(m),
        "received_at": m.received_at, "risk_band": a.risk_band,
        "top_reason": a.reasons[0]["text"] if a.reasons else None,
        "colleague_count": a.colleague_count, "escalated": escalated, "readable": m.readable,
    }


def list_messages(db: Session, user: User, band: str | None, channel: str | None, limit: int,
                  cursor: str | None, reports_only: bool = False) -> dict:
    """Inbox order: band severity, then received_at desc. Reports order: newest submission first."""
    q = (select(Message, Assessment, _escalated())
         .join(Assessment, Assessment.message_id == Message.id).where(Message.user_id == user.id))
    if band:
        q = q.where(Assessment.risk_band == band)
    if channel:
        q = q.where(Message.channel == channel)
    c = decode_cursor(cursor) if cursor else None
    try:
        if reports_only:
            q = q.where(Message.source != "gmail")
            if c:
                t = datetime.fromisoformat(c[0])
                q = q.where(or_(Message.created_at < t, (Message.created_at == t) & (Message.id < c[1])))
            q = q.order_by(Message.created_at.desc(), Message.id.desc())
        else:
            rank = case(BAND_RANK, value=Assessment.risk_band, else_=9)
            if c:
                t = datetime.fromisoformat(c[1])
                q = q.where(or_(rank > c[0],
                                (rank == c[0]) & (Message.received_at < t),
                                (rank == c[0]) & (Message.received_at == t) & (Message.id < c[2])))
            q = q.order_by(rank, Message.received_at.desc(), Message.id.desc())
    except (ValueError, TypeError, IndexError):
        raise HTTPException(400, "invalid cursor")
    rows = db.execute(q.limit(limit + 1)).all()
    page, more = rows[:limit], len(rows) > limit
    nxt = None
    if more:
        m, a, _ = page[-1]
        nxt = (encode_cursor(m.created_at.isoformat(), m.id) if reports_only
               else encode_cursor(BAND_RANK.get(a.risk_band, 9), m.received_at.isoformat(), m.id))
    return {"items": [_item(m, a, e) for m, a, e in page], "next_cursor": nxt}


def get_own_message(db: Session, user: User, message_id: int, lock: bool = False) -> Message:
    """Someone else's message is indistinguishable from a missing one (404)."""
    q = select(Message).where(Message.id == message_id, Message.user_id == user.id)
    m = db.scalar(q.with_for_update() if lock else q)
    if not m:
        raise HTTPException(404, "message not found")
    return m


def get_assessment(db: Session, m: Message) -> Assessment:
    return db.scalars(select(Assessment).where(Assessment.message_id == m.id)
                      .order_by(Assessment.id.desc())).first()


def message_detail(db: Session, m: Message, a: Assessment | None = None) -> dict:
    a = a or get_assessment(db, m)
    esc = db.scalar(select(Escalation).where(Escalation.message_id == m.id))
    fb = db.scalar(select(Feedback.verdict).where(Feedback.message_id == m.id, Feedback.user_id == m.user_id))
    return {
        "id": m.id, "channel": m.channel, "source": m.source, "sender": m.sender,
        "sender_display_name": m.sender_display_name, "reply_to": m.reply_to, "subject": m.subject,
        "body_text": m.body_text, "urls": list(m.urls or []), "attachments": m.attachments or [],
        "received_at": m.received_at, "readable": m.readable,
        "assessment": {
            "risk_band": a.risk_band, "reasons": a.reasons, "evidence": a.evidence,
            "data_completeness": a.data_completeness, "model_versions": a.model_versions,
            "colleague_count": a.colleague_count,
        },
        "escalated_at": esc.sent_at if esc else None, "feedback": fb,
        "what_to_do": WHAT_TO_DO[a.risk_band],
    }
