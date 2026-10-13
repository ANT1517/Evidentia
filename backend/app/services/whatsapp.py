"""WhatsApp bot logic (Twilio sandbox). The webhook in api/webhooks.py is a thin wrapper around this.

Message text is attacker-controlled data: a command is only recognised when the WHOLE message is the
command, and nothing in a message can change what the bot does. Links are never opened.
"""
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client

from app.config import get_settings
from app.db import SessionLocal
from app.models import Escalation, Message, PendingReport, User
from app.services.directory import normalize_phone
from app.services.escalation import EscalationFailed, defang, escalate_message
from app.services.messages import WHAT_TO_DO, get_assessment
from app.services.pipeline import process_message
from shared.schemas import NormalizedMessage

log = logging.getLogger(__name__)

MAX_TEXT = 5000
MAX_NOTE = 500
MAX_REPLY = 1500
PENDING_TTL = timedelta(minutes=15)

UNKNOWN_NUMBER = ("This number isn't registered with Evedentia. "
                  "Add your WhatsApp number in the Evedentia app settings.")
MEDIA_ONLY = "Please paste or share the message text. Images aren't checked yet."
TOO_LONG = f"That message is too long (max {MAX_TEXT:,} characters). Please send a shorter part of it."
ASK_SENDER = ("Got it. Who sent this? Reply with the sender's name, ID (like JD-SBIINB) or number. "
              "Reply skip if you don't know.")
CHECKING = "Checking..."
RESTART = "Okay, starting over. Share the suspicious message (paste it or share it here)."
HELP = ("Evedentia can check a suspicious SMS or WhatsApp message.\n"
        "1. Share or paste the message here.\n"
        "2. Tell me who sent it (or reply skip).\n"
        "Commands: report (start over), status (last result), escalate [note] (send the last one to IT), help.")
NOTHING_YET = "You haven't checked a message here yet. Share one to start."
ESCALATED = "Sent to IT. They'll follow up if needed."
ALREADY = "Already sent to IT."
IT_DOWN = "Couldn't reach IT right now, try again."
CHECK_FAILED_TEXT = "We couldn't fully check this message."

_HEAD = {"URGENT": "🔴 URGENT", "REVIEW": "🟠 REVIEW", "LOW": "🟢 LOW", "INSUFFICIENT_DATA": "⚪ COULDN'T FULLY CHECK"}
_URL = re.compile(r"https?://[^\s<>\"')]+")
_WA_MARKER = re.compile(r"(?im)^\s*(forwarded\b|\[?\d{1,2}/\d{1,2}/\d{2,4},?\s+\d{1,2}:\d{2})")
_SIMPLE_CMD = re.compile(r"^\s*(help|report|status)\s*$", re.I)
_ESCALATE_CMD = re.compile(r"^\s*escalate(?:\s+(.*))?$", re.I | re.S)


def last4(number: str) -> str:
    return (number or "")[-4:]


@dataclass
class Reply:
    text: str | None = None  # sent back immediately as TwiML
    job: Callable[[], None] | None = None  # runs after the response (own DB session)


# ---------- helpers ----------

def parse_command(body: str) -> tuple[str, str | None] | None:
    """Whole-message commands only. 'please escalate this' is NOT a command."""
    m = _SIMPLE_CMD.match(body)
    if m:
        return m.group(1).lower(), None
    m = _ESCALATE_CMD.match(body)
    if m:
        note = (m.group(1) or "").strip()
        if len(note) <= MAX_NOTE:  # a long text that merely starts with the word is a report, not a command
            return "escalate", note or None
    return None


def find_employee(db: Session, from_number: str) -> User | None:
    num = from_number.removeprefix("whatsapp:").strip()
    num = normalize_phone(num) or num
    return (db.scalar(select(User).where(User.whatsapp_number == num))
            or db.scalar(select(User).where(User.phone == num)))


def format_result(band: str, reasons: list[str], colleague_count: int, escalated: bool = False) -> str:
    lines = [_HEAD.get(band, _HEAD["INSUFFICIENT_DATA"])]
    lines += [f"- {r[:200]}" for r in reasons[:3]]
    lines += WHAT_TO_DO.get(band, WHAT_TO_DO["INSUFFICIENT_DATA"])[:2]
    if colleague_count > 0:
        lines.append(f"Also sent to {colleague_count} colleagues")
    if escalated:
        lines.append(ALREADY)
    elif band != "LOW":
        lines.append("Reply escalate to send this to IT.")
    text = defang("\n".join(lines))  # reasons may quote links from the message
    return text if len(text) <= MAX_REPLY else text[:MAX_REPLY - 3] + "..."


def couldnt_check_text() -> str:
    return format_result("INSUFFICIENT_DATA", [CHECK_FAILED_TEXT], 0)


def _last_whatsapp_message(db: Session, user_id: int) -> Message | None:
    return db.scalars(select(Message).where(Message.user_id == user_id, Message.source == "whatsapp")
                      .order_by(Message.created_at.desc(), Message.id.desc())).first()


def _wa(number: str) -> str:
    return number if number.startswith("whatsapp:") else f"whatsapp:{number}"


def send_whatsapp(to: str, body: str) -> None:
    """Send via the Twilio REST API. Failures are logged by category and never raised."""
    s = get_settings()
    try:
        Client(s.TWILIO_ACCOUNT_SID, s.TWILIO_AUTH_TOKEN).messages.create(
            from_=_wa(s.TWILIO_WHATSAPP_FROM), to=_wa(to), body=body[:MAX_REPLY])
    except TwilioRestException as e:
        log.warning("twilio send failed to=***%s status=%s code=%s", last4(to), e.status, e.code)
    except Exception as e:
        log.warning("twilio send failed to=***%s err=%s", last4(to), type(e).__name__)


# ---------- background jobs (own DB session, never raise) ----------

def _check_job(user_id: int, to: str, msg: NormalizedMessage) -> None:
    try:
        with SessionLocal() as db:
            m, a = process_message(db, msg, source="whatsapp")
            text = format_result(a.risk_band, [r["text"] for r in a.reasons], a.colleague_count)
    except Exception as e:  # never LOW on failure
        log.warning("whatsapp check failed user=%s err=%s", user_id, type(e).__name__)
        text = couldnt_check_text()
    send_whatsapp(to, text)


def _escalate_job(user_id: int, to: str, note: str | None) -> None:
    try:
        with SessionLocal() as db:
            user = db.get(User, user_id)
            m = _last_whatsapp_message(db, user_id)
            if not m:
                text = NOTHING_YET
            else:
                try:
                    text = ESCALATED if escalate_message(db, user, m, note)[1] else ALREADY
                except EscalationFailed:
                    text = IT_DOWN
    except Exception as e:
        log.warning("whatsapp escalate failed user=%s err=%s", user_id, type(e).__name__)
        text = IT_DOWN
    send_whatsapp(to, text)


# ---------- the conversation ----------

def handle_message(db: Session, user: User, from_number: str, sid: str, body: str, num_media: int) -> Reply:
    """Cheap, synchronous state machine. Heavy work is returned as a job."""
    body = (body or "").strip()
    if num_media > 0 and not body:
        return Reply(MEDIA_ONLY)

    cmd = parse_command(body)
    if cmd:
        name, note = cmd
        if name == "help":
            return Reply(HELP)
        if name == "report":
            db.execute(delete(PendingReport).where(PendingReport.whatsapp_number == from_number))
            return Reply(RESTART)
        if name == "status":
            m = _last_whatsapp_message(db, user.id)
            if not m:
                return Reply(NOTHING_YET)
            a = get_assessment(db, m)
            done = db.scalar(select(Escalation.id).where(Escalation.message_id == m.id)) is not None
            return Reply(format_result(a.risk_band, [r["text"] for r in a.reasons], a.colleague_count, done))
        uid = user.id
        return Reply(None, lambda: _escalate_job(uid, from_number, note))

    now = datetime.now(timezone.utc)
    pending = db.get(PendingReport, from_number)
    fresh = pending is not None and pending.stage == "awaiting_sender" and now - pending.updated_at < PENDING_TTL

    if not fresh:  # start a report (a stale pending row is replaced)
        if len(body) > MAX_TEXT:
            return Reply(TOO_LONG)
        if not body:
            return Reply(HELP)
        if pending is None:
            pending = PendingReport(whatsapp_number=from_number)
            db.add(pending)
        pending.message_text, pending.stage, pending.message_sid, pending.updated_at = body, "awaiting_sender", sid, now
        return Reply(ASK_SENDER)

    sender = body[:200]
    channel = "sms"
    if sender.lower() == "skip":
        sender = "unknown"
    elif sender.lower().startswith("wa "):
        sender, channel = sender[3:].strip() or "unknown", "whatsapp"
    if channel == "sms" and _WA_MARKER.search(pending.message_text):
        channel = "whatsapp"
    text = pending.message_text
    msg = NormalizedMessage(
        user_id=user.id, channel=channel, external_id=pending.message_sid or sid, sender=sender,
        body_text=text, urls=list(dict.fromkeys(u.rstrip(".,;:!?") for u in _URL.findall(text))),
        attachments=[], headers={}, received_at=now,
    )
    db.delete(pending)
    uid = user.id
    return Reply(CHECKING, lambda: _check_job(uid, from_number, msg))
