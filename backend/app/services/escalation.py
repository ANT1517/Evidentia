"""Report to IT: plain-text email with every URL defanged. Never HTML, never attachments."""
import logging
import re
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Assessment, Escalation, Message, User

log = logging.getLogger(__name__)

_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
MAX_BODY = 20_000


def defang(text: str) -> str:
    """http -> hxxp, and dots in the host -> [.] so nothing in the email is clickable."""
    def one(m: re.Match) -> str:
        scheme, rest = m.group(0).split("://", 1)
        host, tail = re.match(r"([^/?#]*)(.*)", rest, re.S).groups()
        return f"hxxp{scheme[4:]}://{host.replace('.', '[.]')}{tail}"

    return _URL.sub(one, text)


def _one_line(s: str, n: int) -> str:
    return " ".join(s.split())[:n]  # also blocks header injection via newlines


def build_email(user: User, m: Message, a: Assessment, note: str | None) -> EmailMessage:
    s = get_settings()
    subj = _one_line(m.subject or m.body_text or "(no subject)", 60)
    lines = [
        f"Reporter: {user.name} <{user.email}>",
        f"Title: {user.title or '-'}",
        f"Channel: {m.channel}   Source: {m.source}",
        f"Sender: {m.sender}",
        f"Display name: {m.sender_display_name or '-'}",
        f"Reply-To: {m.reply_to or '-'}",
        f"Received: {m.received_at.isoformat()}",
        f"Risk band: {a.risk_band}   Data completeness: {a.data_completeness}",
        "",
        "Reasons:",
    ]
    by_id = {e["evidence_id"]: e for e in a.evidence}
    used: set[str] = set()
    for r in a.reasons:
        lines.append(f"- [{r['code']}] {r['text']}")
        for eid in r.get("evidence_ids", []):
            used.add(eid)
            e = by_id.get(eid)
            if e:
                lines.append(f"    evidence {eid}: type={e['type']} value={e['value']} "
                             f"source={e['source']} status={e['status']}")
    if not a.reasons:
        lines.append("- (none)")
    rest = [e for e in a.evidence if e["evidence_id"] not in used]
    if rest:
        lines += ["", "Other evidence:"] + [
            f"- {e['evidence_id']}: type={e['type']} value={e['value']} source={e['source']} status={e['status']}"
            for e in rest]
    lines += ["", f"Employee note: {note or '-'}", "", "URLs:"]
    lines += [f"- {u}" for u in (m.urls or [])] or ["- (none)"]
    body = m.body_text or ""
    lines += ["", "Message (plain text):", "----------", body[:MAX_BODY]
              + ("\n[truncated]" if len(body) > MAX_BODY else ""), "----------"]

    msg = EmailMessage()
    msg["Subject"] = defang(f"[Evedentia][{a.risk_band}] Reported by {_one_line(user.name, 80)}: {subj}")
    msg["From"] = s.SMTP_FROM
    msg["To"] = s.IT_SECURITY_EMAIL
    msg.set_content(defang("\n".join(lines)), charset="utf-8")
    return msg


def send_escalation(user: User, m: Message, a: Assessment, note: str | None) -> str:
    """Send and return the recipient. Raises on any SMTP/network failure."""
    s = get_settings()
    msg = build_email(user, m, a, note)
    with smtplib.SMTP(s.SMTP_HOST, s.SMTP_PORT, timeout=10) as smtp:
        if s.SMTP_USER:
            smtp.starttls()
            smtp.login(s.SMTP_USER, s.SMTP_PASSWORD)
        smtp.send_message(msg)
    return s.IT_SECURITY_EMAIL


class EscalationFailed(Exception):
    """The email could not be sent; nothing was saved, so the caller can retry."""


def escalate_message(db: Session, user: User, m: Message, note: str | None) -> tuple[Escalation, bool]:
    """Report one of the user's messages to IT. Returns (escalation, created); idempotent."""
    from app.services.messages import get_assessment  # local import: messages has no dependency on this module

    db.execute(select(Message.id).where(Message.id == m.id).with_for_update())  # concurrent taps send one email
    existing = db.scalar(select(Escalation).where(Escalation.message_id == m.id))
    if existing:
        return existing, False
    try:
        sent_to = send_escalation(user, m, get_assessment(db, m), note)
    except Exception as e:
        db.rollback()
        log.warning("escalation email failed user=%s msg=%s err=%s", user.id, m.id, type(e).__name__)
        raise EscalationFailed from e
    esc = Escalation(message_id=m.id, user_id=user.id, sent_to=sent_to,
                     sent_at=datetime.now(timezone.utc), employee_note=note)
    db.add(esc)
    db.commit()
    return esc, True
