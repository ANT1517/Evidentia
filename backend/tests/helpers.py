import itertools
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app.db import SessionLocal
from app.models import Assessment, Escalation, Feedback, Message, PendingReport, TwilioEvent, User
from app.services.pipeline import fallback, process_message
from shared.schemas import NormalizedMessage

DOMAIN = "@t4.test"  # every Phase 4 test user lives here, so purge() can find them
T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
_n = itertools.count(1)


def purge():
    with SessionLocal() as db:
        uids = list(db.scalars(select(User.id).where(User.email.like("%" + DOMAIN))))
        mids = list(db.scalars(select(Message.id).where(Message.user_id.in_(uids))))
        db.execute(delete(Feedback).where(Feedback.message_id.in_(mids)))
        db.execute(delete(Escalation).where(Escalation.message_id.in_(mids)))
        db.execute(delete(Assessment).where(Assessment.message_id.in_(mids)))
        db.execute(delete(Message).where(Message.id.in_(mids)))
        db.execute(delete(User).where(User.id.in_(uids)))
        db.execute(delete(PendingReport))  # test database only
        db.execute(delete(TwilioEvent))
        db.commit()


def make_user(name: str, local: str, admin: bool = False) -> int:
    with SessionLocal() as db:
        u = User(name=name, email=local + DOMAIN, title="Tester", is_admin=admin)
        db.add(u)
        db.commit()
        return u.id


def make_msg(uid, body="hello", subject=None, channel="email", hours=0, source="gmail",
             sender="x@y.test", urls=None, placeholder=False) -> int:
    """Stored through the real pipeline; the stub engine picks the band from the body text."""
    msg = NormalizedMessage(
        user_id=uid, channel=channel, external_id=f"t4-{next(_n)}", sender=sender, subject=subject,
        body_text="" if placeholder else body, urls=urls or [], attachments=[], headers={},
        received_at=T0 + timedelta(hours=hours),
    )
    with SessionLocal() as db:
        if placeholder:
            m, _ = process_message(db, msg, fallback("UNREADABLE", "We couldn't read this email"),
                                   source=source, readable=False)
        else:
            m, _ = process_message(db, msg, source=source)
        return m.id
