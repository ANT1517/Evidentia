"""Demo data for the frontend and for demos:  python -m app.seed [--me you@gmail.com]

Idempotent: safe to run again. Messages go through the real pipeline, so bands come from whatever
engine is installed (the stub today). `--me` makes your own Google account the first (admin) employee,
so you see the demo messages after signing in.
"""
import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import get_settings
from app.db import SessionLocal
from app.models import Escalation, Message, User
from app.services.directory import normalize_phone
from app.services.pipeline import fallback, process_message
from shared.schemas import NormalizedMessage

CEO_BODY = ("Hi, are you at your desk? I'm in a meeting and need you to change the bank details for our vendor "
            "Acme Supplies before 5pm today. New account 50100234567890, IFSC HDFC0001234. Keep this between us.")
CEO_SUBJECT = "Quick favour: vendor bank change"

EMPLOYEES = [  # name, title, email, phone, admin
    ("Asha Rao", "Finance Manager", "asha.rao@demo.evedentia.test", "+91 98765 43210", True),
    ("Ravi Kumar", "Accounts Executive", "ravi.kumar@demo.evedentia.test", "+91 91234 56789", False),
    ("Meera Iyer", "HR Associate", "meera.iyer@demo.evedentia.test", "+91 99887 76655", False),
]

# (employee index, key, hours ago, channel, source, sender, display name, reply_to, subject, body, urls, placeholder)
MESSAGES = [
    (0, "ms-phish", 2, "email", "gmail", "no-reply@micros0ft-security.example.com", "Microsoft Account Team",
     "helpdesk@gmail-mail.example.net", "Your password expires today",
     "Your Microsoft password expires today. Confirm your password within 24 hours: "
     "http://micros0ft-security.example.com/login?u=asha", ["http://micros0ft-security.example.com/login?u=asha"], False),
    (0, "ceo-bank", 5, "email", "gmail", "ceo.mgmt@acme-corp-mail.example.com", "Priya Nair (CEO)",
     "priya.nair.ceo@gmail.example.com", CEO_SUBJECT, CEO_BODY, [], False),
    (1, "ceo-bank", 5, "email", "gmail", "ceo.mgmt@acme-corp-mail.example.com", "Priya Nair (CEO)",
     "priya.nair.ceo@gmail.example.com", CEO_SUBJECT, CEO_BODY, [], False),
    (0, "review", 8, "email", "gmail", "accounts@vendor-billing.example.com", "Vendor Billing", None,
     "Urgent: invoice #4821 overdue", "This is an urgent reminder that invoice 4821 is overdue. Please pay this week.",
     [], False),
    (0, "low-lunch", 26, "email", "gmail", "meera.iyer@demo.evedentia.test", "Meera Iyer", None, "Lunch on Friday?",
     "Are we still on for lunch at noon on Friday?", [], False),
    (0, "low-invoice", 30, "email", "gmail", "billing@known-vendor.example.com", "Known Vendor", None,
     "Invoice 4799 due Friday", "Attached is invoice 4799 for last month's services, due Friday as agreed.", [], False),
    (0, "empty", 40, "email", "gmail", "newsletter@promo.example.com", "Promo", None, "(image only)", "", [], False),
    (0, "unreadable", 50, "email", "gmail", "unknown", None, None, "unknown", "", [], True),
    (0, "kyc-sms", 3, "sms", "whatsapp", "+91 90000 11122", None, None, None,
     "Dear customer your SBI KYC expires today. Update your password at http://sbi-kyc-update.example.com/x or your "
     "account will be blocked.", ["http://sbi-kyc-update.example.com/x"], False),
    (0, "new-number", 1, "whatsapp", "check", "+91 90000 33344", None, None, None,
     "Hi, it's Priya, new number. Can you do me a quick favour? Need to pay a vendor, send bank details.", [], False),
    (2, "meera-low", 6, "email", "gmail", "hr@corp.example.com", "HR Team", None, "Benefits enrolment reminder",
     "Open enrolment closes on the 31st.", [], False),
]


def seed(me: str | None = None) -> dict:
    now = datetime.now(timezone.utc)
    created = {"users": 0, "messages": 0}
    with SessionLocal() as db:
        users: list[User] = []
        for i, (name, title, email, phone, admin) in enumerate(EMPLOYEES):
            if i == 0 and me:
                email = me.lower()
            u = db.scalar(select(User).where(User.email == email))
            if not u:
                u = User(name=name, email=email)
                db.add(u)
                created["users"] += 1
            u.title, u.phone, u.is_admin = title, normalize_phone(phone), admin
            db.flush()
            users.append(u)
        db.commit()

        for idx, key, hours, channel, source, sender, display, reply_to, subject, body, urls, placeholder in MESSAGES:
            u = users[idx]
            ext = f"seed-{key}-{u.id}"
            if db.scalar(select(Message.id).where(Message.user_id == u.id, Message.channel == channel,
                                                  Message.external_id == ext)):
                continue
            msg = NormalizedMessage(
                user_id=u.id, channel=channel, external_id=ext, sender=sender, sender_display_name=display,
                reply_to=reply_to, subject=subject, body_text=body, urls=urls, attachments=[], headers={},
                received_at=now - timedelta(hours=hours))
            try:
                if placeholder:
                    process_message(db, msg, fallback("UNREADABLE", "We couldn't read this email"),
                                    source=source, readable=False)
                else:
                    process_message(db, msg, source=source)
                created["messages"] += 1
            except IntegrityError:
                db.rollback()

        # one already-escalated message so the UI shows that state (no email is sent)
        m = db.scalar(select(Message).where(Message.user_id == users[0].id,
                                            Message.external_id == f"seed-ms-phish-{users[0].id}"))
        if m and not db.scalar(select(Escalation.id).where(Escalation.message_id == m.id)):
            db.add(Escalation(message_id=m.id, user_id=users[0].id, sent_to=get_settings().IT_SECURITY_EMAIL,
                              sent_at=now - timedelta(hours=1), employee_note="Looks like a fake login page"))
            db.commit()
    return created


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--me", help="your Google email: used instead of the first demo employee")
    r = seed(ap.parse_args().me)
    print(f"seeded: {r['users']} new employees, {r['messages']} new messages (re-running adds nothing)")
