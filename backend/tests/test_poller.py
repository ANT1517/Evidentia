import asyncio
import base64
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from google.auth.exceptions import RefreshError
from sqlalchemy import delete, select

from app.db import SessionLocal
from app.deps import create_session_token
from app.main import app
from app.models import Assessment, Message, User
from app.services import pipeline
from app.services.crypto import encrypt
from app.workers import gmail_poller as poller

FIX = Path(__file__).parent / "fixtures"
EMAILS = ["poll-a@corp.test", "poll-b@corp.test"]


class _Exec:
    def __init__(self, v):
        self.v = v

    def execute(self):
        return self.v


class FakeGmail:
    """Minimal stand-in for the Gmail API client: users().messages().list/get."""

    def __init__(self, files=("phish_reset.eml", "normal.eml")):
        self.raw = {f"g-{f}": (FIX / f).read_bytes() for f in files}

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, **kw):
        assert kw["labelIds"] == ["INBOX"] and kw["maxResults"] == 25 and kw["q"].startswith("after:")
        return _Exec({"messages": [{"id": i} for i in self.raw]})

    def get(self, userId, id, format):
        assert format == "raw"
        return _Exec({"raw": base64.urlsafe_b64encode(self.raw[id]).decode().rstrip("=")})


def _purge():
    with SessionLocal() as db:
        ids = list(db.scalars(select(User.id).where(User.email.in_(EMAILS))))
        mids = list(db.scalars(select(Message.id).where(Message.user_id.in_(ids))))
        db.execute(delete(Assessment).where(Assessment.message_id.in_(mids)))
        db.execute(delete(Message).where(Message.id.in_(mids)))
        db.execute(delete(User).where(User.id.in_(ids)))
        db.commit()


@pytest.fixture
def users():
    _purge()
    with SessionLocal() as db:
        us = [User(name=e, email=e, gmail_refresh_token_enc=encrypt("rt"),
                   gmail_connected_at=datetime.now(timezone.utc)) for e in EMAILS]
        db.add_all(us)
        db.commit()
        ids = [u.id for u in us]
    yield ids
    _purge()


def _rows(uid):
    with SessionLocal() as db:
        return list(db.execute(
            select(Message.external_id, Assessment.risk_band)
            .join(Assessment, Assessment.message_id == Message.id).where(Message.user_id == uid)))


def test_poll_stores_two_messages_and_is_idempotent(users, monkeypatch):
    monkeypatch.setattr(poller, "build_service", lambda user: FakeGmail())
    assert poller.poll_user(users[0]) == 2
    got = dict(_rows(users[0]))
    assert got == {"g-phish_reset.eml": "URGENT", "g-normal.eml": "LOW"}
    assert poller.poll_user(users[0]) == 0
    assert len(_rows(users[0])) == 2
    with SessionLocal() as db:
        u = db.get(User, users[0])
        assert u.last_polled_at is not None
        m = db.scalar(select(Message).where(Message.external_id == "g-normal.eml", Message.user_id == u.id))
        assert m.channel == "email" and m.sender == "alice@corp.test" and "lunch" in m.body_text


def test_engine_exception_gives_insufficient_data(users, monkeypatch):
    def boom(msg):
        raise RuntimeError("engine down")

    monkeypatch.setattr(pipeline, "analyze", boom)
    monkeypatch.setattr(poller, "build_service", lambda user: FakeGmail(("phish_reset.eml",)))
    assert poller.poll_user(users[0]) == 1
    with SessionLocal() as db:
        a = db.scalar(select(Assessment).join(Message).where(Message.user_id == users[0]))
    assert a.risk_band == "INSUFFICIENT_DATA" and a.data_completeness == "UNKNOWN"
    assert a.reasons[0]["text"] == "We couldn't fully check this message"


def test_engine_timeout_gives_insufficient_data(users, monkeypatch):
    monkeypatch.setattr(pipeline, "ANALYZE_TIMEOUT", 0.1)
    monkeypatch.setattr(pipeline, "analyze", lambda msg: time.sleep(1))
    monkeypatch.setattr(poller, "build_service", lambda user: FakeGmail(("normal.eml",)))
    poller.poll_user(users[0])
    assert _rows(users[0])[0].risk_band == "INSUFFICIENT_DATA"


def test_one_users_failure_does_not_block_another(users, monkeypatch):
    def build(user):
        if user.id == users[0]:
            raise RuntimeError("api error")
        return FakeGmail()

    monkeypatch.setattr(poller, "build_service", build)
    asyncio.run(poller.poll_all())
    assert _rows(users[0]) == [] and len(_rows(users[1])) == 2


def test_invalid_grant_marks_disconnected(users, monkeypatch):
    def build(user):
        raise RefreshError("invalid_grant: Token has been expired or revoked.")

    monkeypatch.setattr(poller, "build_service", build)
    with pytest.raises(RefreshError):
        poller.poll_user(users[0])
    with SessionLocal() as db:
        u = db.get(User, users[0])
        assert u.gmail_refresh_token_enc is None and u.gmail_connected_at is None


def test_scan_endpoint(users, monkeypatch):
    monkeypatch.setattr(poller, "build_service", lambda user: FakeGmail())
    c = TestClient(app, base_url="http://localhost:8000")
    assert c.post("/scan").status_code == 401
    c.cookies.set("ev_session", create_session_token(users[0]))
    assert c.post("/scan").json() == {"new_messages": 2}
    assert c.post("/scan").json() == {"new_messages": 0}


def test_unparseable_email_stored_as_insufficient_data_and_never_retried(users, monkeypatch):
    calls = []

    def bad_parse(raw, user_id, external_id):
        calls.append(external_id)
        raise ValueError("garbage")

    monkeypatch.setattr(pipeline, "parse_mime", bad_parse)
    monkeypatch.setattr(poller, "build_service", lambda user: FakeGmail(("phish_reset.eml",)))
    assert poller.poll_user(users[0]) == 1
    with SessionLocal() as db:
        m, a = db.execute(select(Message, Assessment).join(Assessment, Assessment.message_id == Message.id)
                          .where(Message.user_id == users[0])).one()
    assert m.sender == "helpdesk@c0rp-support.test" and m.subject == "Password reset required"
    assert a.risk_band == "INSUFFICIENT_DATA" and a.data_completeness == "UNKNOWN"
    assert a.reasons[0]["text"] == "We couldn't read this email"
    assert poller.poll_user(users[0]) == 0 and len(calls) == 1  # not retried


def test_unreadable_headers_fall_back_to_unknown(users, monkeypatch):
    class Junk(FakeGmail):
        def get(self, userId, id, format):
            return _Exec({"raw": "!!!not base64!!!"})

    monkeypatch.setattr(poller, "build_service", lambda user: Junk(("normal.eml",)))
    assert poller.poll_user(users[0]) == 1
    with SessionLocal() as db:
        m = db.scalar(select(Message).where(Message.user_id == users[0]))
    assert m.sender == "unknown" and m.subject == "unknown"
