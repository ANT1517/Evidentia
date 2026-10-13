import itertools
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update
from twilio.request_validator import RequestValidator

from app.config import get_settings
from app.db import SessionLocal
from app.main import app
from app.models import Escalation, Message, PendingReport, User
from app.services import escalation as esc_mod
from app.services import pipeline
from app.services import whatsapp as bot
from shared.schemas import Assessment, Reason
from tests.helpers import make_user, purge

TOKEN = "test-twilio-token"
URL = "http://localhost:8000/webhooks/twilio/whatsapp"
NUMBER = "+919999900001"
FROM = f"whatsapp:{NUMBER}"
_sid = itertools.count(1)
SCAM = "Dear customer your SBI KYC expires today. Update your password at http://sbi-kyc-update.example.com/x now"


class FakeTwilio:
    sent: list = []
    fail = False

    def __init__(self, sid, token):
        pass

    @property
    def messages(self):
        return self

    def create(self, **kw):
        if FakeTwilio.fail:
            raise ConnectionError("twilio down")
        FakeTwilio.sent.append(kw)


class FakeSMTP:
    sent: list = []
    fail = False

    def __init__(self, host, port, timeout=None):
        if FakeSMTP.fail:
            raise ConnectionRefusedError("smtp down")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


@pytest.fixture(autouse=True)
def env(monkeypatch):
    purge()
    FakeTwilio.sent, FakeTwilio.fail, FakeSMTP.sent, FakeSMTP.fail = [], False, [], False
    monkeypatch.setattr(bot, "Client", FakeTwilio)
    monkeypatch.setattr(esc_mod.smtplib, "SMTP", FakeSMTP)
    yield
    purge()


@pytest.fixture
def uid():
    u = make_user("Test Employee", "wa")
    with SessionLocal() as db:
        db.execute(update(User).where(User.id == u).values(whatsapp_number=NUMBER))
        db.commit()
    return u


def post(body="", sid=None, from_=FROM, media=0, sign=True, query=""):
    params = {"From": from_, "Body": body, "MessageSid": sid or f"SMtest{next(_sid)}", "NumMedia": str(media)}
    headers = {}
    if sign:
        headers["X-Twilio-Signature"] = RequestValidator(TOKEN).compute_signature(URL + query, params)
    return TestClient(app, base_url="http://localhost:8000").post(
        "/webhooks/twilio/whatsapp" + query, data=params, headers=headers)


def reply_text(r) -> str:
    m = re.search(r"<Message>(.*?)</Message>", r.text, re.S)
    return m.group(1).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&#x27;", "'") if m else ""


def sent_bodies():
    return [k["body"] for k in FakeTwilio.sent]


def run_report(text=SCAM, sender="JD-SBIINB"):
    sid = f"SMtest{next(_sid)}"
    post(text, sid=sid)
    return sid, post(sender)


def stub_assessment(monkeypatch, reasons, band="URGENT", colleagues=0):
    a = Assessment(risk_band=band, reasons=[Reason(code="X", text=t, evidence_ids=[]) for t in reasons],
                   evidence=[], data_completeness="COMPLETE", model_versions={"engine": "t"},
                   colleague_count=colleagues)
    monkeypatch.setattr(pipeline, "analyze", lambda msg: a)


def _count(model, *where):
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(model).where(*where))


# ---------- webhook security ----------

def test_bad_or_missing_signature_is_403(uid):
    assert post("hi", sign=False).status_code == 403
    r = TestClient(app, base_url="http://localhost:8000").post(
        "/webhooks/twilio/whatsapp", data={"From": FROM, "Body": "hi", "MessageSid": "SMx"},
        headers={"X-Twilio-Signature": "bogus"})
    assert r.status_code == 403
    assert _count(PendingReport) == 0


def test_signature_covers_the_query_string(uid):
    assert post("hi", query="?x=1").status_code == 200
    params = {"From": FROM, "Body": "hi", "MessageSid": "SMq", "NumMedia": "0"}
    sig = RequestValidator(TOKEN).compute_signature(URL, params)  # signed without the query
    r = TestClient(app, base_url="http://localhost:8000").post(
        "/webhooks/twilio/whatsapp?x=1", data=params, headers={"X-Twilio-Signature": sig})
    assert r.status_code == 403


def test_missing_twilio_settings_is_503(monkeypatch, uid):
    monkeypatch.setattr(get_settings(), "TWILIO_AUTH_TOKEN", "")
    assert post("hi").status_code == 503


# ---------- who is this ----------

def test_unknown_number(uid):
    r = post("hi", from_="whatsapp:+919999900099")
    assert r.status_code == 200 and "isn't registered with Evedentia" in reply_text(r)
    assert _count(PendingReport) == 0


def test_phone_column_is_a_fallback(uid):
    with SessionLocal() as db:
        db.execute(update(User).where(User.id == uid).values(whatsapp_number=None, phone=NUMBER))
        db.commit()
    assert "Who sent this?" in reply_text(post(SCAM))


# ---------- the flow ----------

def test_full_flow_message_sender_result(uid):
    sid, _ = None, None
    sid = f"SMtest{next(_sid)}"
    r1 = post(SCAM, sid=sid)
    assert "Who sent this?" in reply_text(r1) and "skip" in reply_text(r1)
    assert _count(PendingReport) == 1
    r2 = post("JD-SBIINB")
    assert reply_text(r2) == "Checking..."
    assert _count(PendingReport) == 0

    assert len(FakeTwilio.sent) == 1
    out = FakeTwilio.sent[0]
    assert out["from_"] == "whatsapp:+14155238886" and out["to"] == FROM
    assert out["body"].startswith("🔴 URGENT\n- Asks for login or bank details.\n")
    assert "Don't click any links" in out["body"] and "Reply escalate to send this to IT." in out["body"]

    with SessionLocal() as db:
        m = db.scalar(select(Message).where(Message.user_id == uid))
    assert (m.source, m.channel, m.sender, m.external_id) == ("whatsapp", "sms", "JD-SBIINB", sid)
    assert m.urls == ["http://sbi-kyc-update.example.com/x"] and m.body_text == SCAM


def test_skip_and_channel_detection(uid):
    run_report(sender="skip")
    run_report(sender="wa +91 98765 43210")
    run_report(text="Forwarded\nhello there", sender="Rahul")
    with SessionLocal() as db:
        rows = db.execute(select(Message.sender, Message.channel).where(Message.user_id == uid)
                          .order_by(Message.id)).all()
    assert rows == [("unknown", "sms"), ("+91 98765 43210", "whatsapp"), ("Rahul", "whatsapp")]


def test_long_message_rejected(uid):
    r = post("a" * 5001)
    assert "too long" in reply_text(r) and _count(PendingReport) == 0
    assert "Who sent this?" in reply_text(post("a" * 5000))


def test_media_only_message(uid):
    r = post("", media=1)
    assert reply_text(r) == "Please paste or share the message text. Images aren't checked yet."
    assert _count(PendingReport) == 0


def test_status_command(uid):
    assert "haven't checked" in reply_text(post("status"))
    run_report()
    assert reply_text(post("STATUS")) == FakeTwilio.sent[0]["body"]


def test_pending_expires_after_15_minutes(uid):
    post("first message")
    with SessionLocal() as db:
        db.execute(update(PendingReport).values(updated_at=datetime.now(timezone.utc) - timedelta(minutes=16)))
        db.commit()
    r = post("second message")  # treated as a NEW report, not as the sender of the first
    assert "Who sent this?" in reply_text(r) and FakeTwilio.sent == []
    with SessionLocal() as db:
        assert db.scalar(select(PendingReport.message_text)) == "second message"


def test_duplicate_message_sid_is_ignored(uid):
    sid = f"SMtest{next(_sid)}"
    post(SCAM, sid=sid)
    sender_sid = f"SMtest{next(_sid)}"
    post("JD-SBIINB", sid=sender_sid)
    again = post("JD-SBIINB", sid=sender_sid)  # Twilio retry
    assert reply_text(again) == "" and len(FakeTwilio.sent) == 1
    assert _count(Message, Message.user_id == uid) == 1
    dup_first = post(SCAM, sid=sid)  # retry of the very first message
    assert reply_text(dup_first) == "" and _count(PendingReport) == 0


# ---------- commands ----------

def test_help_and_report_commands(uid):
    assert "Commands:" in reply_text(post("help"))
    post("some text")
    assert _count(PendingReport) == 1
    assert "starting over" in reply_text(post("Report"))
    assert _count(PendingReport) == 0


@pytest.mark.parametrize("text", [
    "please escalate this now", "help me my account is blocked", "Report: your parcel is held, pay at http://x.test",
    "status update: urgent wire", "Escalate " + "x" * 600,
])
def test_command_words_inside_a_message_do_not_trigger_commands(uid, text):
    r = post(text)
    assert "Who sent this?" in reply_text(r)
    assert FakeSMTP.sent == [] and _count(Escalation) == 0 and FakeTwilio.sent == []


def test_escalate_sent_then_already_sent(uid):
    run_report()
    FakeTwilio.sent.clear()
    assert reply_text(post("escalate looks like a scam")) == ""  # confirmation arrives via REST
    assert sent_bodies() == [bot.ESCALATED]
    assert len(FakeSMTP.sent) == 1
    mail = FakeSMTP.sent[0]
    body = mail.get_content()
    assert "looks like a scam" in body and "hxxp://sbi-kyc-update[.]example[.]com/x" in body
    assert mail["Subject"].startswith("[Evedentia][URGENT] Reported by Test Employee")
    post("ESCALATE")
    assert sent_bodies()[-1] == "Already sent to IT." and len(FakeSMTP.sent) == 1
    assert _count(Escalation) == 1
    assert "Already sent to IT." in reply_text(post("status"))


def test_escalate_smtp_failure(uid):
    run_report()
    FakeTwilio.sent.clear()
    FakeSMTP.fail = True
    post("escalate")
    assert sent_bodies() == ["Couldn't reach IT right now, try again."]
    assert _count(Escalation) == 0
    FakeSMTP.fail = False
    post("escalate")
    assert sent_bodies()[-1] == bot.ESCALATED and len(FakeSMTP.sent) == 1


def test_escalate_with_nothing_checked(uid):
    post("escalate")
    assert sent_bodies() == [bot.NOTHING_YET] and FakeSMTP.sent == []


# ---------- result text ----------

def test_result_defangs_urls_and_stays_under_limit(uid, monkeypatch):
    stub_assessment(monkeypatch, ["Link http://evil.example.com/a looks fake", "x" * 3000, "y" * 3000, "fourth"],
                    colleagues=2)
    run_report()
    body = FakeTwilio.sent[0]["body"]
    assert "hxxp://evil[.]example[.]com/a" in body and "http://" not in body
    assert "Also sent to 2 colleagues" in body and "- fourth" not in body  # max 3 reasons
    assert len(body) <= 1500


def test_result_formats_per_band():
    low = bot.format_result("LOW", [], 0)
    assert low == "🟢 LOW\nNo warning signs found. Stay alert anyway"
    rev = bot.format_result("REVIEW", ["a"], 0)
    assert rev.startswith("🟠 REVIEW\n- a\nVerify with the sender") and rev.endswith("Reply escalate to send this to IT.")
    ins = bot.format_result("INSUFFICIENT_DATA", [], 0)
    assert ins.startswith("⚪ COULDN'T FULLY CHECK") and "Ask IT" in ins
    assert len(bot.format_result("URGENT", ["z" * 5000] * 3, 9)) <= 1500


def test_analysis_failure_says_could_not_check_never_low(uid, monkeypatch):
    def boom(msg):
        raise RuntimeError("engine down")

    monkeypatch.setattr(pipeline, "analyze", boom)
    run_report()
    body = FakeTwilio.sent[0]["body"]
    assert body.startswith("⚪ COULDN'T FULLY CHECK") and "LOW" not in body


def test_hard_failure_in_the_job_still_sends_could_not_check(uid, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(bot, "process_message", boom)
    run_report()
    assert FakeTwilio.sent[0]["body"].startswith("⚪ COULDN'T FULLY CHECK")


def test_twilio_send_failure_does_not_crash(uid):
    FakeTwilio.fail = True
    sid, r = run_report()
    assert r.status_code == 200 and reply_text(r) == "Checking..."
    assert _count(Message, Message.user_id == uid) == 1


def test_one_employee_cannot_see_or_escalate_anothers_report(uid):
    other = make_user("Other Employee", "wa-other")
    with SessionLocal() as db:
        db.execute(update(User).where(User.id == other).values(whatsapp_number="+919999900002"))
        db.commit()
    run_report()  # employee A has a checked message
    FakeTwilio.sent.clear()
    b = "whatsapp:+919999900002"
    assert "haven't checked" in reply_text(post("status", from_=b))
    post("escalate", from_=b)
    assert sent_bodies() == [bot.NOTHING_YET] and FakeSMTP.sent == [] and _count(Escalation) == 0
