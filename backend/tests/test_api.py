import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import SessionLocal
from app.deps import create_session_token
from app.main import app
from app.models import Escalation, Feedback
from app.services import escalation as esc_mod
from app.services import pipeline
from tests.helpers import make_msg, make_user, purge

EML = (b"From: Boss <boss@evil.test>\r\nSubject: Wire money\r\nDate: Mon, 13 Oct 2026 10:00:00 +0000\r\n\r\n"
       b"Please update the bank details at http://evil.test/pay\r\n")


@pytest.fixture
def ids():
    purge()
    d = {"a": make_user("Test A", "a"), "b": make_user("Test B", "b"), "admin": make_user("Admin", "admin", True)}
    yield d
    purge()


def client(uid=None) -> TestClient:
    c = TestClient(app, base_url="http://localhost:8000")
    if uid:
        c.cookies.set("ev_session", create_session_token(uid))
    return c


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


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.sent, FakeSMTP.fail = [], False
    monkeypatch.setattr(esc_mod.smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


# ---------- isolation ----------

def test_cannot_touch_another_employees_message(ids, smtp):
    mid = make_msg(ids["a"], "password please")
    b = client(ids["b"])
    assert b.get(f"/me/messages/{mid}").status_code == 404
    assert b.post(f"/me/messages/{mid}/escalate", json={}).status_code == 404
    assert b.post(f"/me/messages/{mid}/feedback", json={"verdict": "fine"}).status_code == 404
    assert b.get("/me/messages").json()["items"] == []
    assert b.get("/me/messages/999999").json() == {"detail": "message not found"}
    assert smtp.sent == []
    assert client().get("/me/messages").status_code == 401


# ---------- list ----------

def test_order_filters_and_cursor_pagination(ids):
    a = ids["a"]
    u_old = make_msg(a, "password", hours=0)
    u_new = make_msg(a, "password", hours=1)
    rev = make_msg(a, "this is urgent", hours=2)
    ins = make_msg(a, "", hours=3)  # empty body -> INSUFFICIENT_DATA
    low = make_msg(a, "lunch?", hours=4)
    sms = make_msg(a, "hi there", channel="sms", hours=5)
    expected = [u_new, u_old, rev, ins, sms, low]
    c = client(a)

    items = c.get("/me/messages").json()["items"]
    assert [i["id"] for i in items] == expected
    assert [i["risk_band"] for i in items] == ["URGENT", "URGENT", "REVIEW", "INSUFFICIENT_DATA", "LOW", "LOW"]
    assert items[0]["top_reason"] == "Asks for login or bank details." and items[-1]["top_reason"] is None

    assert [i["id"] for i in c.get("/me/messages?band=URGENT").json()["items"]] == [u_new, u_old]
    assert [i["id"] for i in c.get("/me/messages?channel=sms").json()["items"]] == [sms]
    assert c.get("/me/messages?band=NOPE").status_code == 422

    got, cursor, pages = [], None, 0
    while True:
        r = c.get("/me/messages", params={"limit": 2, **({"cursor": cursor} if cursor else {})}).json()
        got += [i["id"] for i in r["items"]]
        pages += 1
        cursor = r["next_cursor"]
        if not cursor:
            break
    assert got == expected and pages == 3
    assert c.get("/me/messages?cursor=garbage").status_code == 400
    assert c.get("/me/messages?limit=101").status_code == 422


def test_placeholder_messages_are_flagged(ids):
    a = ids["a"]
    plain = make_msg(a, subject="unknown", placeholder=True, hours=1)
    headers_ok = make_msg(a, subject="Invoice", placeholder=True, hours=2)
    c = client(a)
    by_id = {i["id"]: i for i in c.get("/me/messages").json()["items"]}
    assert by_id[plain]["readable"] is False and by_id[plain]["preview"] == "Couldn't read this email"
    assert by_id[plain]["risk_band"] == "INSUFFICIENT_DATA"
    assert by_id[headers_ok]["preview"] == "Invoice"
    d = c.get(f"/me/messages/{plain}").json()
    assert d["readable"] is False and d["what_to_do"] == ["We couldn't fully check this. Ask IT if you're unsure"]


def test_detail_what_to_do_feedback_and_preview(ids):
    a = ids["a"]
    urgent = make_msg(a, "password " + "x" * 300, urls=["http://x.test/a"])
    review = make_msg(a, "urgent")
    low = make_msg(a, "lunch")
    c = client(a)
    d = c.get(f"/me/messages/{urgent}").json()
    assert d["what_to_do"] == ["Don't click any links", "Don't reply or send money", "Report this to IT"]
    assert d["urls"] == ["http://x.test/a"] and d["escalated_at"] is None and d["feedback"] is None
    assert d["assessment"]["reasons"][0]["code"] == "CREDENTIAL_REQUEST"
    items = {i["id"]: i for i in c.get("/me/messages").json()["items"]}
    assert len(items[urgent]["preview"]) == 120  # no subject: first 120 chars of the body
    assert c.get(f"/me/messages/{review}").json()["what_to_do"][0].startswith("Verify with the sender")
    assert c.get(f"/me/messages/{low}").json()["what_to_do"] == ["No warning signs found. Stay alert anyway"]

    assert c.post(f"/me/messages/{urgent}/feedback", json={"verdict": "fine"}).json() == {
        "message_id": urgent, "verdict": "fine"}
    c.post(f"/me/messages/{urgent}/feedback", json={"verdict": "fine"})
    assert c.get(f"/me/messages/{urgent}").json()["feedback"] == "fine"
    assert c.post(f"/me/messages/{urgent}/feedback", json={"verdict": "bad"}).status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Feedback).where(Feedback.message_id == urgent)) == 1


# ---------- escalation ----------

def test_escalate_sends_one_plain_text_defanged_email(ids, smtp):
    a = ids["a"]
    mid = make_msg(a, "<b>Reset</b> at http://evil.example.com/login?x=1 now password",
                   subject="Reset\r\nBcc: evil@x.test", urls=["http://evil.example.com/login?x=1"],
                   sender="helpdesk@c0rp.test")
    c = client(a)
    r = c.post(f"/me/messages/{mid}/escalate", json={"note": "looks fake"})
    assert r.status_code == 200 and r.json()["employee_note"] == "looks fake"
    assert len(smtp.sent) == 1
    m = smtp.sent[0]
    body = m.get_content()
    assert not m.is_multipart() and m.get_content_type() == "text/plain"
    assert m["Bcc"] is None and "\n" not in m["Subject"]
    assert m["Subject"].startswith("[Evedentia][URGENT] Reported by Test A: ")
    assert "hxxp://evil[.]example[.]com/login?x=1" in body
    assert "http://" not in body and "https://" not in body
    assert "looks fake" in body and "a@t4.test" in body and "CREDENTIAL_REQUEST" in body
    assert "type=keyword" in body  # evidence line

    again = c.post(f"/me/messages/{mid}/escalate", json={})
    assert again.status_code == 200 and again.json()["id"] == r.json()["id"]
    assert len(smtp.sent) == 1
    assert c.get(f"/me/messages/{mid}").json()["escalated_at"] is not None
    assert c.get("/me/messages").json()["items"][0]["escalated"] is True


def test_escalate_note_limit(ids, smtp):
    mid = make_msg(ids["a"], "password")
    assert client(ids["a"]).post(f"/me/messages/{mid}/escalate", json={"note": "x" * 501}).status_code == 422
    assert smtp.sent == []


def test_smtp_failure_returns_502_and_creates_no_row(ids, smtp):
    mid = make_msg(ids["a"], "password")
    c = client(ids["a"])
    smtp.fail = True
    r = c.post(f"/me/messages/{mid}/escalate", json={})
    assert r.status_code == 502 and isinstance(r.json()["detail"], str)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Escalation).where(Escalation.message_id == mid)) == 0
    smtp.fail = False
    assert c.post(f"/me/messages/{mid}/escalate", json={}).status_code == 200  # retry works
    assert len(smtp.sent) == 1


def test_defang_helper():
    d = esc_mod.defang
    assert d("see https://a.b.example.com/p?q=1.2 and http://1.2.3.4:80/x") == \
        "see hxxps://a[.]b[.]example[.]com/p?q=1.2 and hxxp://1[.]2[.]3[.]4:80/x"


# ---------- /check ----------

def test_check_text_message(ids):
    c = client(ids["a"])
    r = c.post("/check", json={"channel": "sms", "sender": "JD-SBIINB",
                               "text": "Update your password: http://sbi-kyc.example.com/x. http://sbi-kyc.example.com/x"})
    assert r.status_code == 200
    d = r.json()
    assert d["source"] == "check" and d["channel"] == "sms" and d["sender"] == "JD-SBIINB"
    assert d["urls"] == ["http://sbi-kyc.example.com/x"]  # trailing sentence dot trimmed, duplicates dropped
    assert d["assessment"]["risk_band"] == "URGENT"
    reports = c.get("/me/reports").json()["items"]
    assert [i["id"] for i in reports] == [d["id"]]
    # the same text again is a new report, not a collision
    assert c.post("/check", json={"channel": "sms", "sender": "JD-SBIINB", "text": "hello"}).status_code == 200
    assert len(c.get("/me/reports").json()["items"]) == 2


def test_check_text_validation(ids):
    c = client(ids["a"])
    r = c.post("/check", json={"channel": "sms", "sender": "x", "text": "a" * 5001})
    assert r.status_code == 422 and isinstance(r.json()["detail"], str)
    assert c.post("/check", json={"channel": "telegram", "sender": "x", "text": "hi"}).status_code == 422
    assert c.post("/check", content=b"{bad", headers={"content-type": "application/json"}).status_code == 422
    assert c.post("/check", content=b"hi", headers={"content-type": "text/plain"}).status_code == 415
    assert client().post("/check", json={"channel": "sms", "sender": "x", "text": "hi"}).status_code == 401
    assert c.post("/check", json={"channel": "sms", "sender": "x", "text": "a" * 5000}).status_code == 200


def test_check_eml_upload(ids):
    c = client(ids["a"])
    r = c.post("/check", files={"file": ("a.eml", EML, "message/rfc822")})
    d = r.json()
    assert r.status_code == 200 and d["channel"] == "email" and d["source"] == "check"
    assert d["subject"] == "Wire money" and d["urls"] == ["http://evil.test/pay"] and d["readable"] is True
    assert d["assessment"]["risk_band"] == "URGENT"
    assert [i["id"] for i in c.get("/me/reports").json()["items"]] == [d["id"]]
    assert [i["id"] for i in c.get("/me/messages").json()["items"]] == [d["id"]]
    assert c.post("/check", files={"other": ("a.eml", EML)}).status_code == 422


def test_check_unparseable_eml_becomes_placeholder(ids, monkeypatch):
    def boom(raw, user_id, external_id):
        raise ValueError("garbage")

    monkeypatch.setattr(pipeline, "parse_mime", boom)
    r = client(ids["a"]).post("/check", files={"file": ("a.eml", EML, "message/rfc822")})
    d = r.json()
    assert r.status_code == 200 and d["readable"] is False
    assert d["assessment"]["risk_band"] == "INSUFFICIENT_DATA" and d["assessment"]["data_completeness"] == "UNKNOWN"
    assert d["sender"] == "boss@evil.test" and d["source"] == "check"


def test_check_eml_size_limits(ids):
    c = client(ids["a"])
    just_over = b"Subject: x\r\n\r\n" + b"a" * (2 * 1024 * 1024)
    assert c.post("/check", files={"file": ("a.eml", just_over)}).status_code == 413
    assert c.post("/check", files={"file": ("a.eml", b"a" * (3 * 1024 * 1024))}).status_code == 413
    ok = b"Subject: x\r\n\r\n" + b"a" * (1024 * 1024)
    assert c.post("/check", files={"file": ("a.eml", ok)}).status_code == 200


# ---------- admin ----------

CSV = (
    "name,title,email,phone\n"
    "Asha Rao,Accountant,asha@t4.test,98765 43210\n"
    "Bad Phone,Mgr,badphone@t4.test,12\n"
    ",Nobody,,+919000000001\n"
    ",,noname@t4.test,\n"
    "Dup Phone,Eng,dup@t4.test,9876543210\n"
    "Ravi,Eng,RAVI@t4.test,+91 91234 56789\n"
)


def _upload(c, text):
    return c.post("/admin/users/import", files={"file": ("d.csv", text.encode(), "text/csv")})


def test_csv_import_reports_bad_rows_and_imports_the_rest(ids):
    c = client(ids["admin"])
    r = _upload(c, CSV)
    assert r.status_code == 200
    assert r.json() == {"created": 2, "updated": 0, "errors": [
        {"row": 3, "error": "invalid phone number"},
        {"row": 4, "error": "email is required"},
        {"row": 5, "error": "name is required"},
        {"row": 6, "error": "phone number already belongs to another employee"},
    ]}
    users = {u["email"]: u for u in c.get("/admin/users?limit=100").json()["items"]}
    assert users["asha@t4.test"]["phone"] == "+919876543210" and users["ravi@t4.test"]["phone"] == "+919123456789"
    assert "badphone@t4.test" not in users

    r2 = _upload(c, "name,title,email,phone\nAsha R,Lead,asha@t4.test,\n")
    assert r2.json() == {"created": 0, "updated": 1, "errors": []}
    users = {u["email"]: u for u in c.get("/admin/users?limit=100").json()["items"]}
    assert users["asha@t4.test"]["title"] == "Lead" and users["asha@t4.test"]["phone"] == "+919876543210"

    assert _upload(c, "foo,bar\n1,2\n").status_code == 400
    assert c.get("/admin/users?cursor=garbage").status_code == 400


def test_admin_pagination(ids):
    c = client(ids["admin"])
    r = c.get("/admin/users?limit=1").json()
    assert len(r["items"]) == 1 and r["next_cursor"]
    nxt = c.get("/admin/users", params={"limit": 1, "cursor": r["next_cursor"]}).json()["items"][0]
    assert nxt["id"] > r["items"][0]["id"]


def test_non_admin_gets_403_on_admin_routes(ids):
    c = client(ids["a"])
    assert _upload(c, CSV).status_code == 403
    r = c.get("/admin/users")
    assert r.status_code == 403 and r.json() == {"detail": "admin only"}
    assert client().get("/admin/users").status_code == 401


# ---------- API quality ----------

def test_cors_allows_credentials_from_frontend():
    r = TestClient(app).options("/me", headers={"Origin": "http://localhost:5173",
                                                  "Access-Control-Request-Method": "GET"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert r.headers["access-control-allow-credentials"] == "true"


def test_openapi_has_response_models_and_tags():
    spec = TestClient(app).get("/openapi.json").json()
    for path, method in [("/me", "get"), ("/me", "patch"), ("/scan", "post"), ("/me/messages", "get"),
                         ("/me/reports", "get"), ("/me/messages/{message_id}", "get"),
                         ("/me/messages/{message_id}/escalate", "post"),
                         ("/me/messages/{message_id}/feedback", "post"),
                         ("/check", "post"), ("/admin/users/import", "post"), ("/admin/users", "get")]:
        op = spec["paths"][path][method]
        assert "$ref" in op["responses"]["200"]["content"]["application/json"]["schema"], (path, method)
        assert op["tags"] and op["summary"]
    assert set(spec["paths"]["/check"]["post"]["requestBody"]["content"]) == {"application/json", "multipart/form-data"}
