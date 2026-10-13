"""Guards for the non-negotiable safety rules. Static checks over app/ plus a few behaviour checks."""
import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.db import SessionLocal, engine
from app.deps import create_session_token
from app.main import _RedactOAuth, app
from app.models import Message
from app.services import pipeline
from app.services.gmail_client import GMAIL_SCOPE
from shared.schemas import NormalizedMessage
from tests.helpers import T0, make_msg, make_user, purge

APP = Path(__file__).resolve().parent.parent / "app"
SOURCES = {p.relative_to(APP).as_posix(): p.read_text(encoding="utf-8") for p in APP.rglob("*.py")}


def _grep(pattern: str) -> dict[str, list[str]]:
    rx = re.compile(pattern)
    return {f: rx.findall(s) for f, s in SOURCES.items() if rx.search(s)}


def test_no_html_rendering_paths():
    assert _grep(r"HTMLResponse|Jinja|render_template|text/html|\.innerHTML|markupsafe") == {}


def test_only_outbound_http_is_the_google_token_revoke():
    assert _grep(r"\brequests\b|urllib\.request|urlopen|aiohttp|httpx\.(get|head|put|patch|delete|request|stream|AsyncClient|Client)") == {}
    assert set(_grep(r"\bhttpx\.post\(")) == {"api/auth.py"}
    assert re.findall(r"https?://[^\s\"')]+", SOURCES["api/auth.py"]).count("https://oauth2.googleapis.com/revoke") == 1


def test_gmail_is_read_only():
    assert GMAIL_SCOPE == "https://www.googleapis.com/auth/gmail.readonly"
    assert _grep(r"mail\.google\.com|gmail\.(modify|send|compose|insert|labels|settings|metadata)") == {}
    calls = set()
    for src in SOURCES.values():
        calls |= set(re.findall(r"\.messages\(\)\.(\w+)", src))
    assert calls == {"list", "get"}
    resources = set()
    for src in SOURCES.values():
        resources |= set(re.findall(r"\.users\(\)\.(\w+)\(", src))
    assert resources == {"messages"}  # no labels, drafts, threads, history


def test_log_calls_never_mention_bodies_or_secrets():
    bad = re.compile(r"\b(body|body_text|text|token|secret|refresh|subject|password|message_text)\b", re.I)
    offenders = []
    for f, src in SOURCES.items():
        for line in src.splitlines():
            if re.search(r"\blog\.(debug|info|warning|error|exception|critical)\(", line):
                args = line.split("(", 1)[1]
                if bad.search(args):
                    offenders.append((f, line.strip()))
    # the one allowed mention is the names of the Twilio settings in the "not configured" message
    offenders = [o for o in offenders if "are not set" not in o[1]]
    assert offenders == []
    assert _grep(r"\bprint\(").keys() <= {"seed.py"}
    assert _grep(r"log\.exception\(") == {}  # tracebacks can echo data


def test_sql_errors_do_not_echo_message_bodies():
    assert engine.hide_parameters is True
    msg = NormalizedMessage(user_id=make_user("Dup", "dup-safety"), channel="sms", external_id="dup-1",
                            sender="x", body_text="SECRETBODY-12345", urls=[], attachments=[], headers={},
                            received_at=T0)
    with SessionLocal() as db:
        pipeline.process_message(db, msg)
        with pytest.raises(IntegrityError) as e:
            pipeline.process_message(db, msg)
    assert "SECRETBODY" not in str(e.value)
    purge()


def test_access_log_redacts_oauth_params():
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                            ("1.2.3.4", "GET", "/auth/google/callback?state=abc&code=4/0secret&scope=email", "1.1", 302), None)
    assert _RedactOAuth().filter(rec)
    assert "secret" not in rec.args[2] and "abc" not in rec.args[2] and "code=[redacted]" in rec.args[2]


def test_stored_body_is_capped():
    uid = make_user("Big", "big-safety")
    msg = NormalizedMessage(user_id=uid, channel="sms", external_id="big-1", sender="x", body_text="a" * 150_000,
                            urls=[], attachments=[], headers={}, received_at=T0)
    with SessionLocal() as db:
        m, _ = pipeline.process_message(db, msg)
        assert len(db.get(Message, m.id).body_text) == pipeline.MAX_STORED_BODY
    purge()


def test_reports_and_check_results_are_per_employee():
    purge()
    a, b = make_user("A", "a-safety"), make_user("B", "b-safety")
    make_msg(a, "password", source="check", channel="sms")
    make_msg(a, "password", source="whatsapp", channel="sms")
    cb = TestClient(app, base_url="http://localhost:8000")
    cb.cookies.set("ev_session", create_session_token(b))
    assert cb.get("/me/reports").json()["items"] == []
    assert cb.get("/me/messages").json()["items"] == []
    r = cb.post("/check", json={"channel": "sms", "sender": "x", "text": "hello"}).json()
    assert [i["id"] for i in cb.get("/me/reports").json()["items"]] == [r["id"]]
    purge()


# ---------- OpenAPI completeness ----------

def test_every_operation_documents_its_response_with_examples():
    spec = TestClient(app).get("/openapi.json").json()
    comps = spec["components"]["schemas"]
    problems = []
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            ok = [c for c in op["responses"] if c[0] in "23"]
            resp = op["responses"][ok[0]] if ok else {}
            if not op.get("tags") or not op.get("summary"):
                problems.append(f"{method} {path}: tags/summary")
            if not ("content" in resp or "headers" in resp):
                problems.append(f"{method} {path}: no documented success response")
            for media in resp.get("content", {}).values():
                ref = media.get("schema", {}).get("$ref")
                if ref and not comps[ref.split("/")[-1]].get("examples"):
                    problems.append(f"{method} {path}: {ref} has no example")
                if "example" not in media and not ref:
                    problems.append(f"{method} {path}: inline schema without example")
            for code, r in op["responses"].items():
                ref = r.get("content", {}).get("application/json", {}).get("schema", {}).get("$ref")
                if code[0] == "4" and code != "422" and ref and not comps[ref.split("/")[-1]].get("examples"):
                    problems.append(f"{method} {path}: error model without example")
    assert problems == []
