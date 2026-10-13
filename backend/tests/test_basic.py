from fastapi.testclient import TestClient

from app.main import app
from app.services.directory import normalize_phone
from engine.analyze import analyze
from engine.parser import parse_mime
from shared.schemas import Assessment, NormalizedMessage

RAW = (
    b"From: Boss <boss@evil.test>\r\nSubject: Hi\r\nDate: Mon, 13 Oct 2026 10:00:00 +0000\r\n\r\n"
    b"update your password at http://x.test/a\r\n"
)


def test_health():
    r = TestClient(app).get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_schema_roundtrip():
    msg = parse_mime(RAW, 1, "abc")
    assert NormalizedMessage.model_validate_json(msg.model_dump_json()) == msg
    a = analyze(msg)
    assert Assessment.model_validate_json(a.model_dump_json()) == a


def test_stub_analyze_bands():
    msg = parse_mime(RAW, 1, "abc")
    assert msg.urls == ["http://x.test/a"] and msg.sender == "boss@evil.test"
    assert analyze(msg).risk_band == "URGENT"
    assert analyze(msg.model_copy(update={"body_text": "so urgent"})).risk_band == "REVIEW"
    assert analyze(msg.model_copy(update={"body_text": "lunch?"})).risk_band == "LOW"


def test_phone_normalization():
    assert normalize_phone("98765 43210") == "+919876543210"
    assert normalize_phone("+91 98765 43210") == "+919876543210"


def _fixture(name: str) -> bytes:
    from pathlib import Path
    return (Path(__file__).parent / "fixtures" / name).read_bytes()


def test_html_only_email_is_converted_not_rendered():
    msg = parse_mime(_fixture("html_only.eml"), 1, "h1")
    assert msg.body_text == "Please verify your password now. Click here"
    assert "secret" not in msg.body_text and "color" not in msg.body_text
    assert msg.urls == ["http://evil.test/login"]
    assert analyze(msg).risk_band == "URGENT"


def test_empty_html_email_is_insufficient_data_not_low():
    msg = parse_mime(_fixture("html_empty.eml"), 1, "h2")
    assert msg.body_text == ""
    assert analyze(msg).risk_band == "INSUFFICIENT_DATA"


def test_tests_use_separate_db_and_no_scheduler():
    from app.db import engine
    assert engine.url.database == "evedentia_test"
    with TestClient(app):  # runs the lifespan
        assert app.state.scheduler is None
