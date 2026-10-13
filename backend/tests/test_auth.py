import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text

from app.api import auth as auth_api
from app.config import get_settings
from app.db import SessionLocal
from app.main import app
from app.models import User
from app.services.crypto import decrypt

EMAIL = "tester-auth@corp.test"


GMAIL = "https://www.googleapis.com/auth/gmail.readonly"


def _mock_google(monkeypatch, email=EMAIL, hd="corp.test", refresh="refresh-secret", scope=f"openid email profile {GMAIL}"):
    async def fake(request):
        t = {"scope": scope, "userinfo": {"email": email, "email_verified": True, "name": "Test User", "hd": hd}}
        if refresh:
            t["refresh_token"] = refresh
        return t

    monkeypatch.setattr(auth_api.oauth.google, "authorize_access_token", fake)


@pytest.fixture
def client():
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email == EMAIL))
        db.commit()
    yield TestClient(app, base_url="http://localhost:8000", follow_redirects=False)
    with SessionLocal() as db:
        db.execute(delete(User).where(User.email == EMAIL))
        db.commit()


def test_login_redirects_to_google_with_offline_and_gmail_scope(client):
    r = client.get("/auth/google")
    loc = r.headers["location"]
    assert r.status_code == 302 and loc.startswith("https://accounts.google.com/")
    assert "gmail.readonly" in loc and "access_type=offline" in loc and "state=" in loc


def test_callback_creates_user_sets_cookie_and_encrypts_token(client, monkeypatch):
    _mock_google(monkeypatch)
    r = client.get("/auth/google/callback?code=x&state=y")
    assert r.status_code == 307 or r.status_code == 302
    assert r.headers["location"] == "http://localhost:5173/inbox"
    sc = r.headers["set-cookie"].lower()
    assert "ev_session=" in sc and "httponly" in sc and "samesite=lax" in sc

    me = client.get("/me").json()
    assert me["email"] == EMAIL and me["gmail_connected"] is True

    with SessionLocal() as db:
        enc = db.scalar(select(User.gmail_refresh_token_enc).where(User.email == EMAIL))
        raw = db.execute(text("select gmail_refresh_token_enc from users where email=:e"), {"e": EMAIL}).scalar()
    assert "refresh-secret" not in raw and decrypt(enc) == "refresh-secret"


def test_missing_refresh_token_keeps_old_one(client, monkeypatch):
    _mock_google(monkeypatch)
    client.get("/auth/google/callback?code=x&state=y")
    _mock_google(monkeypatch, refresh=None)
    client.get("/auth/google/callback?code=x&state=y")
    assert client.get("/me").json()["gmail_connected"] is True


def test_wrong_domain_rejected(client, monkeypatch):
    monkeypatch.setenv("ALLOWED_EMAIL_DOMAIN", "corp.test")
    get_settings.cache_clear()
    try:
        _mock_google(monkeypatch, email="x@gmail.com", hd="")
        r = client.get("/auth/google/callback?code=x&state=y")
        assert r.headers["location"] == "http://localhost:5173/login?error=domain"
        assert "ev_session" not in r.headers.get("set-cookie", "")
        with SessionLocal() as db:
            assert db.scalar(select(User).where(User.email == "x@gmail.com")) is None
    finally:
        monkeypatch.delenv("ALLOWED_EMAIL_DOMAIN")
        get_settings.cache_clear()


def test_me_requires_auth(client):
    assert client.get("/me").status_code == 401
    client.cookies.set("ev_session", "garbage")
    assert client.get("/me").status_code == 401


def test_patch_whatsapp_and_disconnect(client, monkeypatch):
    _mock_google(monkeypatch)
    client.get("/auth/google/callback?code=x&state=y")
    r = client.patch("/me", json={"whatsapp_number": "98765 43210"})
    assert r.json()["whatsapp_number"] == "+919876543210"
    assert client.patch("/me", json={"whatsapp_number": "abc"}).status_code == 422
    monkeypatch.setattr(auth_api.httpx, "post", lambda *a, **k: None)
    assert client.post("/auth/gmail/disconnect").json() == {"gmail_connected": False}
    assert client.get("/me").json()["gmail_connected"] is False
    assert client.post("/auth/logout").status_code == 200


def test_missing_gmail_scope_signs_in_but_not_connected(client, monkeypatch):
    _mock_google(monkeypatch, scope="openid email profile")
    r = client.get("/auth/google/callback?code=x&state=y")
    assert r.headers["location"] == "http://localhost:5173/inbox?error=gmail_scope"
    assert "ev_session=" in r.headers["set-cookie"]
    assert client.get("/me").json()["gmail_connected"] is False
    with SessionLocal() as db:
        assert db.scalar(select(User.gmail_refresh_token_enc).where(User.email == EMAIL)) is None
