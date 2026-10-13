import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api_models import Detail, DisconnectOut, OkOut
from app.config import get_settings
from app.db import get_db
from app.deps import COOKIE, SESSION_DAYS, create_session_token, current_user
from app.models import User
from app.services.crypto import decrypt, encrypt
from app.services.gmail_client import GMAIL_SCOPE

log = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])

_s = get_settings()
oauth = OAuth()
oauth.register(
    name="google",
    client_id=_s.GOOGLE_CLIENT_ID,
    client_secret=_s.GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    client_kwargs={"scope": f"openid email profile {GMAIL_SCOPE}"},
)


def _login_error(code: str) -> RedirectResponse:
    return RedirectResponse(f"{get_settings().FRONTEND_URL}/login?error={code}")


def _cookie_secure() -> bool:
    return urlparse(get_settings().PUBLIC_BASE_URL).hostname not in ("localhost", "127.0.0.1")


REDIRECT = {302: {"description": "Redirect", "headers": {"Location": {"schema": {"type": "string"}}}}}


@router.get("/auth/google", status_code=302, response_class=RedirectResponse, responses=REDIRECT,
            summary="Start Google sign-in: browser navigation, not fetch (redirects to Google)")
async def google_login(request: Request):
    # authlib stores a random `state` in the session and checks it on callback
    return await oauth.google.authorize_redirect(
        request,
        get_settings().GOOGLE_REDIRECT_URI,
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true",
    )


@router.get("/auth/google/callback", status_code=302, response_class=RedirectResponse, responses={
    302: {"description": "Sets the ev_session cookie and redirects to FRONTEND_URL/inbox "
                         "(?error=gmail_scope if Gmail access was not granted), or to FRONTEND_URL/login?error=domain|oauth|email",
          "headers": {"Location": {"schema": {"type": "string"}}}}},
            summary="Google redirects here after consent")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError:
        log.warning("oauth callback failed")
        return _login_error("oauth")
    info = token.get("userinfo") or {}
    email = (info.get("email") or "").lower()
    if not email or not info.get("email_verified", False):
        return _login_error("email")

    domain = get_settings().ALLOWED_EMAIL_DOMAIN.strip().lower()
    if domain and not (email.endswith("@" + domain) and info.get("hd", "").lower() == domain):
        return _login_error("domain")

    user = db.scalar(select(User).where(User.email == email))
    if not user:
        user = User(name=info.get("name") or email.split("@")[0], email=email)
        db.add(user)
    granted = (token.get("scope") or "").split()
    gmail_ok = GMAIL_SCOPE in granted
    refresh = token.get("refresh_token")
    if refresh and gmail_ok:  # Google omits it on re-consent sometimes: keep the old one
        user.gmail_refresh_token_enc = encrypt(refresh)
        user.gmail_connected_at = datetime.now(timezone.utc)
    db.commit()

    dest = "/inbox" if gmail_ok else "/inbox?error=gmail_scope"
    resp = RedirectResponse(f"{get_settings().FRONTEND_URL}{dest}")
    resp.set_cookie(
        COOKIE, create_session_token(user.id), max_age=SESSION_DAYS * 86400,
        httponly=True, samesite="lax", secure=_cookie_secure(),
    )
    return resp


@router.post("/auth/logout", response_model=OkOut, summary="Sign out (clears the cookie)")
def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@router.post("/auth/gmail/disconnect", response_model=DisconnectOut, responses={401: {"model": Detail}},
             summary="Revoke and forget the Gmail connection")
def gmail_disconnect(user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.gmail_refresh_token_enc:
        try:  # best effort
            httpx.post(
                "https://oauth2.googleapis.com/revoke",
                data={"token": decrypt(user.gmail_refresh_token_enc)}, timeout=5,
            )
        except Exception:
            log.warning("google revoke failed user=%s", user.id)
    user.gmail_refresh_token_enc = None
    user.gmail_connected_at = None
    db.commit()
    return {"gmail_connected": False}
