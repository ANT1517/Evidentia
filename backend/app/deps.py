from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Cookie, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import User

COOKIE = "ev_session"
SESSION_DAYS = 7


def create_session_token(user_id: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    return jwt.encode({"sub": str(user_id), "exp": exp}, get_settings().SECRET_KEY, algorithm="HS256")


def current_user(ev_session: str | None = Cookie(default=None), db: Session = Depends(get_db)) -> User:
    if not ev_session:
        raise HTTPException(401, "not signed in")
    try:
        uid = int(jwt.decode(ev_session, get_settings().SECRET_KEY, algorithms=["HS256"])["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, "invalid session")
    user = db.get(User, uid)
    if not user:
        raise HTTPException(401, "unknown user")
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if not (user.is_admin or user.email.lower() in get_settings().admin_emails):
        raise HTTPException(403, "admin only")
    return user
