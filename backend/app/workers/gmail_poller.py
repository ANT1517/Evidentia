import asyncio
import base64
import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from google.auth.exceptions import RefreshError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.config import get_settings
from app.db import SessionLocal
from app.models import Message, User
from app.services.gmail_client import build_gmail_service
from app.services.pipeline import process_raw_email

log = logging.getLogger(__name__)
build_service = build_gmail_service  # tests replace this
USER_TIMEOUT = 120  # seconds per user per poll
BACKFILL = timedelta(days=7)  # only look back this far before the first connection


def _ingest(db, svc, user: User, gmail_id: str) -> bool:
    raw_b64 = svc.users().messages().get(userId="me", id=gmail_id, format="raw").execute()["raw"]
    try:
        raw = base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4))
    except Exception:
        raw = None  # stored as an unreadable placeholder, never retried
    try:
        process_raw_email(db, raw, user.id, gmail_id, source="gmail")
    except IntegrityError:  # already stored (e.g. concurrent /scan)
        db.rollback()
        return False
    return True


def poll_user(user_id: int) -> int:
    """Fetch and process new INBOX emails for one user. Returns the number of new messages."""
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if not user or not user.gmail_refresh_token_enc:
            return 0
        try:
            svc = build_service(user)
            since = (user.gmail_connected_at or datetime.now(timezone.utc)) - BACKFILL
            resp = svc.users().messages().list(
                userId="me", labelIds=["INBOX"], maxResults=25, q=f"after:{int(since.timestamp())}"
            ).execute()
            ids = [m["id"] for m in resp.get("messages", [])]
            known = set(db.scalars(select(Message.external_id).where(
                Message.user_id == user.id, Message.channel == "email", Message.external_id.in_(ids))))
            new = 0
            for gid in ids:
                if gid in known:
                    continue
                try:
                    new += _ingest(db, svc, user, gid)
                except Exception as e:  # one bad message must not block the rest
                    db.rollback()
                    log.warning("ingest failed user=%s gmail_id=%s err=%s", user.id, gid, type(e).__name__)
            user.last_polled_at = datetime.now(timezone.utc)
            db.commit()
            return new
        except RefreshError as e:
            if "invalid_grant" in str(e):  # revoked or expired: employee must reconnect
                user.gmail_refresh_token_enc = None
                user.gmail_connected_at = None
                db.commit()
                log.warning("gmail disconnected user=%s", user.id)
            raise


async def poll_all() -> None:
    with SessionLocal() as db:
        ids = list(db.scalars(select(User.id).where(User.gmail_refresh_token_enc.is_not(None))))
    for uid in ids:  # sequential; each user isolated
        try:
            await asyncio.wait_for(asyncio.to_thread(poll_user, uid), USER_TIMEOUT)
        except Exception as e:
            log.warning("poll failed user=%s err=%s", uid, type(e).__name__)


def start_scheduler() -> AsyncIOScheduler:
    s = AsyncIOScheduler()
    s.add_job(poll_all, "interval", seconds=get_settings().GMAIL_POLL_SECONDS,
              max_instances=1, coalesce=True, next_run_time=datetime.now(timezone.utc))
    s.start()
    return s
