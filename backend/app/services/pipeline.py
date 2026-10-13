"""Single entry point that stores a NormalizedMessage plus its assessment.

Used by the Gmail poller, /check and the WhatsApp bot. Only normalized fields are stored (never raw MIME).
"""
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from sqlalchemy.orm import Session

from app.models import Assessment as AssessmentRow
from app.models import Message
from engine.analyze import analyze
from engine.parser import parse_mime
from shared.schemas import Assessment, NormalizedMessage, Reason

log = logging.getLogger(__name__)
ANALYZE_TIMEOUT = 60  # seconds
MAX_STORED_BODY = 100_000  # characters kept in the database; analyze() still sees the full text
_pool = ThreadPoolExecutor(max_workers=4)


def fallback(code: str = "CHECK_FAILED", text: str = "We couldn't fully check this message") -> Assessment:
    """A failed check is never LOW."""
    return Assessment(
        risk_band="INSUFFICIENT_DATA",
        reasons=[Reason(code=code, text=text, evidence_ids=[])],
        evidence=[], data_completeness="UNKNOWN", model_versions={"engine": "error"},
    )


def run_analysis(msg: NormalizedMessage) -> Assessment:
    # ponytail: a timed-out analyze() keeps running in its thread; there is no way to kill it
    try:
        return _pool.submit(analyze, msg).result(timeout=ANALYZE_TIMEOUT)
    except Exception as e:  # includes TimeoutError
        log.warning("analyze failed ext=%s err=%s", msg.external_id, type(e).__name__)
        return fallback()


def process_message(
    db: Session, msg: NormalizedMessage, assessment: Assessment | None = None,
    source: str = "gmail", readable: bool = True,
) -> tuple[Message, AssessmentRow]:
    """Analyze (unless an assessment is given) and store in one transaction.
    Raises IntegrityError if (user, channel, external_id) exists."""
    a = assessment or run_analysis(msg)
    m = Message(
        user_id=msg.user_id, channel=msg.channel, external_id=msg.external_id, sender=msg.sender,
        sender_display_name=msg.sender_display_name, reply_to=msg.reply_to, subject=msg.subject,
        body_text=msg.body_text[:MAX_STORED_BODY], urls=msg.urls, received_at=msg.received_at,
        attachments=[x.model_dump() for x in msg.attachments], source=source, readable=readable,
    )
    db.add(m)
    db.flush()
    d = a.model_dump(mode="json")
    row = AssessmentRow(
        message_id=m.id, risk_band=d["risk_band"], reasons=d["reasons"], evidence=d["evidence"],
        data_completeness=d["data_completeness"], model_versions=d["model_versions"],
        colleague_count=d["colleague_count"],
    )
    db.add(row)
    db.commit()
    return m, row


def placeholder_message(raw: bytes, user_id: int, external_id: str) -> NormalizedMessage:
    """Stand-in for an email we could not parse: sender/subject from the raw headers if readable."""
    sender = subject = "unknown"
    try:
        h = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
        sender = parseaddr(str(h.get("From") or ""))[1][:500] or sender
        subject = str(h.get("Subject") or "").strip()[:500] or subject
    except Exception:
        pass
    return NormalizedMessage(
        user_id=user_id, channel="email", external_id=external_id, sender=sender, subject=subject,
        body_text="", urls=[], attachments=[], headers={}, received_at=datetime.now(timezone.utc),
    )


def process_raw_email(
    db: Session, raw: bytes | None, user_id: int, external_id: str, source: str
) -> tuple[Message, AssessmentRow]:
    """Parse + analyze + store. raw=None means it could not even be decoded.
    A parse failure stores an INSUFFICIENT_DATA placeholder (never LOW)."""
    try:
        if raw is None:
            raise ValueError("undecodable")
        msg = parse_mime(raw, user_id, external_id)
    except Exception as e:
        log.warning("parse failed user=%s ext=%s err=%s", user_id, external_id, type(e).__name__)
        return process_message(
            db, placeholder_message(raw or b"", user_id, external_id),
            fallback("UNREADABLE", "We couldn't read this email"), source=source, readable=False,
        )
    return process_message(db, msg, source=source)
