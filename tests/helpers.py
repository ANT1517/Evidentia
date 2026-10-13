from datetime import datetime, timezone
from pathlib import Path

from engine.parser import parse_email
from engine.schemas import (
    Attachment,
    AuthResults,
    Channel,
    IngestSource,
    NormalizedMessage,
)

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
FIX = Path(__file__).parent / "fixtures"


def trusted_auth(**over) -> AuthResults:
    base = dict(spf="pass", dkim="pass", dmarc="pass", authserv_id="mx.google.com")
    base.update(over)
    return AuthResults(**base)


def make(**over) -> NormalizedMessage:
    """A clean email that arrived through the trusted Gmail path. Override fields as needed."""
    base = dict(
        external_id="t1",
        channel=Channel.EMAIL,
        sender="billing@acmesupplies.example",
        sender_display_name="Acme Supplies Billing",
        subject="Invoice",
        body_text="Please see the portal.",
        auth=trusted_auth(),
        ingest_source=IngestSource.GMAIL_API,
        received_at=NOW,
    )
    base.update(over)
    return NormalizedMessage(**base)


def att(name: str, ctype: str = "application/octet-stream") -> Attachment:
    return Attachment(filename=name, content_type=ctype, size=10, sha256="0" * 64)


def fixture_msg(name: str, source: IngestSource = IngestSource.GMAIL_API) -> NormalizedMessage:
    return parse_email((FIX / name).read_bytes(), external_id=name, ingest_source=source)


def by_check(results, check):
    return next(r for r in results if r.check == check)
