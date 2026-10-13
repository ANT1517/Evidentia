"""STUB - replaced by Member B. Keep the signature stable."""
import hashlib
import re
from html.parser import HTMLParser
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

from shared.schemas import AttachmentMeta, NormalizedMessage

_URL = re.compile(r"https?://[^\s<>\"')]+")
_HEADERS = ("Authentication-Results", "Received-SPF", "From", "Reply-To", "Return-Path")


class _Text(HTMLParser):
    """HTML -> plain text. Never rendered; script/style dropped; link hrefs collected."""

    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self.links: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            href = dict(attrs).get("href") or ""
            if href.startswith(("http://", "https://")):
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def _html_to_text(html: str) -> tuple[str, list[str]]:
    p = _Text()
    p.feed(html)
    return " ".join(" ".join(p.parts).split()), p.links


def parse_mime(raw: bytes, user_id: int, external_id: str) -> NormalizedMessage:
    m = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(m.get("From", "")))
    links: list[str] = []
    body = m.get_body(preferencelist=("plain",))
    if body:
        text = body.get_content()
    else:
        html = m.get_body(preferencelist=("html",))
        text, links = _html_to_text(html.get_content()) if html else ("", [])
    try:
        received = parsedate_to_datetime(str(m["Date"]))
    except (TypeError, ValueError):
        received = datetime.now(timezone.utc)
    atts = []
    for p in m.iter_attachments():
        data = p.get_payload(decode=True) or b""
        atts.append(AttachmentMeta(
            filename=p.get_filename() or "",
            mime_type=p.get_content_type(),
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        ))
    headers = {h: [str(v) for v in m.get_all(h, [])] for h in _HEADERS if m.get_all(h)}
    if m.get("DKIM-Signature"):
        headers["DKIM-Signature"] = ["present"]
    return NormalizedMessage(
        user_id=user_id, channel="email", external_id=external_id,
        sender=addr, sender_display_name=name or None,
        reply_to=parseaddr(str(m.get("Reply-To", "")))[1] or None,
        subject=str(m["Subject"]) if m["Subject"] else None,
        body_text=text, urls=list(dict.fromkeys(links + _URL.findall(text))), attachments=atts,
        headers=headers, received_at=received,
    )
