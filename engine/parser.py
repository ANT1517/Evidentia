"""Safe MIME parser: raw email bytes -> NormalizedMessage.

Nothing here renders HTML, opens an attachment or fetches a URL. Attachments are only
measured and hashed; HTML is flattened to text by a tokenizer that drops script/style.
"""
from __future__ import annotations

import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser
from typing import Optional

from .domains import host_of, registered_domain
from .schemas import (
    Attachment,
    AuthResults,
    Channel,
    IngestSource,
    LinkMismatch,
    NormalizedMessage,
)

MAX_BODY_CHARS = 200_000
MAX_URLS = 200

_URL_RE = re.compile(r"""https?://[^\s<>"'\)\]]+""", re.IGNORECASE)
_TRAILING_PUNCT = ".,;:!?)]}>'\""
_SHOWN_DOMAIN_RE = re.compile(
    r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#\s]|$)", re.IGNORECASE
)
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_RECEIVED_SPF_RE = re.compile(r"^\s*([a-z]+)", re.IGNORECASE)

_BLOCK_TAGS = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "hr"}
_SKIP_TAGS = {"script", "style", "head", "title"}


class _HtmlToText(HTMLParser):
    """Flattens HTML to text and records every <a href> with its visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[tuple[str, str]] = []   # (href, visible text)
        self.srcs: list[str] = []
        self._skip = 0
        self._href: Optional[str] = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip += 1
            return
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href = a["href"]
            self._anchor_text = []
        if tag in ("img", "iframe", "form") and (a.get("src") or a.get("action")):
            self.srcs.append(a.get("src") or a.get("action"))
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
            return
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor_text).strip()))
            self._href = None
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        raw = re.sub(r"\n\s*\n+", "\n\n", raw)
        return raw.strip()


def _html_to_text(html: str) -> tuple[str, list[tuple[str, str]], list[str]]:
    p = _HtmlToText()
    try:
        p.feed(html)
        p.close()
    except Exception:  # malformed HTML must never break the pipeline
        pass
    return p.text(), p.links, p.srcs


def _part_text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _clean_url(url: str) -> str:
    return url.strip().rstrip(_TRAILING_PUNCT)


def _dedupe(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for it in items:
        if it and it not in seen:
            seen[it] = None
    return list(seen)


def _parse_auth(msg: EmailMessage) -> AuthResults:
    """Read results from the topmost Authentication-Results header only.

    The topmost header is the one added by the server that received the mail. Lower ones
    were present before delivery and can be forged by the sender, so they are ignored.
    Whether the topmost header itself can be believed depends on how the message reached
    us (see rules.auth_trust); the parser only reports what it saw and who claimed it.
    """
    for name, value in msg.items():
        if name.lower() != "authentication-results":
            continue
        text = str(value)
        authserv = text.split(";", 1)[0].strip().split()[0].lower() if text.strip() else None
        found: dict[str, str] = {}
        for mech, result in _AUTH_RE.findall(text):
            found.setdefault(mech.lower(), result.lower())
        return AuthResults(
            spf=found.get("spf"),
            dkim=found.get("dkim"),
            dmarc=found.get("dmarc"),
            authserv_id=authserv,
        )
    rspf = msg.get("Received-SPF")
    if rspf:
        m = _RECEIVED_SPF_RE.match(str(rspf))
        if m:
            # No authserv_id: this header is self-declared and is never treated as trusted.
            return AuthResults(spf=m.group(1).lower())
    return AuthResults()


def _address(msg: EmailMessage, header: str) -> tuple[str, str]:
    """(display_name, addr_spec) of the first address in a header, '' if absent."""
    try:
        hdr = msg[header]
        if hdr is None:
            return "", ""
        addrs = getattr(hdr, "addresses", None)
        if addrs:
            return addrs[0].display_name or "", (addrs[0].addr_spec or "").lower()
    except Exception:
        pass
    return "", ""


def _mismatches(links: list[tuple[str, str]]) -> list[LinkMismatch]:
    out: list[LinkMismatch] = []
    for href, text in links:
        href_host = host_of(href)
        m = _SHOWN_DOMAIN_RE.search(text or "")
        if not href_host or not m:
            continue
        shown = m.group(1).lower()
        if registered_domain(shown) != registered_domain(href_host):
            out.append(
                LinkMismatch(
                    shown_domain=registered_domain(shown),
                    href=_clean_url(href),
                    href_domain=registered_domain(href_host),
                )
            )
    return out


def parse_email(
    raw: bytes,
    external_id: str,
    user_id: Optional[int] = None,
    channel: Channel = Channel.EMAIL,
    ingest_source: IngestSource = IngestSource.UNKNOWN,
) -> NormalizedMessage:
    """Parse raw RFC 5322 bytes into a NormalizedMessage. Never raises on bad mail."""
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)  # type: ignore[assignment]

    display_name, sender = _address(msg, "From")
    _, reply_to = _address(msg, "Reply-To")

    plain_parts: list[str] = []
    html_texts: list[str] = []
    all_links: list[tuple[str, str]] = []
    html_urls: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()

        if filename or disposition == "attachment":
            data = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=str(filename or ""),
                    content_type=ctype,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest() if data else None,
                )
            )
            continue

        if ctype == "text/plain":
            plain_parts.append(_part_text(part))
        elif ctype == "text/html":
            text, links, srcs = _html_to_text(_part_text(part))
            html_texts.append(text)
            all_links.extend(links)
            html_urls.extend(l[0] for l in links)
            html_urls.extend(srcs)

    # Prefer the sender's plain text; fall back to the flattened HTML.
    body = "\n\n".join(p.strip() for p in plain_parts if p.strip())
    if not body:
        body = "\n\n".join(t for t in html_texts if t)
    body = body[:MAX_BODY_CHARS]

    urls = _dedupe(
        [_clean_url(u) for u in _URL_RE.findall(body)]
        + [_clean_url(u) for u in html_urls if re.match(r"https?://", u.strip(), re.I)]
    )[:MAX_URLS]

    return NormalizedMessage(
        external_id=external_id,
        channel=channel,
        user_id=user_id,
        sender=sender,
        sender_display_name=display_name,
        reply_to=reply_to,
        subject=str(msg["Subject"] or ""),
        body_text=body,
        urls=urls,
        attachments=attachments,
        link_mismatches=_mismatches(all_links),
        auth=_parse_auth(msg),
        ingest_source=ingest_source,
    )
