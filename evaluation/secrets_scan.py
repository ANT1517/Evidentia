"""Offline detection of obvious secrets and personal data in message text.

Heuristics only: they catch careless inclusion, not a determined leak, and they cannot prove
that a text is free of personal data. A hit is reported as (rule, offsets), never the matched
text, so reports do not reproduce the sensitive value.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str          # "error" or "warning"
    start: int
    end: int


_RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost")
_RESERVED_DOMAINS = ("example.com", "example.org", "example.net")

_PATTERNS = [
    ("private_key_block", "error", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", "error", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", "error", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack_token", "error", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", "error", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", "error", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("secret_assignment", "error", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|passwd|password)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{20,}")),
    ("us_ssn", "error", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("aadhaar_like", "error", re.compile(r"(?<!\d)\d{4}\s\d{4}\s\d{4}(?!\d)")),
    ("phone_with_country_code", "warning", re.compile(r"(?<!\w)\+\d{1,3}[\s.-]?\(?\d[\d\s().-]{7,}\d")),
]
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"(?i)\bhttps?://[^\s<>\"')]+")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def iban_ok(s: str) -> bool:
    s = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in s)
    return int(num) % 97 == 1


def is_reserved_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    return (h.endswith(_RESERVED_SUFFIXES) or h in _RESERVED_DOMAINS
            or any(h.endswith("." + d) for d in _RESERVED_DOMAINS))


def scan_text(text: str, *, synthetic: bool) -> list:
    """All findings in `text`. For synthetic records, a URL on a non-reserved host is an error
    (synthetic data should never point at a real site); otherwise it is a warning."""
    found = []
    for rule, sev, rx in _PATTERNS:
        for m in rx.finditer(text):
            found.append(Finding(rule, sev, m.start(), m.end()))

    for m in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            found.append(Finding("possible_card_number", "error", m.start(), m.end()))

    for m in _IBAN.finditer(text):
        try:
            if iban_ok(m.group()):
                found.append(Finding("possible_iban", "error", m.start(), m.end()))
        except ValueError:
            pass

    for m in _EMAIL.finditer(text):
        if not is_reserved_host(m.group(1)):
            found.append(Finding("email_address_not_reserved_domain", "error", m.start(), m.end()))

    for m in _URL.finditer(text):
        host = urlsplit(m.group()).hostname or ""
        if host and not is_reserved_host(host):
            found.append(Finding("url_host_not_reserved", "error" if synthetic else "warning",
                                 m.start(), m.end()))
    return sorted(found, key=lambda f: (f.start, f.rule))
