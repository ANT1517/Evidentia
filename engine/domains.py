"""Domain helpers shared by the parser and the rule checks.

Registered-domain lookup uses the Public Suffix List snapshot bundled with `tldextract`.
`suffix_list_urls=()` disables any network fetch, so results are offline and deterministic
for a pinned tldextract version.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Optional
from urllib.parse import urlsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Characters that look like ASCII but are not. Deliberately small and explicit.
_CONFUSABLES = {
    # digits that stand in for letters
    "0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t",
    # Cyrillic / Greek look-alikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l",
    "ο": "o", "ν": "v", "ρ": "p", "α": "a", "ι": "i",
}
_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def normalize_host(host: str) -> str:
    """Lower-case, strip trailing dot, NFKC-normalise, and decode punycode to Unicode."""
    host = unicodedata.normalize("NFKC", host.strip()).lower().rstrip(".")
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def _ascii_host(host: str) -> str:
    try:
        return normalize_host(host).encode("idna").decode("ascii")
    except UnicodeError:
        return normalize_host(host)


def host_of(url: str) -> Optional[str]:
    """Normalised hostname of a URL, or None if it has none."""
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:
        return None
    return normalize_host(host) if host else None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """eTLD+1 from the Public Suffix List (Unicode form, so skeletons can be compared).

    Unlisted TLDs follow the PSL default rule: the last label is the suffix.
    IP addresses and single labels are returned unchanged.
    """
    host = normalize_host(host)
    if not host or is_ip(host):
        return host
    r = _EXTRACT(_ascii_host(host))
    if r.top_domain_under_public_suffix:
        return normalize_host(r.top_domain_under_public_suffix)
    labels = [p for p in host.split(".") if p]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def domain_label(registered: str) -> str:
    """Name part of a registered domain: 'micros0ft-secure.example' -> 'micros0ft-secure'."""
    r = _EXTRACT(_ascii_host(registered))
    if r.domain and r.suffix:
        return normalize_host(r.domain)
    labels = [p for p in normalize_host(registered).split(".") if p]
    return labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")


def email_domain(address: str) -> str:
    """Normalised domain of an email address; '' if there is none."""
    return normalize_host(address.rsplit("@", 1)[1]) if "@" in address else ""


def skeleton(text: str) -> str:
    """Collapse look-alike characters so 'micros0ft', 'rnicrosoft' and 'microsoft' compare equal."""
    s = unicodedata.normalize("NFKC", text).lower()
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in s)
    for a, b in _MULTI:
        s = s.replace(a, b)
    return re.sub(r"[^a-z0-9\-]", "", s)


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
