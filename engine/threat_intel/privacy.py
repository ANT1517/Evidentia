"""Indicator normalisation and the central sharing gate.

Every external lookup goes through `check_sharing()` first. The gate is deny-by-default:
an indicator leaves the process only if an operator listed it in SharingPolicy. Query
strings, fragments and credentials are stripped before anything is compared or sent, and an
URL carrying credentials is refused outright. Message bodies, MIME and attachment contents
never reach this module at all: only these three indicator types exist.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import unquote, urlsplit

from ..domains import host_of, is_ip, registered_domain, to_ascii_host
from .config import SharingPolicy
from .types import Indicator, IndicatorType

MAX_URL_LEN = 2048
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# Names that are internal by convention; never sent even if someone approves them by mistake.
_INTERNAL_SUFFIXES = {"local", "internal", "corp", "lan", "home", "intranet", "localhost", "private"}


def normalize_url(raw: str) -> Optional[Indicator]:
    """http(s) URL -> scheme://host[:port]/path with query, fragment and credentials removed."""
    raw = (raw or "").strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE) or len(raw) > 8192:
        return None
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname
    if not host:
        return None
    ascii_host = to_ascii_host(host)
    if not all(_LABEL.match(l) for l in ascii_host.split(".")) and not is_ip(ascii_host):
        return None
    scheme = parts.scheme.lower()
    default = 443 if scheme == "https" else 80
    netloc = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    if port and port != default:
        netloc += f":{port}"
    value = f"{scheme}://{netloc}{parts.path or '/'}"
    if len(value) > MAX_URL_LEN:
        return None
    flags = set()
    if parts.query:
        flags.add("had_query")
    if parts.fragment:
        flags.add("had_fragment")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        flags.add("had_credentials")
    return Indicator(IndicatorType.URL, value, original=raw, flags=frozenset(flags))


def normalize_domain(host: str) -> Optional[Indicator]:
    """Any host -> its registered domain in ASCII form. IPs and single labels are rejected."""
    host = (host or "").strip().strip(".")
    if not host or is_ip(host):
        return None
    reg = to_ascii_host(registered_domain(host))
    labels = reg.split(".")
    if len(labels) < 2 or not all(_LABEL.match(l) for l in labels):
        return None
    return Indicator(IndicatorType.DOMAIN, reg, original=host)


def normalize_sha256(raw: str) -> Optional[Indicator]:
    v = (raw or "").strip().lower()
    return Indicator(IndicatorType.SHA256, v, original=raw) if _SHA256.match(v) else None


def _host_is_sensitive(host: str) -> Optional[str]:
    if is_ip(host):
        ip = ipaddress.ip_address(host.strip("[]"))
        if not ip.is_global:
            return "private or reserved IP address"
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return "single-label (internal) host name"
    if labels[-1] in _INTERNAL_SUFFIXES or host.endswith(".home.arpa"):
        return "internal host name"
    return None


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_B64ISH = re.compile(r"^[A-Za-z0-9_+=]{24,}$")
_JWT = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")
_LONG_NUMBER = re.compile(r"^\d{12,}$")


def _token_like(segment: str) -> bool:
    """Does one path segment or host label look like a secret, id or personal data?"""
    seg = unquote(segment)
    if not seg:
        return False
    if "@" in seg or _UUID.match(seg) or _HEX.match(seg) or _JWT.match(seg):
        return True
    if _LONG_NUMBER.match(seg):
        return True
    if _B64ISH.match(seg) and re.search(r"[A-Za-z]", seg) and re.search(r"\d", seg):
        return True
    return False


def sensitive_reason(url_value: str) -> Optional[str]:
    """Heuristic: why this normalised URL might embed a token or private data, else None.

    Deliberately conservative: a refusal costs one lookup, a leak cannot be taken back.
    """
    parts = urlsplit(url_value)
    host = parts.hostname or ""
    if "@" in parts.netloc:
        return "URL contains embedded credentials"
    if ";" in parts.path and "=" in parts.path:
        return "path contains parameters that may carry a session or token"
    if any(_token_like(seg) for seg in parts.path.split("/")):
        return "path looks like it contains a token, identifier or personal data"
    reg = registered_domain(host) if host and not is_ip(host) else host
    sub = host[: -len(reg)].strip(".") if reg and host.endswith(reg) else ""
    if sub and any(_token_like(l) for l in sub.split(".")):
        return "host name contains an identifier-like label"
    return None


def check_sharing(ind: Indicator, policy: SharingPolicy) -> Optional[str]:
    """Return a refusal reason, or None if this indicator may be sent to an external provider."""
    if ind.type is IndicatorType.SHA256:
        if ind.value not in policy.approved_sha256:
            return "file hash is not on the approved-to-share list"
        return None

    host = host_of(ind.value) if ind.type is IndicatorType.URL else ind.value
    if not host:
        return "no host to evaluate"
    reg = registered_domain(host)
    if reg in policy.denied_domains or host in policy.denied_domains:
        return "protected company domain: never shared"
    why = _host_is_sensitive(host)
    if why:
        return why

    if ind.type is IndicatorType.URL:
        if "had_credentials" in ind.flags:
            return "URL contains embedded credentials"
        looks = sensitive_reason(ind.value)
        if looks and ind.value not in policy.reviewed_token_like_urls:
            return looks + " (approve it under reviewed_token_like_urls only if it is public)"
        if ind.value not in policy.approved_urls:
            return "URL is not on the approved-to-share list"
        return None
    if reg not in policy.approved_domains:
        return "domain is not on the approved-to-share list"
    return None


def audit_policy(policy: SharingPolicy) -> list:
    """Problems that would make an approval list accidentally authorise something unsafe.

    Run at service start-up (fail closed). Messages describe the entry by redacted
    reference or position, never by echoing a raw value.
    """
    problems: list = []
    for n, u in enumerate(sorted(policy.approved_urls), 1):
        ind = normalize_url(u)
        if ind is None:
            problems.append(f"approved_urls[{n}]: not a valid http(s) URL")
            continue
        if ind.flags:
            problems.append(f"approved_urls {ind.ref}: has a query string, fragment or credentials; "
                            f"approve the bare URL instead")
            continue
        if ind.value != u:
            problems.append(f"approved_urls {ind.ref}: not in normalised form")
            continue
        why = sensitive_reason(ind.value)
        if why and u not in policy.reviewed_token_like_urls:
            problems.append(f"approved_urls {ind.ref}: {why}; list it under "
                            f"reviewed_token_like_urls only after confirming it is public")
        if "@" in urlsplit(ind.value).netloc:
            problems.append(f"approved_urls {ind.ref}: credentials can never be approved")
    for u in sorted(policy.reviewed_token_like_urls - policy.approved_urls):
        problems.append("reviewed_token_like_urls: entry is not also in approved_urls")
    for n, d in enumerate(sorted(policy.approved_domains), 1):
        ind = normalize_domain(d)
        if ind is None or ind.value != d:
            problems.append(f"approved_domains[{n}]: must be a lower-case registered domain "
                            f"(no scheme, path, wildcard or subdomain)")
    for n, h in enumerate(sorted(policy.approved_sha256), 1):
        if not _SHA256.match(h):
            problems.append(f"approved_sha256[{n}]: must be 64 lower-case hex characters")
    return problems
