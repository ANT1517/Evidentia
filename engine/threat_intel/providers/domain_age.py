"""Domain registration age via RDAP (RFC 7480 family).

Queries the registry's RDAP server for the TLD from a configured map; the target domain
itself is never contacted. WHOIS (port 43) is intentionally NOT implemented: it needs raw
sockets to arbitrary hosts, which the origin guard forbids.

Age is computed against the injected `now`, so results are reproducible in tests.
A young domain is a weak signal on its own and never produces Urgent by policy.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ...schemas import EvidenceStatus as S
from ..config import DOMAIN_AGE, ThreatIntelConfig, usable_rdap_base
from ..http import HttpRequest, HttpResponse
from ..types import ErrorCategory, FindingCategory as F, Indicator, IndicatorType as T, Outcome, ProviderError
from .base import Provider, json_object, unknown

_DOMAIN = re.compile(r"^[a-z0-9.-]+$")


def _parse_when(text: str) -> datetime:
    t = text.strip()
    if t.endswith(("Z", "z")):
        t = t[:-1] + "+00:00"
    dt = datetime.fromisoformat(t)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class DomainAge(Provider):
    name = DOMAIN_AGE
    supported = frozenset({T.DOMAIN})
    key_env_attr = None
    key_required = False
    handled_statuses = frozenset({200, 404})

    def build_request(self, ind: Indicator, api_key, cfg: ThreatIntelConfig) -> HttpRequest:
        domain = ind.value
        if not _DOMAIN.match(domain):
            raise ProviderError(ErrorCategory.INVALID_INDICATOR, "unexpected characters in domain")
        tld = domain.rsplit(".", 1)[-1]
        base = usable_rdap_base(cfg.rdap_servers.get(tld))
        if not base:
            raise ProviderError(
                ErrorCategory.NO_DATA, f"no usable https RDAP endpoint configured for .{tld}")
        return HttpRequest("GET", base.rstrip("/") + f"/domain/{domain}",
                           headers={"Accept": "application/rdap+json"})

    def interpret(self, ind, resp: HttpResponse, now: datetime, cfg: ThreatIntelConfig) -> Outcome:
        if resp.status == 404:
            raise ProviderError(ErrorCategory.NO_DATA, "RDAP has no record for this domain")
        body = json_object(resp)
        events = body.get("events")
        if not isinstance(events, list):
            raise unknown("missing events list")
        registered = None
        for ev in events:
            if isinstance(ev, dict) and ev.get("eventAction") == "registration":
                raw = ev.get("eventDate")
                if isinstance(raw, str):
                    try:
                        registered = _parse_when(raw)
                    except ValueError:
                        raise unknown("registration date is not ISO 8601") from None
                break
        if registered is None:
            raise ProviderError(ErrorCategory.NO_DATA, "no registration date in RDAP response")
        age_days = (now - registered).days
        if age_days < 0:
            raise unknown("registration date is in the future")
        details = {"age_days": age_days, "registered": registered.date().isoformat()}
        if age_days < cfg.new_domain_days:
            return Outcome(S.FOUND, F.RECENTLY_REGISTERED, details)
        return Outcome(S.NOT_FOUND, F.REGISTRATION_KNOWN, details)
