"""PhishTank check-URL API: POST /checkurl/ (format=json, optional app_key).

Documented over plain http://; this adapter uses https:// only and never falls back, so if
the endpoint does not serve TLS the lookup is NOT_CHECKED, not downgraded.
The docs give no formal JSON schema and show `verified`/`valid` both as 'y' and as booleans,
so both are accepted and anything else is UNKNOWN_FORMAT.

Four outcomes are kept distinct:
  in_database false                 -> NOT_FOUND (PhishTank has no entry; not "safe")
  in database, verified and valid   -> FOUND / PHISHING_VERIFIED
  in database, not yet verified     -> FOUND / PHISHING_UNVERIFIED
  in database, verified not-valid   -> NOT_FOUND (PhishTank judged it not phishing)
  request failed / unreadable       -> NOT_CHECKED (by the service)
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from urllib.parse import urlencode

from ...schemas import EvidenceStatus as S
from ..config import PHISHTANK, ThreatIntelConfig
from ..http import HttpRequest, HttpResponse
from ..types import FindingCategory as F, Indicator, IndicatorType as T, Outcome
from .base import Provider, json_object, unknown

_TRUE = {"y", "yes", "true", "1"}
_FALSE = {"n", "no", "false", "0"}


def _flag(v) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in _TRUE:
            return True
        if s in _FALSE:
            return False
    return None


class PhishTank(Provider):
    name = PHISHTANK
    supported = frozenset({T.URL})
    key_env_attr = "phishtank_key_env"
    key_required = False                      # optional: without it limits are tighter
    rate_limit_statuses = frozenset({429, 509})

    def build_request(self, ind: Indicator, api_key, cfg: ThreatIntelConfig) -> HttpRequest:
        form = {"url": ind.value, "format": "json"}
        if api_key:
            form["app_key"] = api_key
        return HttpRequest(
            "POST", cfg.phishtank_origin.rstrip("/") + "/checkurl/",
            headers={"User-Agent": cfg.phishtank_user_agent,
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            body=urlencode(form).encode(),
        )

    def interpret(self, ind, resp: HttpResponse, now: datetime, cfg: ThreatIntelConfig) -> Outcome:
        body = json_object(resp)
        res = body.get("results", body)
        if not isinstance(res, dict) or "in_database" not in res:
            raise unknown("missing results.in_database")
        in_db = _flag(res.get("in_database"))
        if in_db is None:
            raise unknown("in_database is not a boolean")
        if not in_db:
            return Outcome(S.NOT_FOUND, F.NONE, {"note": "no PhishTank entry"})

        verified = _flag(res.get("verified")) if "verified" in res else False
        if verified is None:
            raise unknown("verified is not a recognised flag")
        if not verified:
            return Outcome(S.FOUND, F.PHISHING_UNVERIFIED, {"verified": False})
        valid = _flag(res.get("valid"))
        if valid is None:
            raise unknown("verified entry lacks a recognised valid flag")
        if valid:
            return Outcome(S.FOUND, F.PHISHING_VERIFIED, {"verified": True, "valid": True})
        return Outcome(S.NOT_FOUND, F.NONE, {"verified": True, "valid": False,
                                             "note": "PhishTank judged this not phishing"})
