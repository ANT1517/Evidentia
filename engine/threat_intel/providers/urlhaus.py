"""URLhaus API (abuse.ch): POST /v1/url/, /v1/host/, /v1/payload/. Header Auth-Key.

Lookup only. The /v1/download/ sample endpoint is never used, and URLs, payload links or
sample names found in a response are never fetched or even stored: only counts and
status words are kept. The documented host example misspells the status field
(`query_staus`), so both spellings are accepted.
"""
from __future__ import annotations

from datetime import datetime
from urllib.parse import urlencode

from ...schemas import EvidenceStatus as S
from ..config import URLHAUS, ThreatIntelConfig
from ..http import HttpRequest, HttpResponse
from ..types import ErrorCategory, FindingCategory as F, Indicator, IndicatorType as T, Outcome, ProviderError
from .base import Provider, json_object, unknown

_INVALID = {"invalid_url", "invalid_host", "invalid_sha256", "invalid_md5"}
_URL_STATES = {"online", "offline", "unknown"}


class URLhaus(Provider):
    name = URLHAUS
    supported = frozenset({T.URL, T.DOMAIN, T.SHA256})
    key_env_attr = "urlhaus_key_env"
    key_required = True

    def build_request(self, ind: Indicator, api_key, cfg: ThreatIntelConfig) -> HttpRequest:
        base = cfg.urlhaus_origin.rstrip("/") + "/v1"
        path, field = {
            T.URL: ("/url/", "url"),
            T.DOMAIN: ("/host/", "host"),
            T.SHA256: ("/payload/", "sha256_hash"),
        }[ind.type]
        return HttpRequest(
            "POST", base + path,
            headers={"Auth-Key": api_key or "",
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            body=urlencode({field: ind.value}).encode(),
        )

    def interpret(self, ind, resp: HttpResponse, now: datetime, cfg: ThreatIntelConfig) -> Outcome:
        body = json_object(resp)
        qs = body.get("query_status", body.get("query_staus"))
        if not isinstance(qs, str):
            raise unknown("missing query_status")
        if qs == "no_results":
            return Outcome(S.NOT_FOUND, F.NONE, {"note": "no URLhaus record"})
        if qs in _INVALID:
            raise ProviderError(ErrorCategory.INVALID_INDICATOR, qs)
        if qs != "ok":
            raise unknown(f"unrecognised query_status '{qs[:30]}'")

        if ind.type is T.URL:
            state = body.get("url_status")
            if not isinstance(state, str) or state not in _URL_STATES:
                raise unknown("url_status missing or unrecognised")
            threat = body.get("threat")
            return Outcome(S.FOUND, F.MALWARE_DISTRIBUTION, {
                "url_status": state,
                "threat": threat if isinstance(threat, str) else None,
            })

        if ind.type is T.DOMAIN:
            urls = body.get("urls")
            count = body.get("url_count")
            if isinstance(count, str) and count.isdigit():
                count = int(count)
            if not isinstance(urls, list) or not isinstance(count, int):
                raise unknown("host response lacks urls/url_count")
            online = sum(1 for u in urls if isinstance(u, dict) and u.get("url_status") == "online")
            return Outcome(S.FOUND, F.HOST_LISTED, {"url_count": count, "urls_online": online})

        # payload (hash)
        count = body.get("url_count")
        if isinstance(count, str) and count.isdigit():
            count = int(count)
        ftype = body.get("file_type")
        if not isinstance(count, int):
            raise unknown("payload response lacks url_count")
        return Outcome(S.FOUND, F.MALWARE_DISTRIBUTION, {
            "url_count": count, "file_type": ftype if isinstance(ftype, str) else None,
        })
