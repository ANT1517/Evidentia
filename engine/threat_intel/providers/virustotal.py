"""VirusTotal API v3: GET /urls/{id}, /domains/{domain}, /files/{sha256}. Header x-apikey.

Lookup only. This module never calls POST /urls or POST /files (which would submit data for
scanning). Public quota (documented): 4 requests/minute, 500/day, non-commercial use only.
Note: VirusTotal's docs warn that a queried domain may be scanned and added to its dataset,
which is why the privacy gate and a separate live-lookup switch exist.

The fetched docs pages did not document response bodies, so parsing relies on the widely used
v3 object shape (data.attributes.last_analysis_stats) and treats anything else as
UNKNOWN_FORMAT rather than guessing.
"""
from __future__ import annotations

import base64
from datetime import datetime

from ...schemas import EvidenceStatus as S
from ..config import VIRUSTOTAL, ThreatIntelConfig
from ..http import HttpRequest, HttpResponse
from ..types import ErrorCategory, FindingCategory as F, Indicator, IndicatorType as T, Outcome, ProviderError
from .base import Provider, json_object, unknown

_STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected", "timeout")


class VirusTotal(Provider):
    name = VIRUSTOTAL
    supported = frozenset({T.URL, T.DOMAIN, T.SHA256})
    key_env_attr = "virustotal_key_env"
    key_required = True
    handled_statuses = frozenset({200, 404})

    def build_request(self, ind: Indicator, api_key, cfg: ThreatIntelConfig) -> HttpRequest:
        base = cfg.virustotal_origin.rstrip("/") + "/api/v3"
        if ind.type is T.URL:
            ident = base64.urlsafe_b64encode(ind.value.encode()).decode().rstrip("=")
            path = f"/urls/{ident}"
        elif ind.type is T.DOMAIN:
            path = f"/domains/{ind.value}"
        else:
            path = f"/files/{ind.value}"
        return HttpRequest("GET", base + path, headers={"x-apikey": api_key or "",
                                                         "accept": "application/json"})

    def interpret(self, ind, resp: HttpResponse, now: datetime, cfg: ThreatIntelConfig) -> Outcome:
        body = json_object(resp)
        if resp.status == 404:
            err = body.get("error")
            if isinstance(err, dict) and err.get("code") == "NotFoundError":
                return Outcome(S.NOT_FOUND, F.NONE, {"note": "no record at VirusTotal"})
            raise unknown("404 without a NotFoundError body")

        attrs = (body.get("data") or {}).get("attributes") if isinstance(body.get("data"), dict) else None
        stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
        if not isinstance(stats, dict):
            raise unknown("missing data.attributes.last_analysis_stats")
        counts = {}
        for k in _STAT_KEYS:
            v = stats.get(k, 0)
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise unknown(f"last_analysis_stats.{k} is not a non-negative integer")
            counts[k] = v
        total = sum(counts.values())
        details = {**counts, "vendors": total}
        if total == 0:
            return Outcome(S.NOT_CHECKED, F.NOT_AVAILABLE, {"note": "record exists, never analysed"})

        mal, sus = counts["malicious"], counts["suspicious"]
        if mal >= cfg.vt_urgent_min:
            return Outcome(S.FOUND, F.MALICIOUS, details)
        if mal >= cfg.vt_review_min or sus >= cfg.vt_review_min:
            return Outcome(S.FOUND, F.SUSPICIOUS, details)
        if mal >= 1 or sus >= 1:
            return Outcome(S.FOUND, F.LOW_CONFIDENCE, details)
        return Outcome(S.NOT_FOUND, F.NONE, details)
