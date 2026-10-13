"""Provider interface. A provider only builds a request and interprets a response.

It never touches the network itself: the service owns transport, retries, timeouts, caching,
rate limits and the privacy gate, so those cannot be skipped by a provider.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from ..config import ThreatIntelConfig
from ..http import HttpRequest, HttpResponse
from ..types import ErrorCategory, Indicator, Outcome, ProviderError


class Provider:
    name: str = ""
    supported: frozenset = frozenset()
    key_env_attr: Optional[str] = None      # ThreatIntelConfig attribute naming the env var
    key_required: bool = False
    handled_statuses: frozenset = frozenset({200})   # statuses passed to interpret()
    rate_limit_statuses: frozenset = frozenset({429})

    def build_request(
        self, ind: Indicator, api_key: Optional[str], cfg: ThreatIntelConfig
    ) -> HttpRequest:
        raise NotImplementedError

    def interpret(
        self, ind: Indicator, resp: HttpResponse, now: datetime, cfg: ThreatIntelConfig
    ) -> Outcome:
        raise NotImplementedError


def json_object(resp: HttpResponse) -> dict:
    """Body as a JSON object, or ProviderError(MALFORMED_RESPONSE)."""
    if resp.truncated:
        raise ProviderError(ErrorCategory.MALFORMED_RESPONSE, "response exceeded size limit")
    try:
        data = json.loads(resp.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProviderError(ErrorCategory.MALFORMED_RESPONSE, "body is not valid JSON") from None
    if not isinstance(data, dict):
        raise ProviderError(ErrorCategory.UNKNOWN_FORMAT, "JSON root is not an object")
    return data


def unknown(detail: str) -> ProviderError:
    return ProviderError(ErrorCategory.UNKNOWN_FORMAT, detail)
