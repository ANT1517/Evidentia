"""Shared fakes for threat-intelligence tests. No real network is ever touched."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Callable, Union
from urllib.parse import urlsplit

from engine.schemas import Attachment
from engine.threat_intel import (
    Clock,
    HttpRequest,
    HttpResponse,
    SharingPolicy,
    ThreatIntelConfig,
    ThreatIntelService,
    TransportError,
)
from helpers import NOW, make

KEY = "k-secret-123"
HASH = "a" * 64
DOMAIN = "phish-test.com"
URL_RAW = f"http://{DOMAIN}/login?token=SECRET-TOKEN#frag-part"
URL = f"http://{DOMAIN}/login"
ALL = frozenset({"urlhaus", "phishtank", "virustotal", "domain_age"})


class FakeClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.mono = 1000.0
        self.dt = now
        self.sleeps: list[float] = []

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.dt += timedelta(seconds=seconds)

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.advance(s)

    def clock(self) -> Clock:
        return Clock(now=lambda: self.dt, monotonic=lambda: self.mono, sleep=self.sleep)


Reply = Union[HttpResponse, Exception]


class FakeTransport:
    """Records every request; `handler(req)` returns a response or raises."""

    def __init__(self, handler: Callable[[HttpRequest], Reply] = None, on_call=None) -> None:
        self.handler = handler or route()
        self.calls: list[HttpRequest] = []
        self.on_call = on_call

    def request(self, req: HttpRequest, *, timeout: float, max_bytes: int) -> HttpResponse:
        self.calls.append(req)
        if self.on_call:
            self.on_call(req)
        out = self.handler(req)
        if isinstance(out, Exception):
            raise out
        return out

    def hosts(self) -> set:
        return {urlsplit(c.url).netloc for c in self.calls}


def jr(obj, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(obj).encode(), headers={})


def raw(body: bytes, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=body, headers={})


VT_CLEAN = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 10, "timeout": 0}}}}


def vt_stats(malicious=0, suspicious=0, harmless=60, undetected=10):
    return {"data": {"attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless,
        "undetected": undetected, "timeout": 0}}}}


def uh_listed(req):
    """URLhaus 'everything is listed' reply, shaped correctly for each endpoint."""
    if req.url.endswith("/v1/url/"):
        return jr({"query_status": "ok", "url_status": "online", "threat": "malware_download"})
    if req.url.endswith("/v1/host/"):
        return jr({"query_status": "ok", "url_count": 2,
                   "urls": [{"url_status": "online"}, {"url_status": "offline"}]})
    return jr({"query_status": "ok", "url_count": 1, "file_type": "exe"})


def uh_clean(req):
    return jr({"query_status": "no_results"})


def rdap(registered: str):
    return {"events": [{"eventAction": "registration", "eventDate": registered},
                       {"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}]}


def route(vt=None, uh=None, pt=None, rd=None):
    """Router with 'everything clean' defaults. Each override is a Reply or callable(req)."""
    defaults = {
        "vt": jr(VT_CLEAN),
        "uh": jr({"query_status": "no_results"}),
        "pt": jr({"meta": {}, "results": {"in_database": False}}),
        "rd": jr(rdap("2010-01-01T00:00:00Z")),
    }
    given = {"vt": vt, "uh": uh, "pt": pt, "rd": rd}

    def handler(req: HttpRequest) -> Reply:
        host = urlsplit(req.url).netloc
        k = ("vt" if "virustotal" in host else "uh" if "urlhaus" in host
             else "pt" if "phishtank" in host else "rd")
        v = given[k] if given[k] is not None else defaults[k]
        return v(req) if callable(v) else v

    return handler


def sharing(urls=(URL,), domains=(DOMAIN,), hashes=(HASH,), denied=()) -> SharingPolicy:
    return SharingPolicy(
        approved_urls=frozenset(urls), approved_domains=frozenset(domains),
        approved_sha256=frozenset(hashes), denied_domains=frozenset(denied),
    )


def cfg(**over) -> ThreatIntelConfig:
    base = dict(enabled=True, enabled_providers=ALL, virustotal_live_enabled=True,
                sharing=sharing(), retry_backoff_s=0.0)
    base.update(over)
    return ThreatIntelConfig(**base)


def service(handler=None, config=None, clock: FakeClock = None, keys=None, **kw):
    fc = clock or FakeClock()
    tr = FakeTransport(handler)
    kp = (lambda n: KEY) if keys is None else (lambda n: keys.get(n))
    svc = ThreatIntelService(config or cfg(), transport=tr, clock=fc.clock(), key_provider=kp, **kw)
    return svc, tr, fc


def msg(**over):
    base = dict(
        sender=f"billing@{DOMAIN}",
        urls=[URL_RAW],
        attachments=[Attachment(filename="invoice.pdf.exe", content_type="application/x-msdownload",
                                size=10, sha256=HASH)],
        body_text="CONFIDENTIAL BODY TEXT do-not-leak",
    )
    base.update(over)
    return make(**base)


def bare_msg(**over):
    """Like msg() but its URL has no query string or fragment, so lookups cover it fully."""
    return msg(**{"urls": [URL], **over})


def timeout() -> TransportError:
    return TransportError("timeout", "TimeoutError")
