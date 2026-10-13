import http.client
import ssl
import urllib.request
import webbrowser

import pytest

from engine.schemas import Attachment, EvidenceStatus as S
from engine.threat_intel import (
    ErrorCategory as E,
    HttpRequest,
    HttpResponse,
    RateLimiter,
    StdlibTransport,
    TransportError,
)
from engine.threat_intel.evidence import build_check_result
from engine.threat_intel.http import GuardedClient, OriginNotAllowed
from engine.threat_intel.runtime import InMemoryTTLCache, cache_key
from engine.threat_intel.privacy import normalize_url
from helpers import NOW
from ti_helpers import (
    DOMAIN, HASH, KEY, URL, FakeClock, FakeTransport, cfg, jr, msg, raw, route, service,
    sharing, timeout, uh_clean, uh_listed, vt_stats,
)

UH_ONLY = dict(enabled_providers=frozenset({"urlhaus"}))
VT_ONLY = dict(enabled_providers=frozenset({"virustotal"}))
URL_ONLY_MSG = dict(sender="", urls=[URL], attachments=[])


def urlhaus_calls(tr):
    return [c for c in tr.calls if "urlhaus" in c.url]


# ------------------------------------------------------------------ cache

def test_positive_and_negative_results_are_cached_and_marked():
    for body, status in ((uh_listed, S.FOUND), (uh_clean, S.NOT_FOUND)):
        svc, tr, _ = service(route(uh=body), config=cfg(**UH_ONLY))
        m = msg(**URL_ONLY_MSG)
        first = svc.lookup_message(m, now=NOW)
        n = len(tr.calls)
        second = svc.lookup_message(m, now=NOW)
        assert len(tr.calls) == n                       # no new request
        r1 = [r for r in first.results if r.indicator_type.value == "url"][0]
        r2 = [r for r in second.results if r.indicator_type.value == "url"][0]
        assert (r1.cache_hit, r2.cache_hit) == (False, True)
        assert r2.status is r1.status is status


def test_cache_ttls_are_configurable_and_expire():
    svc, tr, fc = service(route(uh=jr({"query_status": "no_results"})),
                          config=cfg(ttl_not_found_s=100, **UH_ONLY))
    m = msg(**URL_ONLY_MSG)
    svc.lookup_message(m, now=NOW)
    n = len(tr.calls)
    fc.advance(99)
    svc.lookup_message(m, now=NOW)
    assert len(tr.calls) == n
    fc.advance(2)
    svc.lookup_message(m, now=NOW)
    assert len(tr.calls) > n


def test_found_and_not_found_use_separate_ttls():
    svc, tr, fc = service(route(uh=uh_listed),
                          config=cfg(ttl_found_s=1000, ttl_not_found_s=1, **UH_ONLY))
    m = msg(**URL_ONLY_MSG)
    svc.lookup_message(m, now=NOW)
    n = len(tr.calls)
    fc.advance(500)
    svc.lookup_message(m, now=NOW)
    assert len(tr.calls) == n


@pytest.mark.parametrize("bad", [
    lambda: raw(b"boom", 500), lambda: raw(b"{}", 429), lambda: raw(b"{}", 401),
    lambda: timeout(), lambda: raw(b"not json"), lambda: jr({"query_status": "mystery"}),
])
def test_transient_failures_are_never_cached_as_clean(bad):
    state = {"fail": True}

    def uh(req):
        return bad() if state["fail"] else jr({"query_status": "no_results"})

    svc, tr, _ = service(route(uh=uh), config=cfg(max_retries=0, **UH_ONLY))
    m = msg(**URL_ONLY_MSG)
    first = svc.lookup_message(m, now=NOW)
    assert all(r.status is S.NOT_CHECKED for r in first.results)
    state["fail"] = False
    second = svc.lookup_message(m, now=NOW)
    assert all(r.status is S.NOT_FOUND and not r.cache_hit for r in second.results)


def test_cache_key_has_provider_type_and_normalised_indicator_without_raw_value():
    a = normalize_url("http://Phish-Test.com/login?x=1")
    b = normalize_url("http://phish-test.com/login#frag")
    assert cache_key("urlhaus", a) == cache_key("urlhaus", b)
    assert cache_key("urlhaus", a) != cache_key("phishtank", a)
    assert cache_key("urlhaus", a).startswith("urlhaus|url|")
    assert "phish-test" not in cache_key("urlhaus", a)


def test_cache_is_bounded():
    fc = FakeClock()
    c = InMemoryTTLCache(fc.clock(), max_entries=2)
    svc, _, _ = service()
    rep = svc.lookup_message(msg(), now=NOW)
    r = rep.results[0]
    for i in range(5):
        c.set(f"k{i}", r, 100)
    assert c.get("k0") is None and c.get("k4") is r


# ------------------------------------------------------------------ retries, deadline, partial

def test_one_retry_on_timeout_then_success():
    calls = {"n": 0}

    def uh(req):
        calls["n"] += 1
        return timeout() if calls["n"] == 1 else jr({"query_status": "no_results"})

    svc, tr, fc = service(route(uh=uh), config=cfg(retry_backoff_s=0.5, **UH_ONLY))
    rep = svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
    assert rep.results[0].status is S.NOT_FOUND
    assert fc.sleeps == [0.5]


def test_retries_are_bounded_and_not_used_for_auth_or_rate_limit():
    svc, tr, _ = service(route(uh=raw(b"x", 500)), config=cfg(max_retries=2, **UH_ONLY))
    svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
    assert len(urlhaus_calls(tr)) == 3 * 2          # (1 + 2 retries) for the URL and for its host
    for status in (401, 429):
        svc, tr, _ = service(route(uh=raw(b"{}", status)), config=cfg(max_retries=3, **UH_ONLY))
        svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
        assert len(urlhaus_calls(tr)) == 2           # one per indicator, no retries


def test_per_request_timeout_never_exceeds_remaining_deadline():
    seen = []

    class T(FakeTransport):
        def request(self, req, *, timeout, max_bytes):
            seen.append(timeout)
            return super().request(req, timeout=timeout, max_bytes=max_bytes)

    fc = FakeClock()
    from engine.threat_intel import ThreatIntelService
    svc = ThreatIntelService(cfg(timeout_s=5.0, deadline_s=3.0, **UH_ONLY), transport=T(),
                             clock=fc.clock(), key_provider=lambda n: KEY)
    svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
    assert seen and max(seen) <= 3.0


def test_deadline_stops_further_lookups_but_keeps_partial_results():
    fc = FakeClock()

    def uh(req):
        fc.advance(6)                                # each URLhaus call burns 6 s
        return jr({"query_status": "ok", "url_status": "online"})

    svc, tr, _ = service(route(uh=uh), config=cfg(deadline_s=10.0), clock=fc)
    rep = svc.lookup_message(msg(), now=NOW)
    assert rep.deadline_hit
    done = [r for r in rep.results if r.conclusive]
    late = [r for r in rep.results if r.error is E.DEADLINE_EXCEEDED]
    assert done and late                             # partial results preserved
    assert any(r.status is S.FOUND for r in done)
    assert not build_check_result(rep, svc.cfg, NOW).completed


def test_one_provider_failing_does_not_hide_the_others():
    svc, tr, _ = service(route(uh=raw(b"", 500), pt=jr({"results": {"in_database": True,
                          "verified": "y", "valid": "y"}})),
                         config=cfg(enabled_providers=frozenset({"urlhaus", "phishtank"}),
                                    max_retries=0))
    rep = svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
    by = {(r.provider, r.indicator_type.value): r for r in rep.results}
    assert by[("urlhaus", "url")].status is S.NOT_CHECKED
    assert by[("phishtank", "url")].status is S.FOUND


# ------------------------------------------------------------------ dedupe, limits

def test_identical_indicators_are_looked_up_once():
    m = msg(sender=f"a@{DOMAIN}", urls=[URL, URL + "?a=1", URL + "#x", f"HTTP://{DOMAIN.upper()}/login"],
            attachments=[Attachment(filename="a", sha256=HASH), Attachment(filename="b", sha256=HASH.upper())])
    svc, tr, _ = service(route())
    rep = svc.lookup_message(m, now=NOW)
    assert rep.indicators_total == 3                 # 1 hash, 1 url, 1 domain
    per_pair = [(c.url, c.body) for c in tr.calls]
    assert len(per_pair) == len(set(per_pair))


def test_per_message_indicator_cap_and_ledger_row():
    urls = [f"http://phish-test.com/p{i}" for i in range(12)]
    sh = sharing(urls=urls)
    svc, tr, _ = service(route(), config=cfg(sharing=sh, max_indicators_per_message=10, **UH_ONLY))
    rep = svc.lookup_message(msg(sender="", urls=urls, attachments=[]), now=NOW)
    assert rep.indicators_total == 13 and rep.skipped_indicators == 3
    assert len(rep.indicators) == 10
    cr = build_check_result(rep, svc.cfg, NOW)
    assert not cr.completed
    assert any(e.type == "threat_intel_limit" and e.status is S.NOT_CHECKED for e in cr.evidence)


def test_provider_rate_limit_is_enforced_and_recovers():
    hashes = [f"{i:064x}" for i in range(6)]
    atts = [Attachment(filename=f"f{i}", sha256=h) for i, h in enumerate(hashes)]
    svc, tr, fc = service(route(), config=cfg(sharing=sharing(hashes=hashes), **VT_ONLY))
    m = msg(sender="", urls=[], attachments=atts)
    rep = svc.lookup_message(m, now=NOW)
    sent = [c for c in tr.calls if "virustotal" in c.url]
    assert len(sent) == 4                            # public quota: 4 per minute
    limited = [r for r in rep.results if r.error is E.RATE_LIMITED]
    assert len(limited) == 2 and all(r.status is S.NOT_CHECKED for r in limited)
    fc.advance(61)
    svc.lookup_message(msg(sender="", urls=[], attachments=atts[4:5].copy()), now=NOW)
    assert len([c for c in tr.calls if "virustotal" in c.url]) == 5


def test_rate_limiter_windows_independent_per_provider():
    fc = FakeClock()
    rl = RateLimiter(fc.clock(), {"a": ((1, 60),), "b": ((1, 60),)})
    assert rl.try_acquire("a") and not rl.try_acquire("a")
    assert rl.try_acquire("b")
    assert rl.try_acquire("unlisted")


def test_multiple_windows_all_apply():
    """3 per 10 s AND 5 per 1000 s: the longer window caps the total."""
    fc = FakeClock()
    rl = RateLimiter(fc.clock(), {"v": ((3, 10), (5, 1000))})
    granted = 0
    for _ in range(20):
        if rl.try_acquire("v"):
            granted += 1
        fc.advance(4)
    assert granted == 5


def test_documented_virustotal_public_quota_is_the_default():
    from engine.threat_intel import DEFAULT_TI_CONFIG
    assert DEFAULT_TI_CONFIG.rate_limits["virustotal"] == ((4, 60), (500, 86_400))


# ------------------------------------------------------------------ network containment

def test_guard_refuses_unconfigured_hosts_schemes_and_userinfo():
    tr = FakeTransport()
    g = GuardedClient(tr, frozenset({"https://urlhaus-api.abuse.ch"}), 1000)
    for url in ("https://evil.example/x", "http://urlhaus-api.abuse.ch/v1/url/",
                "https://urlhaus-api.abuse.ch@evil.example/", "https://urlhaus-api.abuse.ch.evil.example/"):
        with pytest.raises(OriginNotAllowed):
            g.send(HttpRequest("GET", url), 1.0)
    assert tr.calls == []
    g.send(HttpRequest("GET", "https://urlhaus-api.abuse.ch/v1/url/"), 1.0)
    assert len(tr.calls) == 1


def test_every_request_goes_only_to_configured_provider_origins():
    svc, tr, _ = service()
    svc.lookup_message(msg(), now=NOW)
    assert tr.calls
    assert tr.hosts() <= {"www.virustotal.com", "urlhaus-api.abuse.ch",
                          "checkurl.phishtank.com", "rdap.verisign.com"}
    assert all(DOMAIN not in c.url.split("/")[2] for c in tr.calls)   # never the message's host


def test_redirect_responses_are_refused_and_not_followed():
    hdr = {"location": "https://evil.example/steal"}
    svc, tr, _ = service(route(uh=HttpResponse(302, b"", hdr)), config=cfg(**UH_ONLY))
    rep = svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
    assert all(r.error is E.REDIRECT_REFUSED for r in rep.results)
    assert "evil.example" not in tr.hosts()
    assert len(tr.calls) == 2                        # one per indicator; no follow-up request


def test_stdlib_transport_never_follows_redirects_and_verifies_tls(monkeypatch):
    made = []

    class Resp:
        status = 302

        def read(self, n):
            return b""

        def getheaders(self):
            return [("Location", "https://evil.example/")]

    class Conn:
        def __init__(self, host, port, timeout, context):
            made.append((host, port, timeout, context, []))
            self.log = made[-1][4]

        def request(self, method, target, body=None, headers=None):
            self.log.append((method, target))

        def getresponse(self):
            return Resp()

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Conn)
    out = StdlibTransport().request(HttpRequest("GET", "https://www.virustotal.com/api/v3/x"),
                                    timeout=2.0, max_bytes=100)
    assert out.status == 302 and out.headers["location"] == "https://evil.example/"
    assert len(made) == 1 and len(made[0][4]) == 1           # exactly one request, no follow
    ctx = made[0][3]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    assert made[0][0] == "www.virustotal.com"


def test_stdlib_transport_maps_timeouts_and_rejects_plain_http(monkeypatch):
    class Boom:
        def __init__(self, *a, **k): pass
        def request(self, *a, **k): raise TimeoutError()
        def close(self): pass

    monkeypatch.setattr(http.client, "HTTPSConnection", Boom)
    with pytest.raises(TransportError) as e:
        StdlibTransport().request(HttpRequest("GET", "https://a.example/"), timeout=1, max_bytes=10)
    assert e.value.kind == "timeout"
    with pytest.raises(TransportError):
        StdlibTransport().request(HttpRequest("GET", "http://a.example/"), timeout=1, max_bytes=10)


def test_no_browser_or_generic_urlopen_is_ever_used(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not be called")

    monkeypatch.setattr(webbrowser, "open", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    svc, tr, _ = service()
    svc.lookup_message(msg(), now=NOW)
    assert tr.calls


def test_oversized_response_is_malformed_not_clean():
    big = HttpResponse(200, b'{"query_status":"no_results"}', {}, truncated=True)
    svc, _, _ = service(route(uh=big), config=cfg(**UH_ONLY))
    rep = svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
    assert all(r.error is E.MALFORMED_RESPONSE for r in rep.results)


# ------------------------------------------------------------------ evidence

def test_evidence_rows_have_ids_status_source_and_timestamps():
    svc, tr, _ = service(route(uh=jr({"query_status": "ok", "url_status": "online"})))
    rep = svc.lookup_message(msg(), now=NOW)
    cr = build_check_result(rep, svc.cfg, NOW)
    ids = [e.evidence_id for e in cr.evidence]
    assert ids == [f"threat_intel-{i}" for i in range(1, len(ids) + 1)]
    for e in cr.evidence:
        assert e.source.startswith("threat_intel:")
        assert e.observed_at == NOW
        assert e.status in (S.FOUND, S.NOT_FOUND, S.NOT_CHECKED)
    found = [e for e in cr.evidence if e.status is S.FOUND and e.source == "threat_intel:urlhaus"]
    assert found and all(e.value.startswith(("http://phish-test.com/...[", "sha256:")) or e.value == DOMAIN
                         for e in cr.evidence if e.type != "threat_intel_limit")
    for r in cr.reasons:
        assert r.evidence_ids and set(r.evidence_ids) <= set(ids)
    assert "SECRET-TOKEN" not in repr(cr.evidence) and HASH not in repr(cr.evidence)


def test_cached_result_keeps_original_lookup_time():
    svc, tr, fc = service(route(uh=jr({"query_status": "no_results"})), config=cfg(**UH_ONLY))
    first = svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW)
    fc.advance(60)
    second = svc.lookup_message(msg(**URL_ONLY_MSG), now=NOW.replace(minute=30))
    assert second.results[0].cache_hit and second.results[0].looked_up_at == first.results[0].looked_up_at
