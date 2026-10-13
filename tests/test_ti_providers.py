import base64
from datetime import timedelta

import pytest

from engine.schemas import EvidenceStatus as S
from engine.threat_intel import ErrorCategory as E
from engine.threat_intel import FindingCategory as F
from engine.threat_intel import IndicatorType as T
from engine.threat_intel.config import ThreatIntelConfig
from helpers import NOW
from ti_helpers import (
    ALL, DOMAIN, HASH, KEY, URL, FakeClock, cfg, jr, msg, raw, rdap, route, service,
    timeout, vt_stats,
)


def only(provider, handler, indicator="url", **kw):
    """Run one provider against a message that yields exactly that indicator type."""
    m = {
        "url": msg(sender="", urls=[URL], attachments=[]),
        "domain": msg(sender=f"a@{DOMAIN}", urls=[], attachments=[]),
        "sha256": msg(sender="", urls=[], attachments=[]).model_copy(
            update={"attachments": msg().attachments}),
    }[indicator]
    svc, tr, fc = service(handler, config=cfg(enabled_providers=frozenset({provider})), **kw)
    rep = svc.lookup_message(m, now=NOW)
    want = {"url": T.URL, "domain": T.DOMAIN, "sha256": T.SHA256}[indicator]
    res = [r for r in rep.results if r.indicator_type is want and r.provider == provider]
    assert len(res) == 1, rep.results
    return res[0], tr


# ================================================================== VirusTotal

def test_vt_url_request_is_documented_lookup_with_key_header():
    r, tr = only("virustotal", route(vt=jr(vt_stats(8))))
    req = tr.calls[0]
    ident = base64.urlsafe_b64encode(URL.encode()).decode().rstrip("=")
    assert req.method == "GET"
    assert req.url == f"https://www.virustotal.com/api/v3/urls/{ident}"
    assert req.headers["x-apikey"] == KEY


@pytest.mark.parametrize("ind,path", [
    ("domain", f"/api/v3/domains/{DOMAIN}"), ("sha256", f"/api/v3/files/{HASH}")])
def test_vt_domain_and_file_endpoints(ind, path):
    _, tr = only("virustotal", route(vt=jr(vt_stats(0))), ind)
    assert tr.calls[0].url == "https://www.virustotal.com" + path


def test_vt_strong_listing_is_found_malicious():
    r, _ = only("virustotal", route(vt=jr(vt_stats(malicious=9))))
    assert (r.status, r.category) == (S.FOUND, F.MALICIOUS)
    assert r.details["malicious"] == 9 and r.details["vendors"] == 79


def test_vt_several_detections_are_suspicious_not_malicious():
    r, _ = only("virustotal", route(vt=jr(vt_stats(malicious=3))))
    assert (r.status, r.category) == (S.FOUND, F.SUSPICIOUS)


def test_vt_single_detection_is_low_confidence():
    r, _ = only("virustotal", route(vt=jr(vt_stats(malicious=1))))
    assert (r.status, r.category) == (S.FOUND, F.LOW_CONFIDENCE)


def test_vt_no_detections_is_not_found_not_safe():
    r, _ = only("virustotal", route(vt=jr(vt_stats(0))))
    assert (r.status, r.category) == (S.NOT_FOUND, F.NONE)


def test_vt_unknown_resource_404_is_not_found():
    body = {"error": {"code": "NotFoundError", "message": "not found"}}
    r, _ = only("virustotal", route(vt=jr(body, 404)))
    assert r.status is S.NOT_FOUND


def test_vt_404_without_notfound_body_is_not_trusted_as_not_found():
    r, _ = only("virustotal", route(vt=jr({"x": 1}, 404)))
    assert r.status is S.NOT_CHECKED and r.error is E.UNKNOWN_FORMAT


def test_vt_record_never_analysed_is_not_checked():
    zero = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0,
            "harmless": 0, "undetected": 0, "timeout": 0}}}}
    r, _ = only("virustotal", route(vt=jr(zero)))
    assert r.status is S.NOT_CHECKED


def test_vt_missing_key():
    r, tr = only("virustotal", route(), keys={})
    assert r.status is S.NOT_CHECKED and r.error is E.NO_API_KEY and tr.calls == []
    assert "VIRUSTOTAL_API_KEY" in r.error_detail and KEY not in r.error_detail


# ================================================================== URLhaus

def test_urlhaus_url_lookup_request_shape():
    r, tr = only("urlhaus", route(uh=jr({"query_status": "ok", "url_status": "online",
                                         "threat": "malware_download"})))
    req = tr.calls[0]
    assert (req.method, req.url) == ("POST", "https://urlhaus-api.abuse.ch/v1/url/")
    assert req.headers["Auth-Key"] == KEY
    assert req.body == b"url=http%3A%2F%2Fphish-test.com%2Flogin"
    assert (r.status, r.category) == (S.FOUND, F.MALWARE_DISTRIBUTION)
    assert r.details["url_status"] == "online"


def test_urlhaus_host_and_payload_endpoints_and_findings():
    host_body = {"query_status": "ok", "url_count": "3", "urls": [
        {"url_status": "online"}, {"url_status": "offline"}, {"url_status": "online"}]}
    r, tr = only("urlhaus", route(uh=jr(host_body)), "domain")
    assert tr.calls[0].url.endswith("/v1/host/") and tr.calls[0].body == f"host={DOMAIN}".encode()
    assert (r.category, r.details["url_count"], r.details["urls_online"]) == (F.HOST_LISTED, 3, 2)

    r, tr = only("urlhaus", route(uh=jr({"query_status": "ok", "url_count": 2,
                                         "file_type": "exe"})), "sha256")
    assert tr.calls[0].url.endswith("/v1/payload/")
    assert tr.calls[0].body == f"sha256_hash={HASH}".encode()
    assert (r.status, r.category) == (S.FOUND, F.MALWARE_DISTRIBUTION)


def test_urlhaus_no_results_is_not_found():
    r, _ = only("urlhaus", route(uh=jr({"query_status": "no_results"})))
    assert r.status is S.NOT_FOUND


def test_urlhaus_documented_query_staus_typo_is_accepted():
    r, _ = only("urlhaus", route(uh=jr({"query_staus": "no_results"})), "domain")
    assert r.status is S.NOT_FOUND


@pytest.mark.parametrize("body,err", [
    ({"query_status": "invalid_url"}, E.INVALID_INDICATOR),
    ({"query_status": "http_post_expected"}, E.UNKNOWN_FORMAT),
    ({"query_status": "something_new"}, E.UNKNOWN_FORMAT),
    ({"no": "status"}, E.UNKNOWN_FORMAT),
    ({"query_status": "ok", "url_status": "weird"}, E.UNKNOWN_FORMAT),
])
def test_urlhaus_unexpected_bodies_are_not_checked(body, err):
    r, _ = only("urlhaus", route(uh=jr(body)))
    assert r.status is S.NOT_CHECKED and r.error is err


def test_urlhaus_response_urls_and_downloads_are_never_followed_or_stored():
    body = {"query_status": "ok", "url_status": "online", "threat": "malware_download",
            "payloads": [{"urlhaus_download": "https://urlhaus-api.abuse.ch/v1/download/" + "b" * 64,
                          "response_sha256": "b" * 64, "filename": "evil.exe"}],
            "urls": [{"url": "http://malware.example/x.exe"}]}
    r, tr = only("urlhaus", route(uh=jr(body)))
    # one URL lookup plus the URL's own domain (host) lookup; nothing the response mentioned
    assert [c.url for c in tr.calls] == ["https://urlhaus-api.abuse.ch/v1/url/",
                                         "https://urlhaus-api.abuse.ch/v1/host/"]
    assert not any("malware.example" in c.url or "download" in c.url for c in tr.calls)
    flat = repr(r.details)
    assert "malware.example" not in flat and "urlhaus_download" not in flat
    assert "/v1/download" not in flat and "evil.exe" not in flat and "b" * 64 not in flat


def test_urlhaus_missing_key():
    r, tr = only("urlhaus", route(), keys={})
    assert r.error is E.NO_API_KEY and tr.calls == []


# ================================================================== PhishTank

PT = lambda **res: jr({"meta": {"status": "success"}, "results": res})


def test_phishtank_verified_phish():
    r, tr = only("phishtank", route(pt=PT(in_database=True, verified="y", valid="y", phish_id=1)))
    req = tr.calls[0]
    assert (req.method, req.url) == ("POST", "https://checkurl.phishtank.com/checkurl/")
    assert req.url.startswith("https://")           # never plain http
    body = req.body.decode()
    assert "format=json" in body and "app_key=" + KEY in body
    assert "phishtank/" in req.headers["User-Agent"]
    assert (r.status, r.category) == (S.FOUND, F.PHISHING_VERIFIED)


def test_phishtank_unverified_entry_is_distinct_from_verified():
    r, _ = only("phishtank", route(pt=PT(in_database=True, verified="n")))
    assert (r.status, r.category) == (S.FOUND, F.PHISHING_UNVERIFIED)
    r, _ = only("phishtank", route(pt=PT(in_database=True)))      # verified field absent
    assert r.category is F.PHISHING_UNVERIFIED


def test_phishtank_no_entry_is_not_found():
    r, _ = only("phishtank", route(pt=PT(in_database=False)))
    assert (r.status, r.category) == (S.NOT_FOUND, F.NONE)


def test_phishtank_verified_but_not_valid_is_not_a_listing():
    r, _ = only("phishtank", route(pt=PT(in_database=True, verified="y", valid="n")))
    assert r.status is S.NOT_FOUND


def test_phishtank_boolean_flags_and_flat_shape_accepted():
    r, _ = only("phishtank", route(pt=jr({"in_database": True, "verified": True, "valid": True})))
    assert r.category is F.PHISHING_VERIFIED


@pytest.mark.parametrize("body", [
    {"results": {"verified": "y"}},
    {"results": {"in_database": "maybe"}},
    {"results": {"in_database": True, "verified": "y"}},      # verified without valid
    {"results": []},
    {"something": "else"},
])
def test_phishtank_unknown_shapes_are_not_checked(body):
    r, _ = only("phishtank", route(pt=jr(body)))
    assert r.status is S.NOT_CHECKED and r.error is E.UNKNOWN_FORMAT


def test_phishtank_key_is_optional_and_omitted_when_absent():
    r, tr = only("phishtank", route(pt=PT(in_database=False)), keys={})
    assert r.status is S.NOT_FOUND
    assert "app_key" not in tr.calls[0].body.decode()


def test_phishtank_509_is_rate_limiting():
    r, _ = only("phishtank", route(pt=raw(b"", 509)))
    assert r.error is E.PROVIDER_RATE_LIMITED


# ================================================================== Domain age

def test_domain_age_is_computed_against_injected_time():
    r, tr = only("domain_age", route(rd=jr(rdap("2026-10-01T04:00:00Z"))), "domain")
    assert tr.calls[0].url == f"https://rdap.verisign.com/com/v1/domain/{DOMAIN}"
    assert (r.status, r.category) == (S.FOUND, F.RECENTLY_REGISTERED)
    assert r.details["age_days"] == 12 and r.details["registered"] == "2026-10-01"


def test_domain_age_boundary_and_old_domain():
    r, _ = only("domain_age", route(rd=jr(rdap("2026-09-13T12:00:00+00:00"))), "domain")
    assert r.details["age_days"] == 30 and r.status is S.NOT_FOUND           # not < 30
    r, _ = only("domain_age", route(rd=jr(rdap("2010-01-01T00:00:00Z"))), "domain")
    assert (r.status, r.category) == (S.NOT_FOUND, F.REGISTRATION_KNOWN)
    assert r.details["age_days"] > 5000


def test_domain_age_uses_clock_when_now_not_given():
    fc = FakeClock()
    svc, tr, _ = service(route(rd=jr(rdap("2026-10-12T00:00:00Z"))), clock=fc,
                         config=cfg(enabled_providers=frozenset({"domain_age"})))
    rep = svc.lookup_message(msg(sender=f"a@{DOMAIN}", urls=[], attachments=[]))
    assert rep.results[0].details["age_days"] == 1
    fc.advance(40 * 86400)                       # clock moves; a fresh lookup (cache bypass) ages
    svc2, _, _ = service(route(rd=jr(rdap("2026-10-12T00:00:00Z"))), clock=fc,
                         config=cfg(enabled_providers=frozenset({"domain_age"})))
    assert svc2.lookup_message(msg(sender=f"a@{DOMAIN}", urls=[], attachments=[])
                               ).results[0].details["age_days"] == 41


@pytest.mark.parametrize("handler,err", [
    (route(rd=jr({"events": []})), E.NO_DATA),
    (route(rd=jr({"events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}]})), E.NO_DATA),
    (route(rd=jr({"errorCode": 404}, 404)), E.NO_DATA),
    (route(rd=jr({"events": [{"eventAction": "registration", "eventDate": "yesterday"}]})), E.UNKNOWN_FORMAT),
    (route(rd=jr({"events": [{"eventAction": "registration", "eventDate": "2999-01-01T00:00:00Z"}]})), E.UNKNOWN_FORMAT),
    (route(rd=jr({"nope": True})), E.UNKNOWN_FORMAT),
])
def test_domain_age_unavailable_dates_are_not_checked(handler, err):
    r, _ = only("domain_age", handler, "domain")
    assert r.status is S.NOT_CHECKED and r.error is err


def test_domain_age_unconfigured_tld_makes_no_request():
    m = msg(sender="a@phish-test.io", urls=[], attachments=[])
    svc, tr, _ = service(config=cfg(enabled_providers=frozenset({"domain_age"}),
                                    sharing=__import__("ti_helpers").sharing(domains=("phish-test.io",))))
    rep = svc.lookup_message(m, now=NOW)
    assert tr.calls == []
    assert rep.results[0].error is E.NO_DATA and ".io" in rep.results[0].error_detail


# ================================================================== failure matrix (every provider)

CASES = [("urlhaus", "url", "uh"), ("phishtank", "url", "pt"),
         ("virustotal", "url", "vt"), ("domain_age", "domain", "rd")]
FAILURES = [
    ("timeout", lambda: timeout(), E.TIMEOUT),
    ("429", lambda: raw(b"{}", 429), E.PROVIDER_RATE_LIMITED),
    ("401", lambda: raw(b"{}", 401), E.AUTH_FAILED),
    ("403", lambda: raw(b"{}", 403), E.AUTH_FAILED),
    ("500", lambda: raw(b"oops", 500), E.SERVER_ERROR),
    ("503", lambda: raw(b"", 503), E.SERVER_ERROR),
    ("bad-json", lambda: raw(b"<html>nope</html>"), E.MALFORMED_RESPONSE),
    ("json-list", lambda: raw(b"[1,2,3]"), E.UNKNOWN_FORMAT),
    ("redirect", lambda: raw(b"", 302), E.REDIRECT_REFUSED),
]


@pytest.mark.parametrize("provider,ind,slot", CASES)
@pytest.mark.parametrize("name,make_reply,err", FAILURES, ids=[f[0] for f in FAILURES])
def test_provider_failures_are_never_clean(provider, ind, slot, name, make_reply, err):
    handler = route(**{slot: lambda req, f=make_reply: f()})
    r, tr = only(provider, handler, ind)
    assert r.status is S.NOT_CHECKED
    assert r.error is err
    assert r.category is F.NOT_AVAILABLE
    assert KEY not in r.error_detail
