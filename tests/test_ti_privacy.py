import logging

import pytest

from engine.schemas import EvidenceStatus as S
from engine.threat_intel import (
    DEFAULT_TI_CONFIG,
    ErrorCategory as E,
    SharingPolicy,
    ThreatIntelService,
)
from engine.threat_intel.evidence import build_check_result
from engine.threat_intel.privacy import (
    check_sharing,
    normalize_domain,
    normalize_sha256,
    normalize_url,
)
from engine.threat_intel.types import IndicatorType as T
from helpers import NOW
from ti_helpers import ALL, DOMAIN, HASH, KEY, URL, URL_RAW, FakeTransport, cfg, msg, service, sharing


# ------------------------------------------------------------------ normalisation / redaction

def test_url_query_fragment_and_credentials_are_stripped_and_flagged():
    i = normalize_url("HTTPS://user:pw@Phish-Test.COM:443/a/b?token=SECRET#frag")
    assert i.value == "https://phish-test.com/a/b"
    assert i.flags == {"had_query", "had_fragment", "had_credentials"}
    assert "SECRET" not in i.value and "pw" not in i.value


def test_default_port_dropped_and_other_port_kept():
    assert normalize_url("http://a.example:80/x").value == "http://a.example/x"
    assert normalize_url("http://a.example:8080/x").value == "http://a.example:8080/x"


def test_idn_url_is_sent_as_punycode():
    i = normalize_url("http://microsоft.com/login")           # Cyrillic о
    assert i.value.startswith("http://xn--") and i.value.isascii()


def test_non_http_and_garbage_urls_rejected():
    for bad in ("ftp://a.example/x", "javascript:alert(1)", "http://", "http://bad host/x", ""):
        assert normalize_url(bad) is None


def test_domain_indicator_is_registered_domain_only():
    assert normalize_domain("a.b.phish-test.com").value == "phish-test.com"
    assert normalize_domain("10.0.0.1") is None
    assert normalize_domain("localhost") is None


def test_sha256_must_be_64_hex():
    assert normalize_sha256("A" * 64).value == "a" * 64
    assert normalize_sha256("abc") is None
    assert normalize_sha256("g" * 64) is None


def test_reference_is_redacted_and_repr_hides_values():
    u = normalize_url("http://phish-test.com/reset/TOKEN123?x=1")
    assert "TOKEN123" not in u.ref and "reset" not in u.ref and "phish-test.com" in u.ref
    assert "TOKEN123" not in repr(u) and "reset" not in repr(u)
    h = normalize_sha256(HASH)
    assert h.ref == "sha256:" + HASH[:12] + "..." and HASH not in h.ref and HASH not in repr(h)


# ------------------------------------------------------------------ the gate

def test_empty_policy_denies_everything():
    p = SharingPolicy()
    for ind in (normalize_url(URL), normalize_domain(DOMAIN), normalize_sha256(HASH)):
        assert check_sharing(ind, p)


def test_exact_approvals_allow_and_nothing_else():
    p = sharing()
    assert check_sharing(normalize_url(URL_RAW), p) is None        # query ignored, stripped form approved
    assert check_sharing(normalize_domain("x." + DOMAIN), p) is None
    assert check_sharing(normalize_sha256(HASH), p) is None
    assert check_sharing(normalize_url(f"http://{DOMAIN}/other"), p)   # different path: not approved
    assert check_sharing(normalize_sha256("b" * 64), p)


def test_domain_approval_does_not_approve_urls_on_that_domain():
    p = SharingPolicy(approved_domains=frozenset({DOMAIN}))
    assert check_sharing(normalize_url(f"http://{DOMAIN}/anything"), p)


def test_credential_urls_refused_even_if_stripped_form_is_approved():
    p = sharing()
    ind = normalize_url(f"http://user:pw@{DOMAIN}/login")
    assert ind.value == URL
    assert "credentials" in check_sharing(ind, p)


def test_internal_and_private_targets_refused_even_if_approved():
    for u in ("http://10.1.2.3/x", "http://intranet.corp/x", "http://127.0.0.1/", "http://host.internal/x"):
        ind = normalize_url(u)
        assert check_sharing(ind, sharing(urls=(ind.value,))), u


def test_protected_domain_refused_even_if_approved():
    p = sharing(domains=("ourcompany.example",), denied=("ourcompany.example",))
    assert "protected" in check_sharing(normalize_domain("mail.ourcompany.example"), p)


# ------------------------------------------------------------------ service behaviour

def test_default_config_is_fully_disabled_and_makes_no_request():
    tr = FakeTransport()
    svc = ThreatIntelService(DEFAULT_TI_CONFIG, transport=tr, key_provider=lambda n: KEY)
    rep = svc.lookup_message(msg(), now=NOW)
    assert tr.calls == [] and rep.results == []
    cr = build_check_result(rep, DEFAULT_TI_CONFIG, NOW)
    assert not cr.completed and all(e.status is S.NOT_CHECKED for e in cr.evidence)


def test_unapproved_indicators_are_not_sent_and_reported_as_not_checked():
    svc, tr, _ = service(config=cfg(sharing=SharingPolicy()))
    rep = svc.lookup_message(msg(), now=NOW)
    assert tr.calls == []
    assert rep.results and all(r.error is E.PRIVACY_BLOCKED for r in rep.results)
    cr = build_check_result(rep, svc.cfg, NOW)
    assert not cr.completed
    assert all(e.status is S.NOT_CHECKED for e in cr.evidence)
    assert any("privacy_blocked" in (e.detail or "") for e in cr.evidence)
    assert not cr.reasons and not cr.facts


def test_virustotal_live_lookups_off_by_default_even_with_key_and_approval():
    svc, tr, _ = service(config=cfg(virustotal_live_enabled=False,
                                    enabled_providers=frozenset({"virustotal"})))
    rep = svc.lookup_message(msg(), now=NOW)
    assert tr.calls == []
    assert "virustotal" in rep.disabled and "switched off" in rep.disabled["virustotal"]


def test_virustotal_still_obeys_privacy_gate_when_live_enabled():
    svc, tr, _ = service(config=cfg(enabled_providers=frozenset({"virustotal"}),
                                    sharing=SharingPolicy()))
    rep = svc.lookup_message(msg(), now=NOW)
    assert tr.calls == [] and all(r.error is E.PRIVACY_BLOCKED for r in rep.results)


def test_only_indicators_leave_the_process():
    svc, tr, _ = service()
    svc.lookup_message(msg(), now=NOW)
    assert tr.calls
    for c in tr.calls:
        blob = (c.url + " " + (c.body or b"").decode()).lower()
        for secret in ("secret-token", "frag-part", "confidential body", "do-not-leak",
                       "billing", "invoice.pdf.exe", "application/x-msdownload"):
            assert secret not in blob, (secret, c.url)


def test_never_scans_uploads_or_downloads():
    svc, tr, _ = service()
    svc.lookup_message(msg(), now=NOW)
    for c in tr.calls:
        path = c.url.lower()
        assert "/download" not in path
        if "virustotal" in path:
            assert c.method == "GET"            # POST /urls or /files would submit for scanning
            assert "/api/v3/urls/" in path or "/domains/" in path or "/files/" in path
            assert "/analyse" not in path and "/upload" not in path and not path.endswith("/files")


def test_logs_contain_redacted_refs_not_values_or_keys(caplog):
    svc, tr, _ = service()
    with caplog.at_level(logging.DEBUG, logger="engine.threat_intel"):
        svc.lookup_message(msg(), now=NOW)
    text = caplog.text
    assert "lookup provider=" in text
    for forbidden in (KEY, "SECRET-TOKEN", "frag-part", HASH, "/login"):
        assert forbidden not in text


def test_api_key_only_in_request_header_and_never_in_results_or_repr():
    svc, tr, _ = service()
    rep = svc.lookup_message(msg(), now=NOW)
    cr = build_check_result(rep, svc.cfg, NOW)
    for c in tr.calls:
        assert KEY not in c.url and KEY not in repr(c)
        in_body = KEY in (c.body or b"").decode()
        # PhishTank documents app_key as a POST form field; everywhere else it is a header.
        assert in_body == ("phishtank" in c.url)
    assert KEY not in repr(svc.cfg)
    assert KEY not in " ".join(repr(e) for e in cr.evidence)
    assert any(KEY in v for c in tr.calls for v in c.headers.values())   # it IS sent, as a header
