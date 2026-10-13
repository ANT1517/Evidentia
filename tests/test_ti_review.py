"""Step 4 review: schema compatibility, coverage semantics, thresholds, RDAP, approvals."""
from dataclasses import replace

import pytest

from engine import DEFAULT_CONFIG, analyze
from engine.policy import POLICY_VERSION, PROFILES, RULE_BASIS, decide
from engine.rules import CheckResult
from engine.schemas import Attachment, Evidence, EvidenceStatus as S, RiskBand as B
from engine.threat_intel import (
    DEFAULT_TI_CONFIG,
    ErrorCategory as E,
    FindingCategory as F,
    IndicatorType as T,
    SharingPolicy,
    ThreatIntelService,
)
from engine.threat_intel.config import (
    RATE_LIMIT_BASIS,
    THRESHOLD_REGISTRY,
    ThreatIntelConfig,
    rdap_servers_from_bootstrap,
    usable_rdap_base,
)
from engine.threat_intel.evidence import build_check_result
from engine.threat_intel.privacy import (
    audit_policy,
    check_sharing,
    normalize_domain,
    normalize_url,
    sensitive_reason,
)
from helpers import NOW
from ti_helpers import (
    DOMAIN, HASH, KEY, URL, FakeTransport, bare_msg, cfg, jr, msg, raw, rdap, route, service,
    sharing, uh_clean, uh_listed, vt_stats,
)

FULL = replace(DEFAULT_CONFIG, active_profile="full")


def one(provider, handler, kind="url", **kw):
    m = {"url": msg(sender="", urls=[URL], attachments=[]),
         "domain": msg(sender=f"a@{DOMAIN}", urls=[], attachments=[]),
         "sha256": msg(sender="", urls=[]).model_copy(update={"attachments": msg().attachments})}[kind]
    svc, tr, _ = service(handler, config=cfg(enabled_providers=frozenset({provider})), **kw)
    want = {"url": T.URL, "domain": T.DOMAIN, "sha256": T.SHA256}[kind]
    rep = svc.lookup_message(m, now=NOW)
    return [r for r in rep.results if r.indicator_type is want][0], tr


# ================================================================== 1. schema compatibility

def test_vt_file_object_extra_stat_keys_are_accepted_and_not_counted_as_vendors():
    stats = {"malicious": 6, "suspicious": 0, "harmless": 0, "undetected": 20, "timeout": 0,
             "confirmed-timeout": 3, "failure": 2, "type-unsupported": 9}
    body = {"data": {"id": HASH, "type": "file", "attributes": {
        "last_analysis_stats": stats, "meaningful_name": "x.exe", "type_description": "Win32 EXE"}}}
    r, _ = one("virustotal", route(vt=jr(body)), "sha256")
    assert (r.status, r.category) == (S.FOUND, F.MALICIOUS)
    assert r.details["vendors"] == 26            # only the five engine-verdict keys


def test_vt_url_object_with_many_documented_fields_parses():
    body = {"data": {"type": "url", "id": "ab" * 32, "attributes": {
        "last_analysis_stats": {"harmless": 60, "malicious": 0, "suspicious": 0,
                                "timeout": 0, "undetected": 10},
        "last_analysis_results": {"Engine": {"category": "harmless", "engine_name": "Engine",
                                             "method": "blacklist", "result": "clean"}},
        "last_analysis_date": 1760000000, "reputation": 0, "times_submitted": 3,
        "categories": {"x": "y"}, "url": "http://x/", "last_final_url": "http://x/",
        "redirection_chain": []}}}
    r, _ = one("virustotal", route(vt=jr(body)))
    assert r.status is S.NOT_FOUND and r.details["vendors"] == 70


@pytest.mark.parametrize("status,code,err", [
    (429, "QuotaExceededError", E.PROVIDER_RATE_LIMITED),
    (429, "TooManyRequestsError", E.PROVIDER_RATE_LIMITED),
    (401, "WrongCredentialsError", E.AUTH_FAILED),
    (401, "AuthenticationRequiredError", E.AUTH_FAILED),
    (401, "UserNotActiveError", E.AUTH_FAILED),
    (403, "ForbiddenError", E.AUTH_FAILED),
    (400, "BadRequestError", E.INVALID_INDICATOR),
    (400, "InvalidArgumentError", E.INVALID_INDICATOR),
    (503, "TransientError", E.SERVER_ERROR),
    (504, "DeadlineExceededError", E.SERVER_ERROR),
    (409, "AlreadyExistsError", E.UNKNOWN_FORMAT),
    (424, "FailedDependencyError", E.UNKNOWN_FORMAT),
])
def test_vt_documented_error_codes_never_become_clean(status, code, err):
    body = {"error": {"code": code, "message": "m"}}
    r, _ = one("virustotal", route(vt=jr(body, status)))
    assert r.status is S.NOT_CHECKED and r.error is err


@pytest.mark.parametrize("stats", [
    {"malicious": "5", "suspicious": 0},
    {"malicious": -1, "suspicious": 0},
    {"malicious": True, "suspicious": 0},
    {"malicious": 1.5, "suspicious": 0},
])
def test_vt_non_integer_counts_are_unknown_format(stats):
    r, _ = one("virustotal", route(vt=jr({"data": {"attributes": {"last_analysis_stats": stats}}})))
    assert r.status is S.NOT_CHECKED and r.error is E.UNKNOWN_FORMAT


def test_phishtank_accepts_the_three_documented_flag_styles():
    for flags in ({"verified": "y", "valid": "y"}, {"verified": "yes", "valid": "yes"},
                  {"verified": True, "valid": True}):
        r, _ = one("phishtank", route(pt=jr({"results": {"in_database": True, **flags}})))
        assert r.category is F.PHISHING_VERIFIED, flags


# ================================================================== 2. coverage semantics

def test_provider_without_support_for_a_type_never_yields_a_result_for_it():
    svc, tr, _ = service(route(), config=cfg(enabled_providers=frozenset({"phishtank"})))
    rep = svc.lookup_message(msg(), now=NOW)       # URL + hash + domain indicators
    pt = [r for r in rep.results if r.provider == "phishtank"]
    assert {r.indicator_type for r in pt} == {T.URL}
    gaps = [r for r in rep.results if r.error is E.NO_COVERAGE]
    assert {r.indicator_type for r in gaps} == {T.SHA256, T.DOMAIN}
    assert all(r.status is S.NOT_CHECKED for r in gaps)


def test_coverage_gap_makes_check_incomplete_with_visible_rows_and_no_false_negative():
    svc, _, _ = service(route(), config=cfg(enabled_providers=frozenset({"phishtank"})))
    cr = build_check_result(svc.lookup_message(msg(), now=NOW), svc.cfg, NOW)
    assert not cr.completed
    gap_rows = [e for e in cr.evidence if e.type == "threat_intel_coverage"]
    assert len(gap_rows) == 2 and all(e.status is S.NOT_CHECKED for e in gap_rows)
    assert not any(e.status is S.NOT_FOUND and e.type in ("threat_intel_sha256", "threat_intel_domain")
                   for e in cr.evidence)


def test_unsupported_pairs_do_not_make_a_covered_message_incomplete():
    # PhishTank cannot do hashes or domains, URLhaus can: coverage is complete.
    svc, _, _ = service(route(uh=uh_clean),
                        config=cfg(enabled_providers=frozenset({"urlhaus", "phishtank"})))
    cr = build_check_result(svc.lookup_message(bare_msg(), now=NOW), svc.cfg, NOW)
    assert cr.completed
    assert not any(e.type == "threat_intel_coverage" for e in cr.evidence)


def test_virustotal_listed_but_switched_off_does_not_count_as_coverage():
    c = cfg(enabled_providers=frozenset({"urlhaus", "virustotal"}), virustotal_live_enabled=False)
    svc, _, _ = service(route(uh=uh_clean), config=c)
    rep = svc.lookup_message(bare_msg(), now=NOW)
    assert "virustotal" in rep.disabled
    assert build_check_result(rep, c, NOW).completed          # URLhaus alone covers every type

    only_vt = cfg(enabled_providers=frozenset({"virustotal"}), virustotal_live_enabled=False)
    svc2, tr2, _ = service(route(), config=only_vt)
    rep2 = svc2.lookup_message(msg(sender="", urls=[], attachments=[]), now=NOW)   # no indicators
    assert tr2.calls == [] and not build_check_result(rep2, only_vt, NOW).completed


def test_domain_age_gaps_never_block_completeness():
    svc, _, _ = service(route(uh=uh_clean, vt=jr(vt_stats(0)), rd=jr({"events": []})))
    cr = build_check_result(svc.lookup_message(bare_msg(), now=NOW), svc.cfg, NOW)
    assert any(e.source == "threat_intel:domain_age" and e.status is S.NOT_CHECKED
               for e in cr.evidence)
    assert cr.completed


def test_incomplete_check_without_rows_still_cites_real_evidence():
    ok = lambda c: CheckResult(c, True, [Evidence(evidence_id=f"{c}-1", type=c, value="", source="t",
                                                 status=S.NOT_FOUND, observed_at=NOW)])
    results = [ok(c) for c in PROFILES["rules_only"].required if c != "identity"]
    results.append(CheckResult("identity", completed=False, evidence=[]))
    d = decide(results, DEFAULT_CONFIG, "rules_only", NOW)
    assert d.band is B.INSUFFICIENT_DATA
    reason = d.reasons[-1]
    ids = {e.evidence_id for e in d.extra_evidence}
    assert reason.evidence_ids and set(reason.evidence_ids) <= ids
    assert "incomplete-identity" in ids


def test_analyze_survives_a_coverage_gap_end_to_end():
    svc, _, _ = service(route(), config=cfg(enabled_providers=frozenset({"phishtank"})))
    a = analyze(msg(attachments=[]), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.INSUFFICIENT_DATA
    ids = {e.evidence_id for e in a.evidence}
    assert all(r.evidence_ids and set(r.evidence_ids) <= ids for r in a.reasons)


# ================================================================== 3. thresholds and policy

def test_policy_version_and_basis_table():
    assert POLICY_VERSION == "0.3.0"
    for rule in ("U1_THREAT_INTEL_MATCH", "U2_EXECUTABLE_ATTACHMENT",
                 "U3_VERIFIED_AUTH_FAIL_WITH_IDENTITY", "U4_COMBINATION", "R1_INDICATOR",
                 "I1_REQUIRED_CHECK_INCOMPLETE", "L1_ALL_REQUIRED_CHECKS_CLEAN"):
        assert rule in RULE_BASIS
    # Every rule states its basis, and none claims to be data-calibrated.
    for text in RULE_BASIS.values():
        assert any(w in text for w in ("provisional", "provider semantics", "structural"))
        assert "calibrated against" not in text


def test_every_fired_rule_id_has_a_documented_basis():
    svc, _, _ = service(route(uh=uh_listed, vt=jr(vt_stats(0))))
    for a in (analyze(msg(), config=FULL, now=NOW, threat_intel=svc),
              analyze(msg(attachments=[]), now=NOW)):
        for rid in a.policy_rules:
            assert rid.split(":")[0] in RULE_BASIS


def test_threshold_registry_matches_defaults_and_none_is_calibrated():
    for name, default, calibrated, note in THRESHOLD_REGISTRY:
        assert getattr(DEFAULT_TI_CONFIG, name) == default, name
        assert calibrated is False and note
    assert DEFAULT_TI_CONFIG.vt_urgent_min > DEFAULT_TI_CONFIG.vt_review_min >= 2


def test_shared_hosting_platform_host_level_findings_raise_no_signal():
    sh = sharing(urls=("http://github.com/x",), domains=("github.com",), hashes=())
    m = msg(sender="", urls=["http://github.com/x"], attachments=[])

    def uh(req):
        if req.url.endswith("/v1/host/"):
            return jr({"query_status": "ok", "url_count": 40, "urls": [{"url_status": "online"}]})
        return jr({"query_status": "no_results"})

    def vt(req):
        return jr(vt_stats(malicious=12)) if "/domains/" in req.url else jr(vt_stats(0))

    svc, _, _ = service(route(uh=uh, vt=vt), config=cfg(sharing=sh))
    a = analyze(m, config=FULL, now=NOW, threat_intel=svc)
    assert not any(r.code.name.endswith("THREAT_LIST") for r in a.reasons)
    assert a.risk_band is not B.URGENT and "R1_INDICATOR:threat_intel.domain_listed" not in a.policy_rules
    noted = [e for e in a.evidence if "shared hosting platform" in (e.detail or "")]
    assert noted and all(e.status is S.FOUND for e in noted)      # kept in the ledger


def test_url_level_listing_on_a_shared_platform_still_counts():
    sh = sharing(urls=("http://github.com/x",), domains=("github.com",), hashes=())
    svc, _, _ = service(route(uh=uh_listed, vt=jr(vt_stats(0))), config=cfg(sharing=sh))
    a = analyze(msg(sender="", urls=["http://github.com/x"], attachments=[]),
                config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.URGENT


# ================================================================== 4. RDAP bootstrap handling

def test_default_snapshot_contains_only_https_servers():
    assert DEFAULT_TI_CONFIG.rdap_servers
    for tld, base in DEFAULT_TI_CONFIG.rdap_servers.items():
        assert usable_rdap_base(base) == base, tld
    assert all(o.startswith("https://") for o in DEFAULT_TI_CONFIG.allowed_origins)


def test_unusable_rdap_entries_are_rejected():
    for bad in ("http://rdap.example/", "ftp://rdap.example/", "https://u:p@rdap.example/",
                "https://rdap.example/?q=1", "https://10.0.0.1/rdap/", "", None, []):
        assert usable_rdap_base(bad) is None, bad
    assert usable_rdap_base(["http://a.example/", "https://b.example/rdap"]) == "https://b.example/rdap/"


def test_bootstrap_converter_drops_tlds_without_https():
    doc = {"services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/", "http://rdap.verisign.com/com/v1/"]],
        [["onlyhttp"], ["http://rdap.insecure.example/"]],
        [["creds"], ["https://user:pw@rdap.example/"]],
        ["malformed"],
        [["ok"], ["http://x.example/", "https://y.example/rdap"]],
    ]}
    got = rdap_servers_from_bootstrap(doc)
    assert got == {"com": "https://rdap.verisign.com/com/v1/",
                   "net": "https://rdap.verisign.com/com/v1/",
                   "ok": "https://y.example/rdap/"}
    assert rdap_servers_from_bootstrap({}) == {} and rdap_servers_from_bootstrap([]) == {}


@pytest.mark.parametrize("tld,server", [
    ("io", None), ("co", None), ("net", "http://rdap.insecure.example/"),
    ("net", ["http://a.example/"]),
])
def test_tld_without_usable_https_endpoint_is_not_checked_and_sends_nothing(tld, server):
    servers = dict(DEFAULT_TI_CONFIG.rdap_servers)
    servers.pop(tld, None)
    if server:
        servers[tld] = server
    c = cfg(enabled_providers=frozenset({"domain_age"}), rdap_servers=servers,
            sharing=sharing(domains=(f"phish-test.{tld}",), urls=(), hashes=()))
    svc, tr, _ = service(config=c)
    rep = svc.lookup_message(msg(sender=f"a@phish-test.{tld}", urls=[], attachments=[]), now=NOW)
    assert tr.calls == []
    r = rep.results[0]
    assert r.status is S.NOT_CHECKED and r.error is E.NO_DATA and "https" in r.error_detail
    assert not any(o.startswith("http://") for o in c.allowed_origins)


def test_rdap_redirect_is_refused_never_followed_never_downgraded():
    resp = __import__("engine.threat_intel", fromlist=["HttpResponse"]).HttpResponse(
        301, b"", {"location": "http://evil.example/rdap/domain/x"})
    r, tr = one("domain_age", route(rd=resp), "domain")
    assert r.error is E.REDIRECT_REFUSED and r.status is S.NOT_CHECKED
    assert tr.hosts() == {"rdap.verisign.com"}


# ================================================================== 5. approvals

TOKEN_PATHS = [
    "/reset/3f2a9c1e-7b4d-4e2a-9c1e-0a1b2c3d4e5f",           # UUID
    "/verify/0123456789abcdef0123456789abcdef",              # 32 hex
    "/s/eyJhbGciOi.eyJzdWIiOiJ4.c2ln",                       # JWT
    "/u/Xk3pQ9aLm2Zr7TbVn4Ws8YcD1",                          # long mixed token
    "/user/jane.doe@corp.example/profile",                   # email address
    "/account/123456789012345",                              # long numeric id
    "/a;jsessionid=ABC123/x",                                # path parameter
]


@pytest.mark.parametrize("path", TOKEN_PATHS)
def test_token_like_paths_are_refused_even_when_exactly_approved(path):
    u = normalize_url("http://phish-test.com" + path)
    assert sensitive_reason(u.value)
    p = SharingPolicy(approved_urls=frozenset({u.value}))
    assert "approved-to-share" not in (check_sharing(u, p) or "")   # refused for the token reason
    assert check_sharing(u, p)
    assert audit_policy(p)                                          # and flagged at start-up


def test_encoded_email_in_path_is_detected():
    assert sensitive_reason(normalize_url("http://phish-test.com/u/jane%40corp.example").value)


def test_identifier_like_host_label_is_refused():
    u = normalize_url("http://a1b2c3d4e5f6a7b8c9d0e1f2.phish-test.com/x")
    assert sensitive_reason(u.value) and check_sharing(u, SharingPolicy(approved_urls=frozenset({u.value})))


def test_ordinary_urls_are_not_flagged():
    for ok in ("http://phish-test.com/login", "http://phish-test.com/2026/10/quarterly-report",
               "http://login.phish-test.com/index.html", "http://phish-test.com/"):
        assert sensitive_reason(normalize_url(ok).value) is None, ok


def test_reviewed_override_allows_a_public_token_like_url_but_never_credentials():
    u = normalize_url("http://phish-test.com/reset/3f2a9c1e-7b4d-4e2a-9c1e-0a1b2c3d4e5f")
    p = SharingPolicy(approved_urls=frozenset({u.value}),
                      reviewed_token_like_urls=frozenset({u.value}))
    assert check_sharing(u, p) is None and audit_policy(p) == []
    cred = normalize_url("http://user:pw@phish-test.com/login")
    pc = SharingPolicy(approved_urls=frozenset({cred.value}),
                       reviewed_token_like_urls=frozenset({cred.value}))
    assert "credentials" in check_sharing(cred, pc)


@pytest.mark.parametrize("entry,field", [
    ("http://phish-test.com/login?token=SECRET", "approved_urls"),
    ("http://phish-test.com/login#frag", "approved_urls"),
    ("http://user:pw@phish-test.com/login", "approved_urls"),
    ("HTTP://Phish-Test.com/login", "approved_urls"),
    ("not a url", "approved_urls"),
    ("https://phish-test.com", "approved_urls"),                 # un-normalised: no trailing /
])
def test_accidental_url_approvals_fail_audit_without_echoing_secrets(entry, field):
    problems = audit_policy(SharingPolicy(approved_urls=frozenset({entry})))
    assert problems
    joined = " ".join(problems)
    assert "SECRET" not in joined and "pw" not in joined.split()


@pytest.mark.parametrize("entry", ["https://phish-test.com", "sub.phish-test.com",
                                   "*.phish-test.com", "Phish-Test.com", "phish-test.com/x"])
def test_domain_approvals_must_be_exact_registered_domains(entry):
    assert audit_policy(SharingPolicy(approved_domains=frozenset({entry})))


def test_hash_approvals_must_be_lowercase_sha256():
    assert audit_policy(SharingPolicy(approved_sha256=frozenset({"A" * 64})))
    assert audit_policy(SharingPolicy(approved_sha256=frozenset({"abc"})))
    assert audit_policy(SharingPolicy(approved_sha256=frozenset({HASH}))) == []


def test_reviewed_list_must_be_subset_of_approved():
    p = SharingPolicy(reviewed_token_like_urls=frozenset({"http://phish-test.com/x"}))
    assert audit_policy(p)


def test_service_refuses_to_start_with_an_unsafe_policy():
    bad = cfg(sharing=SharingPolicy(approved_urls=frozenset({"http://phish-test.com/a?token=SECRET"})))
    with pytest.raises(ValueError) as e:
        ThreatIntelService(bad, transport=FakeTransport())
    assert "SECRET" not in str(e.value)


def test_message_url_with_token_path_is_blocked_and_nothing_is_sent():
    secret_url = "http://phish-test.com/reset/3f2a9c1e-7b4d-4e2a-9c1e-0a1b2c3d4e5f?x=1"
    svc, tr, _ = service(route(), config=cfg(enabled_providers=frozenset({"urlhaus", "phishtank"})))
    rep = svc.lookup_message(msg(sender="", urls=[secret_url], attachments=[]), now=NOW)
    blocked = [r for r in rep.results if r.indicator_type is T.URL]
    assert blocked and all(r.error is E.PRIVACY_BLOCKED for r in blocked)
    assert not any("3f2a9c1e" in c.url + (c.body or b"").decode() for c in tr.calls)


def test_exact_approval_of_bare_url_sends_only_the_bare_url():
    m = msg(sender="", attachments=[], urls=[URL + "?session=PRIVATE#also-private"])
    svc, tr, _ = service(route(), config=cfg(enabled_providers=frozenset({"urlhaus"})))
    svc.lookup_message(m, now=NOW)
    sent = [c.body.decode() for c in tr.calls if c.url.endswith("/v1/url/")]
    assert sent == ["url=http%3A%2F%2Fphish-test.com%2Flogin"]
    assert not any("PRIVATE" in (c.url + (c.body or b"").decode()) for c in tr.calls)


# ================================================================== 6. rate-limit labelling

def test_rate_limit_basis_distinguishes_documented_quota_from_local_budgets():
    assert "documented" in RATE_LIMIT_BASIS["virustotal"]
    for p in ("urlhaus", "phishtank", "domain_age"):
        assert "application-side safety budget" in RATE_LIMIT_BASIS[p]
    assert set(RATE_LIMIT_BASIS) == set(DEFAULT_TI_CONFIG.rate_limits)


def test_local_budget_exhaustion_states_its_basis():
    c = cfg(enabled_providers=frozenset({"urlhaus"}), rate_limits={"urlhaus": ((1, 60),)})
    svc, tr, _ = service(route(uh=uh_clean), config=c)
    rep = svc.lookup_message(msg(sender="", attachments=[]), now=NOW)   # url + domain = 2 requests
    limited = [r for r in rep.results if r.error is E.RATE_LIMITED]
    assert limited and "application-side safety budget" in limited[0].error_detail
    assert len(tr.calls) == 1
