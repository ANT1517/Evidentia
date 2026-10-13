from dataclasses import replace

import pytest

from engine import DEFAULT_CONFIG, analyze
from engine.policy import PROFILES, POLICY_VERSION
from engine.schemas import EvidenceStatus as S, ReasonCode as RC, RiskBand as B
from engine.threat_intel import ThreatIntelService
from helpers import NOW
from ti_helpers import (
    DOMAIN, HASH, KEY, URL_RAW, FakeTransport, cfg, jr, msg, rdap, raw, route, service,
    sharing, uh_clean, uh_listed, vt_stats,
)

FULL = replace(DEFAULT_CONFIG, active_profile="full")


def clean_msg(**kw):
    # No attachment so that no rule fires; auth is trusted-pass from helpers.make()
    base = dict(attachments=[], sender=f"billing@{DOMAIN}")
    base.update(kw)
    return msg(**base)


def ids(a):
    return [e.evidence_id for e in a.evidence]


def assert_consistent(a):
    assert len(ids(a)) == len(set(ids(a)))
    for r in a.reasons:
        assert r.evidence_ids and set(r.evidence_ids) <= set(ids(a))


# ------------------------------------------------------------------ rules_only stays offline

def test_rules_only_never_touches_the_network_even_with_a_service_supplied():
    def explode(req):
        raise AssertionError("external request under rules_only")

    tr = FakeTransport(explode)
    svc = ThreatIntelService(cfg(), transport=tr, key_provider=lambda n: KEY)
    a = analyze(msg(), now=NOW, threat_intel=svc)
    assert tr.calls == []
    assert a.analysis_profile == "rules_only"
    assert "threat_intel" not in a.model_versions
    assert not any(e.source.startswith("threat_intel") for e in a.evidence)


def test_analyze_without_service_is_unchanged_and_backward_compatible():
    a = analyze(clean_msg(), now=NOW)
    assert a.risk_band is B.LOW and a.policy_version == POLICY_VERSION == "0.2.1"


# ------------------------------------------------------------------ full profile

def test_listed_url_is_urgent_with_valid_evidence():
    svc, tr, _ = service(route(uh=uh_listed, vt=jr(vt_stats(0))))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.URGENT and "U1_THREAT_INTEL_MATCH" in a.policy_rules
    r = next(r for r in a.reasons if r.code is RC.URL_ON_THREAT_LIST)
    ev = {e.evidence_id: e for e in a.evidence}
    assert all(ev[i].status is S.FOUND and ev[i].source == "threat_intel:urlhaus"
               for i in r.evidence_ids)
    assert a.model_versions["threat_intel"] == "0.1.1"
    assert_consistent(a)


def test_listed_attachment_hash_is_urgent():
    m = msg(sender="", urls=[])                    # keeps the hash indicator only
    svc, _, _ = service(route(uh=uh_listed))
    a = analyze(m, config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.URGENT
    assert RC.HASH_ON_THREAT_LIST in {r.code for r in a.reasons}


def test_phishtank_verified_listing_is_urgent():
    pt = jr({"results": {"in_database": True, "verified": "y", "valid": "y"}})
    svc, _, _ = service(route(pt=pt, uh=uh_clean, vt=jr(vt_stats(0))))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.URGENT


def test_unverified_phishtank_report_is_review_not_urgent():
    pt = jr({"results": {"in_database": True, "verified": "n"}})
    svc, _, _ = service(route(pt=pt, uh=uh_clean, vt=jr(vt_stats(0))))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.REVIEW
    assert not any(p.startswith("U") for p in a.policy_rules)


def test_single_virustotal_detection_is_not_conclusive():
    svc, _, _ = service(route(vt=jr(vt_stats(malicious=1)), uh=uh_clean))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is not B.URGENT
    assert RC.URL_ON_THREAT_LIST not in {r.code for r in a.reasons}
    vt = [e for e in a.evidence if e.source == "threat_intel:virustotal" and e.status is S.FOUND]
    assert vt                                       # preserved in the ledger, policy ignores it


def test_strong_virustotal_domain_detection_is_review_not_urgent():
    # The URL and file lookups are clean; only the domain gets 10 detections.
    def vt(req):
        return jr(vt_stats(malicious=10)) if "/domains/" in req.url else jr(vt_stats(0))

    svc, _, _ = service(route(vt=vt, uh=uh_clean))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.REVIEW


def test_new_domain_alone_is_review_never_urgent():
    svc, _, _ = service(route(rd=jr(rdap("2026-10-10T00:00:00Z")), uh=uh_clean, vt=jr(vt_stats(0))))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.REVIEW
    assert RC.NEW_DOMAIN in {r.code for r in a.reasons}
    assert not any(p.startswith("U") for p in a.policy_rules)
    assert_consistent(a)


# ------------------------------------------------------------------ completeness

def test_clean_threat_intel_alone_never_makes_full_profile_low():
    svc, tr, _ = service(route(uh=uh_clean, vt=jr(vt_stats(0))))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert tr.calls
    assert a.risk_band is B.INSUFFICIENT_DATA
    assert a.data_completeness == "partial"
    check_ev = [e for e in a.evidence if e.evidence_id.startswith("missing-")]
    assert {e.type for e in check_ev} == {"text_model", "intent_questions"}   # TI itself ran
    assert a.reasons[-1].code is RC.CHECK_INCOMPLETE
    assert_consistent(a)


def test_unavailable_threat_intel_is_insufficient_data():
    svc, _, _ = service(route(uh=raw(b"", 503), pt=raw(b"", 503), vt=raw(b"", 503)),
                        config=cfg(max_retries=0))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.INSUFFICIENT_DATA
    ti = [e for e in a.evidence if e.evidence_id.startswith("threat_intel-")]
    assert ti and all(e.status is not S.NOT_FOUND or e.source == "threat_intel:domain_age" for e in ti)
    assert_consistent(a)


def test_threat_intel_unavailable_is_visible_when_profile_requires_it_but_no_service():
    a = analyze(clean_msg(), config=FULL, now=NOW)
    miss = [e for e in a.evidence if e.evidence_id == "missing-threat_intel"]
    assert miss and miss[0].status is S.NOT_CHECKED
    assert a.risk_band is B.INSUFFICIENT_DATA


def test_default_deny_config_yields_not_checked_never_clean():
    svc = ThreatIntelService(transport=FakeTransport(), key_provider=lambda n: KEY)   # all defaults
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    ti = [e for e in a.evidence if e.evidence_id.startswith("threat_intel-")]
    assert ti and all(e.status is S.NOT_CHECKED for e in ti)
    assert a.risk_band is B.INSUFFICIENT_DATA


def test_privacy_blocked_indicators_block_completeness_but_not_other_findings():
    from engine.threat_intel import SharingPolicy
    svc, tr, _ = service(route(uh=uh_listed), config=cfg(sharing=SharingPolicy()))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    assert tr.calls == [] and a.risk_band is B.INSUFFICIENT_DATA
    assert any("privacy_blocked" in (e.detail or "") for e in a.evidence)


def test_org_domain_is_never_looked_up_even_if_someone_approves_it():
    org = "ourcompany.example"
    m = clean_msg(sender=f"x@{org}", urls=[])
    svc, tr, _ = service(config=cfg(sharing=sharing(domains=(org,), urls=(), hashes=())))
    a = analyze(m, config=FULL, now=NOW, threat_intel=svc)
    assert not any(org in c.url or org in (c.body or b"").decode() for c in tr.calls)
    assert any("protected company domain" in (e.detail or "") for e in a.evidence)


# ------------------------------------------------------------------ determinism & contract

def test_assessment_with_threat_intel_is_deterministic_and_serialisable():
    def run():
        svc, _, _ = service(route(uh=uh_listed, vt=jr(vt_stats(0))))
        return analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)

    a, b = run(), run()
    assert a == b and a.model_dump_json() == b.model_dump_json()
    from engine import Assessment
    assert Assessment.model_validate_json(a.model_dump_json()) == a


def test_no_secret_value_reaches_the_assessment():
    svc, _, _ = service(route(uh=uh_listed, vt=jr(vt_stats(0))))
    a = analyze(clean_msg(), config=FULL, now=NOW, threat_intel=svc)
    blob = a.model_dump_json()
    for secret in (KEY, "SECRET-TOKEN", "frag-part", HASH):
        assert secret not in blob


def test_threat_intel_check_is_required_in_full_profile_only():
    assert "threat_intel" in PROFILES["full"].required
    assert "threat_intel" not in PROFILES["rules_only"].required
