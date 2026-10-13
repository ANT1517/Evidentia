"""A lookup of a stripped URL must never be read as a verdict on the original full URL."""
import dataclasses

import pytest

from engine import DEFAULT_CONFIG, analyze
from engine.policy import PROFILES, decide
from engine.rules import CheckResult
from engine.schemas import Evidence, EvidenceStatus as S, ReasonCode as RC, RiskBand as B
from engine.threat_intel import ErrorCategory as E
from engine.threat_intel import IndicatorType as T
from engine.threat_intel.evidence import build_check_result
from engine.threat_intel.service import TI_VERSION
from helpers import NOW
from ti_helpers import (
    DOMAIN, URL, bare_msg, cfg, jr, msg, route, service, uh_clean, uh_listed, vt_stats,
)

UH = dict(enabled_providers=frozenset({"urlhaus"}))
FULL = dataclasses.replace(DEFAULT_CONFIG, active_profile="full")


def url_only(url, **kw):
    base = dict(sender="", attachments=[], urls=[url])
    base.update(kw)
    return msg(**base)


def url_result(rep):
    return [r for r in rep.results if r.indicator_type is T.URL][0]


def scope_rows(cr):
    return [e for e in cr.evidence if e.type == "threat_intel_full_url"]


# ------------------------------------------------------------------ negative lookups

@pytest.mark.parametrize("raw_url,omitted", [
    (URL + "?token=PRIVATE-QUERY", ("query",)),
    (URL + "#PRIVATE-FRAGMENT", ("fragment",)),
    (URL + "?a=1#PRIVATE-FRAGMENT", ("query", "fragment")),
])
def test_negative_lookup_on_stripped_url_is_partial_not_conclusive_for_the_original(raw_url, omitted):
    svc, tr, _ = service(route(uh=uh_clean), config=cfg(**UH))
    rep = svc.lookup_message(url_only(raw_url), now=NOW)
    r = url_result(rep)

    # What was actually asked: the stripped target, and the answer is a real (cacheable) one.
    assert r.status is S.NOT_FOUND and r.conclusive
    assert r.omitted == omitted and r.partial and not r.covers_original

    # The ledger records the partial scope and the unchecked full URL separately.
    cr = build_check_result(rep, svc.cfg, NOW)
    row = next(e for e in cr.evidence if e.type == "threat_intel_url")
    assert row.status is S.NOT_FOUND and "withheld" in row.detail and "full URL" in row.detail
    sc = scope_rows(cr)
    assert len(sc) == 1 and sc[0].status is S.NOT_CHECKED
    assert sc[0].source == "threat_intel:scope" and sc[0].observed_at == NOW
    assert all(o in sc[0].detail for o in omitted)
    assert not cr.completed

    # The omitted parts were never sent.
    sent = " ".join(c.url + (c.body or b"").decode() for c in tr.calls)
    assert "PRIVATE" not in sent and "token" not in sent
    assert all(c.url.startswith("https://urlhaus-api.abuse.ch/") for c in tr.calls)


def test_url_without_query_or_fragment_is_fully_covered_and_has_no_scope_row():
    svc, _, _ = service(route(uh=uh_clean), config=cfg(**UH))
    rep = svc.lookup_message(url_only(URL), now=NOW)
    r = url_result(rep)
    assert r.omitted == () and r.covers_original
    cr = build_check_result(rep, svc.cfg, NOW)
    assert cr.completed and scope_rows(cr) == []


def test_http_error_on_stripped_url_stays_not_checked():
    svc, _, _ = service(route(uh=lambda r: jr({}, 500)), config=cfg(max_retries=0, **UH))
    rep = svc.lookup_message(url_only(URL + "?x=1"), now=NOW)
    r = url_result(rep)
    assert r.status is S.NOT_CHECKED and r.error is E.SERVER_ERROR and r.omitted == ("query",)
    assert scope_rows(build_check_result(rep, svc.cfg, NOW)) == []   # no answer, so no scope claim


# ------------------------------------------------------------------ positive lookups

def test_positive_listing_on_redacted_target_is_found_and_says_what_was_matched():
    svc, tr, _ = service(route(uh=uh_listed), config=cfg(**UH))
    rep = svc.lookup_message(url_only(URL + "?token=PRIVATE-QUERY#PRIVATE-FRAGMENT"), now=NOW)
    r = url_result(rep)
    assert r.status is S.FOUND and r.omitted == ("query", "fragment")
    cr = build_check_result(rep, svc.cfg, NOW)
    assert "threat_intel.url_listed" in cr.facts
    reason = next(x for x in cr.reasons if x.code is RC.URL_ON_THREAT_LIST)
    assert "address of this link" in reason.text and "withheld" in reason.text
    ev = {e.evidence_id: e for e in cr.evidence}
    assert all(ev[i].status is S.FOUND for i in reason.evidence_ids)
    assert len(scope_rows(cr)) == 1                       # the full URL is still not covered
    assert not cr.completed
    assert "PRIVATE" not in " ".join(c.url + (c.body or b"").decode() for c in tr.calls)


def test_positive_listing_still_drives_urgent_end_to_end_with_incompleteness_visible():
    svc, _, _ = service(route(uh=uh_listed, vt=jr(vt_stats(0))))
    m = url_only(URL + "?utm=track#top", sender=f"a@{DOMAIN}")
    a = analyze(m, config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is B.URGENT and "U1_THREAT_INTEL_MATCH" in a.policy_rules
    ids = {e.evidence_id for e in a.evidence}
    assert all(r.evidence_ids and set(r.evidence_ids) <= ids for r in a.reasons)
    assert any(e.type == "threat_intel_full_url" and e.status is S.NOT_CHECKED for e in a.evidence)
    assert a.reasons[-1].code is RC.CHECK_INCOMPLETE
    assert a.model_versions["threat_intel"] == TI_VERSION == "0.1.1"


# ------------------------------------------------------------------ policy behaviour

def _ok(check):
    return CheckResult(check, True, [Evidence(evidence_id=f"{check}-1", type=check, value="",
                                              source="t", status=S.NOT_FOUND, observed_at=NOW)])


def _everything_else_clean():
    return [_ok(c) for c in sorted(PROFILES["full"].required) if c != "threat_intel"]


def test_partial_lookup_alone_cannot_qualify_the_full_assessment_for_low():
    svc, _, _ = service(route(uh=uh_clean, vt=jr(vt_stats(0))))
    partial = build_check_result(
        svc.lookup_message(bare_msg(attachments=[], urls=[URL + "?a=1"]), now=NOW), svc.cfg, NOW)
    exact = build_check_result(
        svc.lookup_message(bare_msg(attachments=[]), now=NOW), svc.cfg, NOW)
    assert not partial.completed and exact.completed

    d_partial = decide(_everything_else_clean() + [partial], DEFAULT_CONFIG, "full", NOW)
    assert d_partial.band is B.INSUFFICIENT_DATA
    assert "threat_intel" in d_partial.missing_checks
    assert d_partial.reasons[-1].code is RC.CHECK_INCOMPLETE
    cited = set(d_partial.reasons[-1].evidence_ids)
    assert any(e.evidence_id in cited and e.type == "threat_intel_full_url" for e in partial.evidence)

    d_exact = decide(_everything_else_clean() + [exact], DEFAULT_CONFIG, "full", NOW)
    assert d_exact.band is B.LOW                         # control: the same data minus the query


def test_analyze_full_profile_with_partial_lookup_is_never_low():
    svc, _, _ = service(route(uh=uh_clean, vt=jr(vt_stats(0))))
    a = analyze(bare_msg(attachments=[], urls=[URL + "?a=1"]), config=FULL, now=NOW, threat_intel=svc)
    assert a.risk_band is not B.LOW


# ------------------------------------------------------------------ caching and merging

def test_scope_is_not_inherited_through_the_cache():
    svc, tr, _ = service(route(uh=uh_clean), config=cfg(**UH))
    first = url_result(svc.lookup_message(url_only(URL), now=NOW))                 # exact, cached
    assert first.omitted == () and not first.cache_hit
    n = len(tr.calls)
    second = url_result(svc.lookup_message(url_only(URL + "?a=1"), now=NOW))       # same target
    assert len(tr.calls) == n and second.cache_hit
    assert second.omitted == ("query",) and not second.covers_original           # not exact

    svc2, _, _ = service(route(uh=uh_clean), config=cfg(**UH))
    p = url_result(svc2.lookup_message(url_only(URL + "?a=1"), now=NOW))            # partial, cached
    e = url_result(svc2.lookup_message(url_only(URL), now=NOW))
    assert p.omitted == ("query",) and e.omitted == () and e.cache_hit and e.covers_original


def test_duplicate_forms_merge_and_stay_partial_if_any_form_was():
    svc, tr, _ = service(route(uh=uh_clean), config=cfg(**UH))
    m = msg(sender="", attachments=[], urls=[URL, URL + "?a=1", URL + "#f"])
    inds = svc.collect_indicators(m)
    urls = [i for i in inds if i.type is T.URL]
    assert len(urls) == 1 and urls[0].omitted == ("query", "fragment")
    rep = svc.lookup_message(m, now=NOW)
    assert len([r for r in rep.results if r.indicator_type is T.URL]) == 1
    assert not build_check_result(rep, svc.cfg, NOW).completed


def test_domain_and_hash_indicators_are_never_marked_partial():
    svc, _, _ = service(route(uh=uh_clean, vt=jr(vt_stats(0))))
    rep = svc.lookup_message(msg(), now=NOW)             # URL has query+fragment; hash and domains too
    for r in rep.results:
        if r.indicator_type is not T.URL:
            assert r.omitted == ()


def test_original_value_never_appears_in_any_assessment_output():
    svc, _, _ = service(route(uh=uh_listed, vt=jr(vt_stats(0))))
    m = url_only(URL + "?token=PRIVATE-QUERY#PRIVATE-FRAGMENT", sender=f"a@{DOMAIN}")
    a = analyze(m, config=FULL, now=NOW, threat_intel=svc)
    assert "PRIVATE" not in a.model_dump_json()
