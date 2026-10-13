from dataclasses import replace

import pytest

from engine.analyze import analyze
from engine.config import DEFAULT_CONFIG as CFG
from engine.policy import PROFILES, POLICY_VERSION, decide
from engine.rules import CheckResult
from engine.schemas import (
    AuthResults,
    Evidence,
    EvidenceStatus as S,
    IngestSource,
    ReasonCode as RC,
    RiskBand as B,
)
from helpers import NOW, att, make, trusted_auth

REQUIRED = sorted(PROFILES["rules_only"].required)


def clean(check: str) -> CheckResult:
    ev = Evidence(evidence_id=f"{check}-1", type=check, value="", source="t",
                  status=S.NOT_FOUND, observed_at=NOW)
    return CheckResult(check, completed=True, evidence=[ev])


def failed(check: str) -> CheckResult:
    ev = Evidence(evidence_id=f"{check}-1", type=check, value="", source="t",
                  status=S.NOT_CHECKED, observed_at=NOW)
    return CheckResult(check, completed=False, evidence=[ev])


def with_facts(check: str, *facts: str) -> CheckResult:
    r = clean(check)
    r.facts |= set(facts)
    return r


def all_clean(**override) -> list[CheckResult]:
    base = {c: clean(c) for c in REQUIRED}
    base.update(override)
    return list(base.values())


def run(results, profile="rules_only", cfg=CFG):
    return decide(results, cfg, profile, NOW)


# ------------------------------------------------------------------ bands

def test_low_only_when_every_required_check_completed_and_clean():
    d = run(all_clean())
    assert d.band == B.LOW and d.policy_rules == ["L1_ALL_REQUIRED_CHECKS_CLEAN"]


@pytest.mark.parametrize("check", REQUIRED)
def test_low_is_impossible_when_any_required_check_fails(check):
    d = run(all_clean(**{check: failed(check)}))
    assert d.band == B.INSUFFICIENT_DATA
    assert check in d.missing_checks
    assert d.reasons[-1].code == RC.CHECK_INCOMPLETE


@pytest.mark.parametrize("check", REQUIRED)
def test_low_is_impossible_when_a_required_check_never_ran(check):
    results = [r for r in all_clean() if r.check != check]
    d = run(results)
    assert d.band == B.INSUFFICIENT_DATA
    reason = d.reasons[-1]
    assert reason.code == RC.CHECK_INCOMPLETE
    synthetic = {e.evidence_id: e for e in d.extra_evidence}
    assert synthetic[f"missing-{check}"].status == S.NOT_CHECKED
    assert f"missing-{check}" in reason.evidence_ids


def test_failed_non_required_check_does_not_block_low():
    assert "auth_dkim" not in PROFILES["rules_only"].required
    d = run(all_clean() + [failed("auth_dkim")])
    assert d.band == B.LOW


def test_review_for_single_indicators_never_urgent():
    for fact in ("reply_to.mismatch", "lookalike.domain", "link.mismatch",
                 "identity.title_claim", "identity.brand_mismatch", "identity.person_mismatch",
                 "attachment.macro", "attachment.risky_other", "auth.trusted_softfail"):
        d = run(all_clean(identity=with_facts("identity", fact)))
        assert d.band == B.REVIEW, fact


def test_verified_auth_fail_alone_is_review():
    d = run(all_clean(auth_spf=with_facts("auth_spf", "auth.trusted_fail", "auth.spf_fail")))
    assert d.band == B.REVIEW


def test_verified_auth_fail_plus_identity_mismatch_is_urgent():
    for ident in ("identity.brand_mismatch", "identity.exec_mismatch",
                  "identity.protected_domain_sender"):
        d = run(all_clean(
            auth_spf=with_facts("auth_spf", "auth.trusted_fail"),
            identity=with_facts("identity", ident),
        ))
        assert d.band == B.URGENT, ident
        assert "U3_VERIFIED_AUTH_FAIL_WITH_IDENTITY" in d.policy_rules


def test_executable_attachment_is_urgent():
    d = run(all_clean(attachments=with_facts("attachments", "attachment.executable")))
    assert d.band == B.URGENT and d.policy_rules == ["U2_EXECUTABLE_ATTACHMENT"]


def test_threat_intel_match_is_urgent_once_a_check_supplies_it():
    for fact in ("threat_intel.url_listed", "threat_intel.hash_listed"):
        d = run(all_clean() + [with_facts("threat_intel", fact)])
        assert d.band == B.URGENT and "U1_THREAT_INTEL_MATCH" in d.policy_rules


def test_configured_combinations_drive_urgent_and_are_editable():
    facts = ("identity.exec_mismatch", "reply_to.mismatch")
    d = run(all_clean(identity=with_facts("identity", facts[0]),
                      reply_to=with_facts("reply_to", facts[1])))
    assert d.band == B.URGENT
    assert d.policy_rules == ["U4_COMBINATION:identity.exec_mismatch+reply_to.mismatch"]

    no_combo = replace(CFG, urgent_combinations=())
    d2 = run(all_clean(identity=with_facts("identity", facts[0]),
                       reply_to=with_facts("reply_to", facts[1])), cfg=no_combo)
    assert d2.band == B.REVIEW


def test_precedence_urgent_over_review_over_insufficient():
    urgent = run(all_clean(attachments=with_facts("attachments", "attachment.executable"),
                           auth_spf=failed("auth_spf")))
    assert urgent.band == B.URGENT
    review = run(all_clean(reply_to=with_facts("reply_to", "reply_to.mismatch"),
                           auth_spf=failed("auth_spf")))
    assert review.band == B.REVIEW
    assert review.reasons[-1].code == RC.CHECK_INCOMPLETE      # incompleteness still shown


# ------------------------------------------------------------------ profiles

def test_rules_only_low_is_labelled_partial_and_lists_out_of_scope_checks():
    d = run(all_clean())
    assert d.profile == "rules_only" and d.data_completeness == "partial"
    oos = {e.type: e for e in d.extra_evidence if e.evidence_id.startswith("out-of-scope-")}
    assert set(oos) == {"threat_intel", "text_model", "intent_questions"}
    assert all(e.status == S.NOT_CHECKED for e in oos.values())


def test_full_profile_cannot_be_low_without_threat_intel_and_models():
    d = run(all_clean(), profile="full")
    assert d.band == B.INSUFFICIENT_DATA
    assert {"threat_intel", "text_model", "intent_questions"} <= set(d.missing_checks)


def test_full_profile_low_only_when_everything_completed():
    extra = [clean("threat_intel"), clean("text_model"), clean("intent_questions")]
    d = run(all_clean() + extra, profile="full")
    assert d.band == B.LOW and d.data_completeness == "complete"


def test_completeness_none_when_nothing_ran():
    d = run([failed(c) for c in REQUIRED])
    assert d.band == B.INSUFFICIENT_DATA and d.data_completeness == "none"


# ------------------------------------------------------------------ via analyze()

def test_analyze_reports_policy_version_profile_and_rules():
    a = analyze(make(), now=NOW)
    assert a.policy_version == POLICY_VERSION == "0.2.1"
    assert a.analysis_profile == "rules_only"
    assert a.data_completeness == "partial"
    assert a.risk_band == B.LOW
    assert a.model_versions == {"rules": "0.1.0"}


def test_analyze_decisions_are_stable():
    m = make(sender="a@micros0ft-secure.example", sender_display_name="Microsoft Support",
             attachments=[att("x.docm")])
    a, b = analyze(m, now=NOW), analyze(m, now=NOW)
    assert a == b
    assert a.model_dump_json() == b.model_dump_json()


def test_analyze_untrusted_auth_makes_clean_message_insufficient_not_low():
    a = analyze(make(ingest_source=IngestSource.EML_UPLOAD), now=NOW)
    assert a.risk_band == B.INSUFFICIENT_DATA
    assert a.reasons[-1].code == RC.CHECK_INCOMPLETE
    assert "unverified" in " ".join(e.detail or "" for e in a.evidence)


def test_analyze_forged_header_cannot_buy_urgent_via_auth_rule():
    m = make(ingest_source=IngestSource.EML_UPLOAD, auth=trusted_auth(spf="fail", dmarc="fail"),
             sender="a@random-host.example", sender_display_name="Microsoft Account Team")
    a = analyze(m, now=NOW)
    assert not any(r.startswith("U3") for r in a.policy_rules)
    assert RC.SPF_FAIL not in {r.code for r in a.reasons}


def test_analyze_forged_pass_cannot_clear_a_message():
    m = make(ingest_source=IngestSource.EML_UPLOAD, auth=trusted_auth(),
             attachments=[att("q.docm")])
    assert analyze(m, now=NOW).risk_band == B.REVIEW


def test_every_reason_cites_existing_evidence_for_every_band():
    msgs = [
        make(),
        make(ingest_source=IngestSource.EML_UPLOAD),
        make(reply_to="x@gmail.example"),
        make(attachments=[att("invoice.pdf.exe")], auth=AuthResults()),
        make(sender="", auth=AuthResults()),
    ]
    for m in msgs:
        a = analyze(m, now=NOW)
        ids = [e.evidence_id for e in a.evidence]
        assert len(ids) == len(set(ids))
        for r in a.reasons:
            assert r.evidence_ids and set(r.evidence_ids) <= set(ids)
