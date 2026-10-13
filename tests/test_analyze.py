import pytest

from engine.analyze import analyze
from engine.parser import parse_email
from engine.schemas import (
    Assessment,
    Channel,
    EvidenceStatus as S,
    IngestSource,
    NormalizedMessage,
    ReasonCode as RC,
    RiskBand as B,
)
from helpers import FIX, NOW, fixture_msg

FIXTURES = sorted(p.name for p in FIX.glob("*.eml"))


def test_legitimate_vendor_is_low_but_labelled_partial():
    a = analyze(fixture_msg("legit_vendor.eml"), now=NOW)
    assert a.risk_band == B.LOW
    assert a.reasons == []
    assert a.analysis_profile == "rules_only" and a.data_completeness == "partial"


def test_legitimate_vendor_uploaded_as_eml_is_insufficient_not_low():
    a = analyze(fixture_msg("legit_vendor.eml", IngestSource.EML_UPLOAD), now=NOW)
    assert a.risk_band == B.INSUFFICIENT_DATA


def test_credential_phish_is_urgent_with_verified_auth_failure():
    a = analyze(fixture_msg("credential_phish.eml"), now=NOW)
    assert a.risk_band == B.URGENT
    codes = {r.code for r in a.reasons}
    assert {RC.SPF_FAIL, RC.DMARC_FAIL, RC.DISPLAY_NAME_SPOOF, RC.LOOKALIKE_DOMAIN,
            RC.LINK_TEXT_MISMATCH} <= codes
    assert "U3_VERIFIED_AUTH_FAIL_WITH_IDENTITY" in a.policy_rules


def test_credential_phish_via_upload_is_urgent_but_not_on_header_claims():
    a = analyze(fixture_msg("credential_phish.eml", IngestSource.EML_UPLOAD), now=NOW)
    assert a.risk_band == B.URGENT                     # brand + look-alike combination
    assert not any(r.startswith("U3") for r in a.policy_rules)
    assert RC.SPF_FAIL not in {r.code for r in a.reasons}


def test_bec_with_reply_to_is_review_in_rules_only_baseline():
    a = analyze(fixture_msg("bec_reply_to.eml"), now=NOW)
    assert a.risk_band == B.REVIEW
    assert {RC.REPLY_TO_MISMATCH, RC.DISPLAY_NAME_SPOOF} <= {r.code for r in a.reasons}


def test_named_executive_with_reply_to_mismatch_is_urgent():
    raw = (
        b'From: "Alex Morgan" <alex.morgan.ceo@mail-hub.example>\n'
        b"Reply-To: alex.private@gmail.example\nSubject: favour\n"
        b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n\nCall me.\n"
    )
    m = parse_email(raw, "ex1", ingest_source=IngestSource.GMAIL_API)
    a = analyze(m, now=NOW)
    assert a.risk_band == B.URGENT
    assert RC.EXEC_IMPERSONATION in {r.code for r in a.reasons}


def test_invoice_pdf_exe_is_urgent_even_without_auth_headers():
    a = analyze(fixture_msg("malicious_attachment.eml"), now=NOW)
    assert a.risk_band == B.URGENT
    assert a.policy_rules == ["U2_EXECUTABLE_ATTACHMENT"]
    assert a.reasons[0].code == RC.RISKY_ATTACHMENT
    assert any(e.status == S.NOT_CHECKED for e in a.evidence)   # auth still shown as unchecked


def test_non_email_channels_are_insufficient_not_low():
    for ch in (Channel.SMS, Channel.WHATSAPP):
        a = analyze(NormalizedMessage(external_id="s", channel=ch, body_text="hi"), now=NOW)
        assert a.risk_band == B.INSUFFICIENT_DATA and a.data_completeness == "none"


@pytest.mark.parametrize("name", FIXTURES)
@pytest.mark.parametrize("source", [IngestSource.GMAIL_API, IngestSource.EML_UPLOAD])
def test_fixture_assessments_are_consistent_and_serialisable(name, source):
    a = analyze(fixture_msg(name, source), now=NOW)
    ids = [e.evidence_id for e in a.evidence]
    assert len(ids) == len(set(ids))
    for r in a.reasons:
        assert r.evidence_ids and set(r.evidence_ids) <= set(ids)
    assert a.risk_band != B.LOW or all(e.status != S.FOUND for e in a.evidence)
    assert Assessment.model_validate_json(a.model_dump_json()) == a
    assert a == analyze(fixture_msg(name, source), now=NOW)


def test_analyze_makes_no_network_calls():
    # conftest.py turns any socket use into a failure; running all fixtures is the test.
    for name in FIXTURES:
        analyze(fixture_msg(name), now=NOW)
