from engine.config import DEFAULT_CONFIG as CFG
from engine.config import EngineConfig
from engine.parser import parse_email
from engine.rules import (
    check_attachments,
    check_auth,
    check_identity,
    check_link_mismatch,
    check_lookalike,
    check_reply_to,
    run_rules,
)
from engine.schemas import (
    AuthResults,
    EvidenceStatus as S,
    IngestSource,
    LinkMismatch,
    ReasonCode as RC,
)
from helpers import NOW, att, by_check, fixture_msg, make, trusted_auth

codes = lambda r: {x.code for x in r.reasons}


# ------------------------------------------------------------------ authentication

def test_legit_vendor_all_checks_complete_and_clean():
    results = run_rules(fixture_msg("legit_vendor.eml"), CFG, NOW)
    assert all(r.completed for r in results)
    assert all(not r.facts for r in results)
    assert all(not r.reasons for r in results)


def test_trusted_spf_and_dmarc_fail_are_found():
    m = make(auth=trusted_auth(spf="fail", dmarc="fail"))
    spf = check_auth(m, CFG, NOW, "spf")
    dmarc = check_auth(m, CFG, NOW, "dmarc")
    assert spf.completed and dmarc.completed
    assert codes(spf) == {RC.SPF_FAIL} and codes(dmarc) == {RC.DMARC_FAIL}
    assert spf.evidence[0].status == S.FOUND
    assert "auth.trusted_fail" in spf.facts
    assert spf.reasons[0].evidence_ids == [spf.evidence[0].evidence_id]


def test_softfail_is_weaker_than_fail():
    r = check_auth(make(auth=trusted_auth(spf="softfail")), CFG, NOW, "spf")
    assert r.facts == {"auth.trusted_softfail"}
    assert "auth.trusted_fail" not in r.facts


def test_missing_auth_headers_are_not_checked_never_pass():
    m = make(auth=AuthResults())
    for mech in ("spf", "dkim", "dmarc"):
        r = check_auth(m, CFG, NOW, mech)
        assert not r.completed
        assert r.evidence[0].status == S.NOT_CHECKED
        assert r.evidence[0].source == "authentication-results:absent"
        assert not r.facts and not r.reasons


def test_forged_results_in_uploaded_eml_are_untrusted():
    # legit_vendor.eml carries spf=pass / dmarc=pass from "mx.ourcompany.example".
    m = fixture_msg("legit_vendor.eml", IngestSource.EML_UPLOAD)
    assert m.auth.spf == "pass"                     # parsed, but only as a claim
    r = check_auth(m, CFG, NOW, "spf")
    assert not r.completed
    ev = r.evidence[0]
    assert ev.status == S.NOT_CHECKED
    assert ev.source == "authentication-results:untrusted"
    assert "unverified" in ev.detail


def test_forged_fail_in_uploaded_eml_never_triggers_high_risk_facts():
    m = make(auth=trusted_auth(spf="fail", dmarc="fail"), ingest_source=IngestSource.EML_UPLOAD)
    for mech in ("spf", "dmarc"):
        r = check_auth(m, CFG, NOW, mech)
        assert not r.completed and not r.facts and not r.reasons


def test_unknown_ingest_source_defaults_to_untrusted():
    m = make(ingest_source=IngestSource.UNKNOWN)
    assert not check_auth(m, CFG, NOW, "spf").completed


def test_gmail_path_but_foreign_authserv_id_is_untrusted():
    m = make(auth=trusted_auth(authserv_id="evil.example"))
    r = check_auth(m, CFG, NOW, "spf")
    assert not r.completed and r.evidence[0].status == S.NOT_CHECKED


def test_received_spf_fallback_is_never_trusted():
    raw = b"From: a@b.example\nReceived-SPF: pass (self declared)\nSubject: x\n\nhi\n"
    m = parse_email(raw, "r", ingest_source=IngestSource.GMAIL_API)
    assert m.auth.spf == "pass" and m.auth.authserv_id is None
    assert not check_auth(m, CFG, NOW, "spf").completed


def test_only_topmost_authentication_results_header_is_read():
    raw = (
        b"Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n"
        b"Authentication-Results: mx.attacker.example; spf=pass; dkim=pass; dmarc=pass\n"
        b"From: a@b.example\nSubject: x\n\nhi\n"
    )
    m = parse_email(raw, "r", ingest_source=IngestSource.GMAIL_API)
    assert (m.auth.spf, m.auth.dmarc, m.auth.authserv_id) == ("fail", "fail", "mx.google.com")


def test_inconclusive_trusted_result_is_not_checked():
    r = check_auth(make(auth=trusted_auth(spf="temperror")), CFG, NOW, "spf")
    assert not r.completed and r.evidence[0].status == S.NOT_CHECKED


# ------------------------------------------------------------------ reply-to

def test_reply_to_mismatch():
    r = check_reply_to(make(reply_to="boss@gmail.example"), CFG, NOW)
    assert r.completed and codes(r) == {RC.REPLY_TO_MISMATCH}
    assert r.facts == {"reply_to.mismatch"}
    assert r.evidence[0].status == S.FOUND


def test_reply_to_same_registered_domain_is_clean():
    r = check_reply_to(make(reply_to="support@mail.acmesupplies.example"), CFG, NOW)
    assert r.completed and not r.reasons
    assert r.evidence[0].status == S.NOT_FOUND


def test_no_reply_to_header_is_clean_but_missing_sender_is_not_checked():
    assert check_reply_to(make(), CFG, NOW).evidence[0].status == S.NOT_FOUND
    r = check_reply_to(make(sender=""), CFG, NOW)
    assert not r.completed and r.evidence[0].status == S.NOT_CHECKED


# ------------------------------------------------------------------ identity

def test_executive_display_name_with_wrong_address():
    m = make(sender="alex.morgan.ceo@gmail.example", sender_display_name="Alex Morgan")
    r = check_identity(m, CFG, NOW)
    assert codes(r) == {RC.EXEC_IMPERSONATION}
    assert "identity.exec_mismatch" in r.facts


def test_executive_name_order_and_case_do_not_matter():
    m = make(sender="x@other.example", sender_display_name="MORGAN, Alex (CEO)")
    assert "identity.exec_mismatch" in check_identity(m, CFG, NOW).facts


def test_real_executive_address_is_not_flagged():
    m = make(sender="alex.morgan@ourcompany.example", sender_display_name="Alex Morgan")
    r = check_identity(m, CFG, NOW)
    assert not r.reasons
    assert "identity.exec_mismatch" not in r.facts
    assert "identity.protected_domain_sender" in r.facts      # context only, not an indicator


def test_non_executive_employee_name_is_review_level_spoof():
    m = make(sender="priya@other.example", sender_display_name="Priya Nair")
    r = check_identity(m, CFG, NOW)
    assert codes(r) == {RC.DISPLAY_NAME_SPOOF}
    assert "identity.person_mismatch" in r.facts


def test_brand_display_name_from_foreign_domain():
    m = make(sender="no-reply@random-host.example", sender_display_name="Microsoft Account Team")
    r = check_identity(m, CFG, NOW)
    assert codes(r) == {RC.DISPLAY_NAME_SPOOF}
    assert "identity.brand_mismatch" in r.facts


def test_brand_display_name_from_real_brand_domain_is_clean():
    m = make(sender="no-reply@mail.microsoft.com", sender_display_name="Microsoft Account Team")
    assert not check_identity(m, CFG, NOW).reasons


def test_executive_title_claim_without_known_address():
    m = make(sender="rajesh@ourcompany.example", sender_display_name="Rajesh Kumar (CEO)")
    r = check_identity(m, CFG, NOW)
    assert "identity.title_claim" in r.facts and codes(r) == {RC.DISPLAY_NAME_SPOOF}


def test_address_inside_display_name_that_is_not_the_sender():
    m = make(sender="x@evil.example", sender_display_name="alex.morgan@ourcompany.example")
    assert "identity.display_address_mismatch" in check_identity(m, CFG, NOW).facts


def test_ordinary_display_name_is_clean_and_ran():
    r = check_identity(make(), CFG, NOW)
    assert r.completed and not r.reasons
    assert r.evidence[-1].status == S.NOT_FOUND


# ------------------------------------------------------------------ look-alike domains

def test_lookalike_digit_substitution_sender():
    m = make(sender="a@micros0ft-secure.example")
    r = check_lookalike(m, CFG, NOW)
    assert codes(r) == {RC.LOOKALIKE_DOMAIN}
    assert {"lookalike.domain", "lookalike.sender"} <= r.facts


def test_lookalike_rn_for_m_against_org_domain():
    m = make(sender="a@ourcornpany.example")
    assert "lookalike.domain" in check_lookalike(m, CFG, NOW).facts


def test_lookalike_one_character_off():
    assert "lookalike.domain" in check_lookalike(make(sender="a@paypa.example"), CFG, NOW).facts
    assert "lookalike.domain" in check_lookalike(make(sender="a@gooogle.com"), CFG, NOW).facts


def test_lookalike_same_name_different_ending():
    assert "lookalike.domain" in check_lookalike(make(sender="a@microsoft.example"), CFG, NOW).facts


def test_lookalike_lure_word_joined():
    assert "lookalike.domain" in check_lookalike(make(sender="a@paypalsecure.com"), CFG, NOW).facts


def test_lookalike_idn_homograph_and_its_punycode_form():
    uni = "microsоft.com"                                     # Cyrillic о
    puny = uni.encode("idna").decode("ascii")
    for host in (uni, puny):
        r = check_lookalike(make(sender=f"a@{host}"), CFG, NOW)
        assert "lookalike.domain" in r.facts, host


def test_lookalike_in_link_host():
    m = make(urls=["http://login.micros0ft-support.example/x"])
    r = check_lookalike(m, CFG, NOW)
    assert "lookalike.domain" in r.facts and "lookalike.sender" not in r.facts


def test_real_protected_domains_and_unrelated_domains_are_clean():
    m = make(sender="a@mail.microsoft.com", urls=["https://www.google.com/", "https://acmesupplies.example"])
    r = check_lookalike(m, CFG, NOW)
    assert r.completed and not r.facts and r.evidence[0].status == S.NOT_FOUND


def test_lookalike_missing_sender_is_not_checked():
    r = check_lookalike(make(sender=""), CFG, NOW)
    assert not r.completed and r.evidence[0].status == S.NOT_CHECKED


# ------------------------------------------------------------------ link text vs destination

def test_link_text_mismatch_from_parser_field():
    m = make(link_mismatches=[LinkMismatch(
        shown_domain="microsoft.com", href="http://evil.example/x", href_domain="evil.example")])
    r = check_link_mismatch(m, CFG, NOW)
    assert codes(r) == {RC.LINK_TEXT_MISMATCH} and r.facts == {"link.mismatch"}


def test_parsed_phish_fixture_has_link_mismatch_rule():
    r = check_link_mismatch(fixture_msg("credential_phish.eml"), CFG, NOW)
    assert "link.mismatch" in r.facts


def test_no_link_mismatch_is_clean():
    r = check_link_mismatch(make(), CFG, NOW)
    assert r.completed and not r.reasons and r.evidence[0].status == S.NOT_FOUND


# ------------------------------------------------------------------ attachments

def test_double_extension_executable():
    r = check_attachments(make(attachments=[att("invoice.pdf.exe")]), CFG, NOW)
    assert r.facts == {"attachment.executable"} and codes(r) == {RC.RISKY_ATTACHMENT}
    assert "disguised" in r.reasons[0].text
    assert "not opened" in r.evidence[0].detail


def test_plain_executable_extensions():
    for name in ("setup.exe", "update.SCR", "run.js", "x.ps1", "tool.bat"):
        r = check_attachments(make(attachments=[att(name)]), CFG, NOW)
        assert "attachment.executable" in r.facts, name


def test_macro_capable_office_extensions_are_review_level():
    for name in ("q3.docm", "budget.xlsm", "deck.pptm"):
        r = check_attachments(make(attachments=[att(name)]), CFG, NOW)
        assert r.facts == {"attachment.macro"}, name


def test_normal_attachments_do_not_fire():
    files = [att("report.pdf", "application/pdf"), att("photo.jpg"), att("notes.docx"),
             att("data.xlsx"), att("archive.tar.gz"), att("README")]
    r = check_attachments(make(attachments=files), CFG, NOW)
    assert r.completed and not r.facts and not r.reasons
    assert r.evidence[0].status == S.NOT_FOUND


def test_executable_hidden_inside_name_and_declared_type_are_review_level():
    assert check_attachments(make(attachments=[att("invoice.exe.pdf")]), CFG, NOW).facts == {
        "attachment.risky_other"}
    r = check_attachments(make(attachments=[att("notes.txt", "application/x-msdownload")]), CFG, NOW)
    assert r.facts == {"attachment.risky_other"}


def test_trailing_dots_and_spaces_do_not_hide_extension():
    r = check_attachments(make(attachments=[att("invoice.pdf.exe . ")]), CFG, NOW)
    assert "attachment.executable" in r.facts


def test_bidi_override_is_escaped_in_evidence_and_flagged():
    r = check_attachments(make(attachments=[att("photo‮gpj.png")]), CFG, NOW)
    assert "attachment.risky_other" in r.facts
    assert "‮" not in r.evidence[0].value and "\\u202e" in r.evidence[0].value


def test_attachment_judged_by_name_only_never_by_declared_type_alone_as_exe():
    # A .pdf name that declares a PDF type is clean even if bytes could be anything:
    # we make no claim about contents either way.
    r = check_attachments(make(attachments=[att("a.pdf", "application/pdf")]), CFG, NOW)
    assert not r.facts


# ------------------------------------------------------------------ ledger integrity

def test_evidence_ids_unique_and_reasons_reference_existing_rows():
    m = make(
        sender="a@micros0ft-secure.example", sender_display_name="Microsoft Account Team",
        reply_to="x@gmail.example", attachments=[att("invoice.pdf.exe"), att("q.docm")],
        auth=trusted_auth(spf="fail", dmarc="fail"),
        link_mismatches=[LinkMismatch(shown_domain="microsoft.com", href="http://e.example",
                                      href_domain="e.example")],
    )
    results = run_rules(m, CFG, NOW)
    ids = [e.evidence_id for r in results for e in r.evidence]
    assert len(ids) == len(set(ids))
    for r in results:
        own = {e.evidence_id for e in r.evidence}
        for reason in r.reasons:
            assert reason.evidence_ids and set(reason.evidence_ids) <= own
            assert all(
                next(e for e in r.evidence if e.evidence_id == i).status == S.FOUND
                for i in reason.evidence_ids
            )


def test_rules_are_deterministic():
    m = fixture_msg("credential_phish.eml")
    a = run_rules(m, CFG, NOW)
    b = run_rules(m, CFG, NOW)
    assert [(r.check, r.completed, r.facts, [e.model_dump() for e in r.evidence]) for r in a] == \
           [(r.check, r.completed, r.facts, [e.model_dump() for e in r.evidence]) for r in b]


def test_config_is_not_hard_coded_in_rules():
    cfg = EngineConfig(org_domains=("acme-corp.example",), directory=())
    m = make(sender="a@acme-c0rp.example")
    assert "lookalike.domain" in check_lookalike(m, cfg, NOW).facts
    assert "lookalike.domain" not in check_lookalike(m, CFG, NOW).facts
