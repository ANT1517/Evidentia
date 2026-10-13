import io
import json
from pathlib import Path

import pytest

from evaluation import schema as S
from evaluation.secrets_scan import luhn_ok, scan_text
from evaluation.similarity import near_duplicate_pairs, normalise, text_digest
from evaluation.validate import PROFILES, load_jsonl, validate_file, validate_records
from eval_helpers import SENTINEL, codes, entries, jsonl, long_text, rec, reviewed

EXAMPLES = Path(__file__).resolve().parents[1] / "evaluation" / "data" / "examples_synthetic.jsonl"
SCHEMA_FILE = Path(__file__).resolve().parents[1] / "evaluation" / "schema" / "record.schema.json"


def check(records, **kw):
    return validate_records(entries(records), **kw)


# ------------------------------------------------------------------ shipped files

def test_example_file_is_valid_provisional_and_does_not_meet_the_starter_profile():
    rep = validate_file(EXAMPLES, profile="starter")
    assert rep.ok and rep.warnings == [] and rep.n_records == 11
    assert rep.coverage_met is False and rep.coverage_failures
    c = rep.coverage
    assert c["independent"] == 0 and set(c["by_label_status"]) <= {"provisional", "needs_review"}
    assert c["by_split"] == {"unassigned": 11}


def test_example_records_are_wholly_synthetic_and_use_reserved_domains():
    for _, r, _ in load_jsonl(EXAMPLES):
        assert r["provenance"]["source_type"] == "synthetic"
        assert r["provenance"]["license"] == "project-synthetic"
        assert r["label_status"] in ("provisional", "needs_review")


def test_committed_json_schema_matches_the_constants():
    assert json.loads(SCHEMA_FILE.read_text(encoding="utf-8")) == json.loads(
        json.dumps(S.json_schema(), sort_keys=True))
    sch = S.json_schema()
    assert set(sch["required"]) == set(S.REQUIRED_FIELDS)
    assert tuple(sch["properties"]["scenario"]["enum"]) == S.SCENARIOS
    assert tuple(sch["properties"]["labels"]["properties"]) == S.INTENT_LABELS


def test_there_are_exactly_four_intent_labels_and_a_separate_outcome():
    assert S.INTENT_LABELS == ("authority_claim_in_content", "payment_request",
                               "credential_request", "urgency_secrecy")
    assert set(S.OUTCOMES) == {"legitimate", "suspicious", "malicious", "ambiguous"}
    assert not set(S.INTENT_LABELS) & set(S.OUTCOMES)


# ------------------------------------------------------------------ structure

def test_clean_record_passes():
    rep = check([rec()])
    assert rep.ok and rep.warnings == []


def test_missing_unknown_and_wrongly_typed_fields():
    bad = rec()
    del bad["group_id"]
    bad["extra_field"] = 1
    bad["has_url"] = "no"
    c = codes(check([bad]))
    assert "missing_field" in c and "unknown_field" in c and "wrong_type" in c


@pytest.mark.parametrize("field,value", [
    ("language", "klingon"), ("channel", "sms"), ("scenario", "cats"), ("outcome", "bad"),
    ("label_status", "done"), ("split", "train"),
])
def test_enumerations_are_enforced(field, value):
    assert "invalid_value" in codes(check([rec(**{field: value})]))


def test_identifier_rules_and_duplicates():
    assert "bad_identifier" in codes(check([rec(rid="X")]))
    rep = check([rec("rec-001"), rec("rec-001", body="Totally different content for this one, "
                                                       "mentioning the quarterly budget review.")])
    assert "duplicate_id" in codes(rep)


def test_schema_version_is_checked():
    assert "bad_schema_version" in codes(check([rec(schema_version="0.9")]))


def test_text_limits_and_control_characters():
    assert "text_too_long" in codes(check([rec(subject="x" * (S.MAX_SUBJECT_CHARS + 1))]))
    assert "control_characters" in codes(check([rec(body="hello\x00world there my friend")]))


def test_empty_text_must_be_declared():
    assert "empty_text_not_declared" in codes(check([rec(subject="", body="")]))
    ok = check([rec(subject="", body="", scenario="short_or_empty", outcome="ambiguous")])
    assert ok.ok


def test_has_url_must_match_detection_both_ways():
    with_url = rec(body="Please sign in at http://login.portal.example/x to continue today.")
    assert "has_url_mismatch" in codes(check([with_url]))                 # says False
    ok = dict(with_url, has_url=True)
    assert check([ok]).ok
    assert "has_url_mismatch" in codes(check([rec(has_url=True)]))        # says True, no URL


def test_obfuscated_urls_count_as_urls():
    r = rec(body="Visit hxxp://login.portal.example/x today please and confirm everything.",
            has_url=True)
    assert check([r]).ok


# ------------------------------------------------------------------ labels and annotation

def test_null_labels_only_with_ambiguous_outcome_or_needs_review():
    r = rec()
    r["labels"]["payment_request"] = None
    assert "null_label_not_allowed" in codes(check([r]))
    r2 = dict(r, outcome="ambiguous")
    assert check([r2]).ok
    r3 = dict(r, label_status="needs_review")
    assert check([r3]).ok


def test_labels_must_be_booleans_with_exactly_the_four_keys():
    r = rec()
    r["labels"]["payment_request"] = "yes"
    assert "wrong_type" in codes(check([r]))
    r2 = rec()
    del r2["labels"]["urgency_secrecy"]
    assert "bad_label_keys" in codes(check([r2]))


def test_scenario_outcome_conflicts():
    assert "scenario_outcome_conflict" in codes(check([rec(scenario="transactional_legit",
                                                           outcome="malicious")]))
    assert "scenario_outcome_conflict" in codes(check([rec(scenario="credential_phish",
                                                           outcome="legitimate")]))


@pytest.mark.parametrize("over,expect", [
    (dict(label_status="reviewed"), True),                                        # single annotator
    (reviewed(annotation={"authored_by": "a", "annotators": ["a", "a"], "adjudicator": None}), True),
    (reviewed(), False),
    (reviewed(annotation={"authored_by": "a-1", "annotators": ["a-1", "b-2"],
                          "adjudicator": "c-3", "initial_disagreement": False}), True),
    (dict(label_status="adjudicated"), True),                                     # no adjudicator
    (dict(label_status="adjudicated",
          annotation={"authored_by": "a-1", "annotators": ["a-1", "b-2"], "adjudicator": "c-3",
                      "initial_disagreement": True}), False),
    (dict(annotation={"authored_by": "a-1", "annotators": ["a-1"], "adjudicator": "c-3"}), True),
])
def test_label_status_must_be_consistent_with_annotation(over, expect):
    codes_ = codes(check([rec(**over)]))
    assert ("status_annotation_conflict" in codes_ or "duplicate_annotator" in codes_) is expect


# ------------------------------------------------------------------ provenance

def test_non_synthetic_records_need_license_source_date_and_redaction_attestation():
    base = rec(provenance={"source_type": "public_dataset", "license": "CC-BY-4.0",
                           "generator": "dataset"})
    c = codes(check([base]))
    assert c.count("missing_field") == 2 and "redaction_not_attested" in c
    full = rec(provenance={"source_type": "public_dataset", "license": "CC-BY-4.0",
                           "generator": "dataset", "source_id": "dataset-x@v1",
                           "retrieved_on": "2026-10-01", "redaction_applied": True})
    assert check([full]).ok


def test_license_must_be_on_the_allow_list_and_match_the_source_type():
    r = rec(provenance={"source_type": "public_dataset", "license": "unknown", "generator": "dataset",
                        "source_id": "x", "retrieved_on": "2026-10-01", "redaction_applied": True})
    assert "invalid_value" in codes(check([r]))
    r2 = rec(provenance={"source_type": "synthetic", "license": "CC0-1.0", "generator": "human"})
    assert "provenance_conflict" in codes(check([r2]))
    r3 = rec(provenance={"source_type": "public_dataset", "license": "project-synthetic",
                         "generator": "dataset", "source_id": "x", "retrieved_on": "2026-10-01",
                         "redaction_applied": True})
    assert "provenance_conflict" in codes(check([r3]))


def test_llm_generated_text_should_name_the_model():
    r = rec(provenance={"source_type": "synthetic", "license": "project-synthetic", "generator": "llm"})
    assert "llm_generator_model_missing" in codes(check([r]))


# ------------------------------------------------------------------ evidence spans

def _with_spans(spans, **over):
    r = rec(body="Please wire 5,000 to the account below today.", **over)
    r["labels"]["payment_request"] = True
    r["evidence_spans"] = spans
    return r


def test_valid_span_passes_and_bad_spans_are_flagged():
    ok = _with_spans({"payment_request": [{"field": "body", "start": 7, "end": 12}]})
    assert check([ok]).ok
    for spans, code in [
        ({"payment_request": [{"field": "body", "start": 0, "end": 999}]}, "span_out_of_bounds"),
        ({"payment_request": [{"field": "body", "start": 5, "end": 5}]}, "span_out_of_bounds"),
        ({"payment_request": [{"field": "title", "start": 0, "end": 3}]}, "bad_span"),
        ({"credential_request": [{"field": "body", "start": 0, "end": 3}]}, "span_for_non_positive_label"),
        ({"unknown_label": [{"field": "body", "start": 0, "end": 3}]}, "invalid_value"),
    ]:
        assert code in codes(check([_with_spans(spans)])), spans


def test_independent_positives_need_spans_warning_or_error():
    r = _with_spans({}, **reviewed())
    del r["evidence_spans"]
    assert "missing_evidence_span" in codes(check([r]))
    assert check([r]).ok                                           # warning by default
    assert not check([r], require_spans=True).ok
    r_prov = _with_spans({})
    del r_prov["evidence_spans"]
    assert "missing_evidence_span" not in codes(check([r_prov]))   # provisional: not required


# ------------------------------------------------------------------ test-split strictness

def test_strict_test_requires_independent_labels():
    r = rec(split="test")
    assert check([r]).ok
    assert "test_label_not_independent" in codes(check([r], strict_test=True))
    assert check([rec(split="test", **reviewed())], strict_test=True).ok


# ------------------------------------------------------------------ secrets and personal data

def _flagged(text, **over):
    rep = check([rec(body=text, **over)])
    return [c for c in codes(rep) if c.startswith("sensitive:")]


def test_secret_and_personal_data_detectors():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    ghp = "ghp_" + "a" * 36
    key = "-----BEGIN " + "RSA PRIVATE KEY-----"
    jwt = "eyJ" + "abcdefghij" + "." + "eyJ" + "abcdefghij" + "." + "abcdefghijkl"
    cases = {
        "sensitive:aws_access_key": f"credentials {aws} here for the team please",
        "sensitive:github_token": f"use the token {ghp} when deploying today please",
        "sensitive:private_key_block": f"{key} lots of base64 text follows below now",
        "sensitive:jwt": f"session value {jwt} was captured in the logs yesterday",
        "sensitive:possible_card_number": "Card 4111 1111 1111 1111 expires next year, thank you.",
        "sensitive:us_ssn": "My number is 123-45-6789 please confirm receipt of this note.",
        "sensitive:aadhaar_like": "ID 1234 5678 9012 is on file for the account holder here.",
        "sensitive:possible_iban": "Pay to GB82WEST12345698765432 before the end of the month.",
        "sensitive:secret_assignment": "api_key = Zk3pQ9aLm2Zr7TbVn4Ws8YcD1xx stored here",
        "sensitive:email_address_not_reserved_domain": "Write to jane.doe@gmail.com for details.",
    }
    for code, text in cases.items():
        assert code in _flagged(text), code


def test_reserved_domains_and_non_luhn_numbers_are_not_flagged():
    ok = ("Write to jane@corp.example or ops@example.com. Reference 1234567890123456 and order "
          "20261013-4471 are internal.")
    assert not luhn_ok("1234567890123456")
    assert _flagged(ok) == []


def test_non_reserved_url_is_error_for_synthetic_and_warning_for_public_data():
    text = "Please open https://www.python.org/downloads/ to continue with the setup today."
    syn = check([rec(body=text, has_url=True)])
    assert "sensitive:url_host_not_reserved" in [i.code for i in syn.errors]
    pub = rec(body=text, has_url=True, provenance={
        "source_type": "public_dataset", "license": "CC0-1.0", "generator": "dataset",
        "source_id": "d@1", "retrieved_on": "2026-10-01", "redaction_applied": True})
    rep = check([pub])
    assert rep.ok and "sensitive:url_host_not_reserved" in [i.code for i in rep.warnings]


def test_reports_name_records_and_offsets_but_never_echo_message_text():
    leaky = rec("rec-leak", body=f"{SENTINEL} contact jane.doe@gmail.com about 123-45-6789 today.",
                subject=f"{SENTINEL} subject")
    rep = check([leaky])
    assert rep.errors
    rendered = "\n".join(i.render() for i in rep.issues)
    assert "rec-leak" in rendered and "characters" in rendered
    assert SENTINEL not in rendered and "jane.doe" not in rendered and "123-45" not in rendered
    assert SENTINEL not in json.dumps([i.__dict__ for i in rep.issues])


# ------------------------------------------------------------------ duplicates and near-duplicates

def test_exact_duplicates_after_normalisation_are_errors_even_across_groups():
    a = rec("rec-001", body="Please pay invoice 4471 of 1,250 by 5 November. Thanks, Acme billing team",
            group_id="grp-one")
    b = rec("rec-002", body="please PAY invoice 9982 of 7,777 by 9 November.  Thanks, Acme Billing TEAM",
            group_id="grp-two")
    assert normalise(a["body"]) == normalise(b["body"])
    rep = check([a, b])
    assert [i.record_id for i in rep.issues if i.code == "exact_duplicate"] == ["rec-001", "rec-002"]


def test_near_duplicate_across_splits_is_an_error():
    base = long_text("alpha")
    a = rec("rec-001", body=base, group_id="grp-one", split="dev")
    b = rec("rec-002", body=base + " plus one extra closing sentence", group_id="grp-two", split="test")
    assert "near_duplicate_across_splits" in codes(check([a, b]))


def test_near_duplicates_in_one_group_are_fine_and_in_different_groups_warn():
    base = long_text("beta")
    near = base + " plus one extra closing sentence"
    same = check([rec("rec-001", body=base, group_id="grp-one"),
                  rec("rec-002", body=near, group_id="grp-one")])
    assert same.issues == []
    diff = check([rec("rec-001", body=base, group_id="grp-one"),
                  rec("rec-002", body=near, group_id="grp-two")])
    assert "near_duplicate_different_group" in codes(diff) and diff.ok


def test_unrelated_texts_and_short_texts_are_not_flagged():
    rep = check([rec("rec-001", body=long_text("gamma"), group_id="grp-one"),
                 rec("rec-002", body=long_text("delta"), group_id="grp-two"),
                 rec("rec-003", subject="", body="ok", group_id="grp-three",
                     scenario="short_or_empty", outcome="ambiguous"),
                 rec("rec-004", subject="", body="thanks", group_id="grp-four",
                     scenario="short_or_empty", outcome="ambiguous")])
    assert rep.issues == []


def test_short_texts_only_match_when_identical():
    pairs = near_duplicate_pairs([("a", "", "wire the money now"), ("b", "", "wire the money now"),
                                  ("c", "", "wire the cash now")])
    assert pairs == [("a", "b", 1.0)]


def test_text_digest_ignores_case_digits_urls_and_spacing():
    assert text_digest("S", "Visit http://a.example/x 123") == text_digest("s", "visit  www.b.example/y 999")


# ------------------------------------------------------------------ groups, splits, coverage

def test_group_must_not_span_splits_and_partial_assignment_warns():
    spans = check([rec("rec-001", group_id="grp-one", split="dev",
                       body=long_text("eps")),
                   rec("rec-002", group_id="grp-one", split="test", body=long_text("zeta"))])
    assert "group_spans_splits" in codes(spans) and not spans.ok
    partial = check([rec("rec-001", group_id="grp-one", split="dev", body=long_text("eps")),
                     rec("rec-002", group_id="grp-one", split="unassigned", body=long_text("zeta"))])
    assert "group_partially_assigned" in codes(partial) and partial.ok


def test_coverage_counts_exclude_needs_review_and_other_languages():
    pos = rec("rec-001", body=long_text("p1"))
    pos["labels"]["payment_request"] = True
    nr = rec("rec-002", body=long_text("p2"), label_status="needs_review")
    nr["labels"]["payment_request"] = None
    hi = rec("rec-003", body=long_text("p3"), language="hi")
    cov = check([pos, nr, hi]).coverage
    assert cov["usable_primary_language"] == 1
    assert cov["labels"]["payment_request"] == {"pos": 1, "neg": 0}
    assert cov["by_language"] == {"en": 2, "hi": 1}


def _corpus_meeting_the_starter_floor(n=330):
    """Structurally valid synthetic corpus built only to exercise the coverage arithmetic."""
    legit = {"transactional_legit", "internal_business_legit", "executive_announcement_legit",
             "security_notice_legit", "urgent_ops_legit"}
    attack = {"credential_phish", "bec_executive_payment", "bec_giftcard", "bec_payroll_change",
              "malicious_link", "no_url_attack", "adversarial_instruction"}
    scenarios = [s for s in S.SCENARIOS if s != "other"]
    out = []
    for i in range(n):
        sc = scenarios[i % len(scenarios)]
        outcome = ("legitimate" if sc in legit else "malicious" if sc in attack
                   else "suspicious" if sc == "vendor_bank_change" else "ambiguous")
        r = rec(f"rec-{i:04d}", body=long_text(f"corpus{i}"), scenario=sc, outcome=outcome,
                split=("dev", "calibration", "test")[i % 3])
        r["labels"] = {k: ((i // (j + 1)) % 2 == 0) for j, k in enumerate(S.INTENT_LABELS)}
        out.append(r)
    return out


def test_coverage_profile_is_reported_met_only_when_the_floors_are_actually_met():
    recs = _corpus_meeting_the_starter_floor()
    rep = check(recs, profile="starter")
    assert rep.ok, [i.render() for i in rep.errors[:3]]
    assert rep.coverage_met is True and rep.coverage_failures == []

    # remove every test-split positive for one label: the profile must now fail on exactly that
    for r in recs:
        if r["split"] == "test":
            r["labels"]["credential_request"] = False
    rep2 = check(recs, profile="starter")
    assert rep2.coverage_met is False
    assert any("test credential_request" in f for f in rep2.coverage_failures)

    # and a corpus below the total floor fails on the total
    rep3 = check(_corpus_meeting_the_starter_floor()[:200], profile="starter")
    assert rep3.coverage_met is False
    assert any("total usable records" in f for f in rep3.coverage_failures)


# ------------------------------------------------------------------ file handling

def test_bad_lines_are_reported_with_line_numbers_and_do_not_stop_validation(tmp_path):
    p = tmp_path / "d.jsonl"
    p.write_text("{not json}\n" + json.dumps(rec("rec-001")) + "\n[1,2]\n\n"
                 + json.dumps(rec("rec-002", body=long_text("q"))) + "\n", encoding="utf-8")
    rep = validate_file(p)
    by = {(i.code, i.line) for i in rep.issues}
    assert ("json_parse_error", 1) in by and ("record_not_object", 3) in by
    assert rep.n_records == 2


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError):
        check([rec()], profile="enormous")


def test_secrets_scan_unit():
    assert luhn_ok("4111111111111111")
    assert scan_text("nothing to see here", synthetic=True) == []
