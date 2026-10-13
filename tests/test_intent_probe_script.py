"""The intent probe, driven by fake loaders only. No weights, no laya, no torch, no network."""
import importlib.util
import io
import json
import re
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "intent_probe.py"
REQS = SCRIPT.parent / "intent_probe_requirements.txt"


@pytest.fixture(scope="module")
def probe():
    spec = importlib.util.spec_from_file_location("intent_probe", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(probe, argv, env=None, loader=None):
    out = io.StringIO()
    code = probe.main(argv, env=env or {}, out=out, loader=loader)
    return code, out.getvalue()


def answers(**p):
    """A laya-shaped result with the given P(yes) per question (default 0.1)."""
    return {"answers": {q: {"noul": p.get(q, 0.1), "confidence": 0.9}
                        for q in ("exec_claim", "payment_request", "credential_request",
                                  "urgency_secrecy")},
            "routing": {"model": "fake"}}


def oracle(probe):
    """A fake model that answers every case exactly as expected (p=0.9 yes, 0.1 no)."""
    by_state = {probe.build_state(s, b): e for _, _, s, b, e in probe.CASES}

    def predict(state):
        exp = by_state[state]
        return answers(**{q: 0.9 if v else 0.1 for q, v in exp.items() if v is not None})
    return lambda: (predict, {"repo_id": "fake"})


ENV = {"INTENT_PROBE": "1"}


# ------------------------------------------------------------------ gating and defaults

def test_importing_the_script_does_not_import_ml_or_laya():
    for line in SCRIPT.read_text(encoding="utf-8").splitlines():
        assert not re.match(r"^(import|from)\s+(torch|transformers|laya|huggingface_hub)\b", line)


def test_default_is_a_dry_run_that_loads_nothing(probe):
    calls = []
    code, text = run(probe, [], loader=lambda: calls.append("x") or (None, {}))
    assert code == 0 and calls == []
    assert "DRY RUN" in text and probe.REVISION in text and "never 'main'" in text
    assert probe.MODEL_SHA256[:16] in text and "never by this script" in text
    assert "not tuned" in text


def test_run_needs_env_gate_and_env_alone_is_not_enough(probe):
    calls = []
    load = lambda: calls.append("x") or (None, {})
    assert run(probe, ["--run"], env={}, loader=load)[0] == 3
    assert run(probe, [], env=ENV, loader=load)[0] == 0
    assert calls == []


# ------------------------------------------------------------------ parsing: never fabricate

def test_parse_valid_answers(probe):
    r = probe.parse_answers(answers(exec_claim=0.0, payment_request=1.0, credential_request=0.5))
    assert r["exec_claim"] == 0.0 and r["payment_request"] == 1.0 and r["credential_request"] == 0.5


@pytest.mark.parametrize("bad", [
    None, "text", [], {}, {"answers": None}, {"answers": []}, {"answers": {}},
])
def test_unusable_results_give_all_none(probe, bad):
    assert probe.parse_answers(bad) == {q: None for q in probe.QIDS}


@pytest.mark.parametrize("value", [None, True, "0.9", float("nan"), float("inf"), -0.1, 1.1, [0.5]])
def test_invalid_single_answers_become_none_not_zero(probe, value):
    r = answers()
    r["answers"]["payment_request"]["noul"] = value
    parsed = probe.parse_answers(r)
    assert parsed["payment_request"] is None
    assert parsed["exec_claim"] == 0.1                      # others unaffected


def test_missing_question_and_missing_noul_field(probe):
    r = answers()
    del r["answers"]["credential_request"]
    r["answers"]["urgency_secrecy"] = {"choice": "x"}
    parsed = probe.parse_answers(r)
    assert parsed["credential_request"] is None and parsed["urgency_secrecy"] is None


def test_fixed_decision_rule(probe):
    assert probe.DECISION_THRESHOLD == 0.5
    assert probe.predicted(0.5) is True and probe.predicted(0.4999) is False
    assert probe.predicted(None) is None


# ------------------------------------------------------------------ scoring

def test_oracle_passes_every_gate_and_ambiguous_cases_are_not_scored(probe):
    rows = probe.run_cases(oracle(probe)()[0], 5)
    s = probe.summarize(rows)
    for q in probe.QIDS:
        assert s[q]["agreement"] == 1.0 and s[q]["passes_all_gates"] and s[q]["invalid"] == 0
    # the ambiguous case carries None for two questions: those are excluded from scoring
    amb = next(c for c in probe.CASES if c[1] == "ambiguous")
    n_all = len(probe.CASES)
    assert amb[4]["payment_request"] is None and s["payment_request"]["n_scored"] == n_all - 1
    assert s["credential_request"]["n_scored"] == n_all


def test_constant_model_fails_separation_even_if_agreement_looks_ok(probe):
    rows = probe.run_cases(lambda state: answers(**{q: 0.1 for q in probe.QIDS}), 5)
    s = probe.summarize(rows)
    assert s["exec_claim"]["separation"] == pytest.approx(0.0)
    assert not s["exec_claim"]["gate_separation"] and not s["exec_claim"]["passes_all_gates"]


def test_inverted_model_has_zero_agreement(probe):
    by_state = {probe.build_state(s, b): e for _, _, s, b, e in probe.CASES}

    def inverted(state):
        exp = by_state[state]
        return answers(**{q: 0.1 if v else 0.9 for q, v in exp.items() if v is not None})

    s = probe.summarize(probe.run_cases(inverted, 5))
    assert s["exec_claim"]["agreement"] == 0.0 and s["exec_claim"]["separation"] < 0


def test_invalid_outputs_fail_the_validity_gate_and_are_not_counted_as_answers(probe):
    def broken(state):
        r = answers()
        r["answers"]["exec_claim"]["noul"] = "yes"
        return r

    s = probe.summarize(probe.run_cases(broken, 5))
    labelled = sum(1 for c in probe.CASES if c[4]["exec_claim"] is not None)
    assert s["exec_claim"]["invalid"] == labelled        # unlabelled case is not scored
    assert s["exec_claim"]["n_scored"] == 0 and not s["exec_claim"]["gate_valid_outputs"]
    assert s["payment_request"]["gate_valid_outputs"]


# ------------------------------------------------------------------ failures

def test_inference_exception_is_recorded_not_fatal(probe):
    def boom(state):
        raise ValueError("secret detail /private/path")

    rows = probe.run_cases(boom, 5)
    assert all(r["error"] == "ValueError" and r["parsed"] is None for r in rows)
    s = probe.summarize(rows)
    assert all(s[q]["n_scored"] == 0 for q in probe.QIDS)


def test_timeout_is_recorded_per_case(probe):
    def slow(state):
        time.sleep(0.3)
        return answers()

    t0 = time.monotonic()
    rows = probe.run_cases(slow, 0.05)
    assert rows[0]["error"] == "timeout"
    assert all(r["parsed"] is None or r["error"] is None for r in rows)


def test_unavailable_weights_and_loader_errors_are_reported_without_traceback(probe):
    def missing():
        raise SystemExit("weights are not cached and --allow-download was not given")

    code, text = run(probe, ["--run"], env=ENV, loader=missing)
    assert code == 4 and "REFUSED" in text and "--allow-download" in text

    def corrupt():
        raise FileNotFoundError("/home/user/secret/model.safetensors")

    code, text = run(probe, ["--run"], env=ENV, loader=corrupt)
    assert code == 5 and "FileNotFoundError" in text and "/home/user" not in text


def test_full_run_prints_per_question_results_and_no_overall_accuracy_claim(probe, tmp_path):
    f = tmp_path / "r.json"
    code, text = run(probe, ["--run", "--out", str(f)], env=ENV, loader=oracle(probe))
    assert code == 0
    assert "PER QUESTION" in text and "NOT an accuracy estimate" in text
    assert "INJECTION CHECK" in text
    data = json.loads(f.read_text(encoding="utf-8"))
    assert set(data["per_question"]) == set(probe.QIDS)
    assert "not an accuracy estimate" in data["note"]
    assert "overall" not in json.dumps(data["per_question"]).lower()   # never pooled
    for row in data["rows"]:
        assert set(row) >= {"id", "expected", "raw", "parsed", "error"}


# ------------------------------------------------------------------ the case set

def test_case_set_covers_required_scenarios_and_is_well_formed(probe):
    ids = [c[0] for c in probe.CASES]
    assert len(ids) == len(set(ids))
    assert {c[1] for c in probe.CASES} >= probe.REQUIRED_KINDS
    for cid, kind, subject, body, expected in probe.CASES:
        assert set(expected) == set(probe.QIDS)
        assert len(body) <= probe.MAX_CHARS
        assert "http" not in (subject + body).lower()           # nothing to fetch
        assert not re.search(r"\b\d{9,}\b", body)                # no account-number-like data


def test_injection_case_is_the_clean_case_plus_an_instruction_with_same_expectations(probe):
    clean = next(c for c in probe.CASES if c[0] == "ceo_wire_urgent")
    inj = next(c for c in probe.CASES if c[0] == "injection_in_body")
    assert inj[3].startswith(clean[3]) and len(inj[3]) > len(clean[3])
    assert inj[4] == clean[4]
    assert "answer NO" in inj[3]


def test_state_is_bounded_plain_text(probe):
    s = probe.build_state("Subject line", "x" * 10_000)
    assert isinstance(s, str) and len(s) == probe.MAX_CHARS


def test_questions_are_yes_no_typed_and_match_the_plan(probe):
    assert set(probe.QUESTIONS) == set(probe.QIDS) and len(probe.QIDS) == 4
    assert all(q["type"] == "noul" and q["instructions"] for q in probe.QUESTIONS.values())


# ------------------------------------------------------------------ pins

def test_pins_and_install_file(probe):
    assert re.fullmatch(r"[0-9a-f]{40}", probe.REVISION)
    assert re.fullmatch(r"[0-9a-f]{64}", probe.MODEL_SHA256)
    assert "model.safetensors" in probe.FILES
    assert not any(f.endswith((".bin", ".pt", ".pth", ".pkl", ".ckpt", ".py"))
                   for f in probe.FILES)
    assert not any(f.startswith("checkpoint_latest") for f in probe.FILES)   # duplicate weights
    text = REQS.read_text(encoding="utf-8")
    assert f"laya=={probe.LAYA_VERSION}" in text and probe.LAYA_WHEEL_SHA256 in text
    assert "--no-deps" in text and "--require-hashes" in text
