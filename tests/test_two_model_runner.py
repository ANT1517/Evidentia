"""DistilBERT adapter and the two-model runner, with fake models only (no weights, no network)."""
import importlib.util
import io
import re
import threading
import time
from pathlib import Path

import pytest

from engine import analyze
from engine.models import email as E
from engine.models.email import EmailClassifierAdapter, EmailModelStatus as ES, validate_probabilities
from engine.models.intent import IntentStatus as IS, LayaIntentAdapter
from engine.models.runner import TwoModelRunner
from engine.schemas import Channel, NormalizedMessage

ROOT = Path(__file__).resolve().parents[1]
SECRET = "ZXQ-PRIVATE-BODY-7731"


def laya_ok(**p):
    qs = ("authority_claim_in_content", "payment_request", "credential_request", "urgency_secrecy")
    return {"answers": {q: {"noul": p.get(q, 0.4)} for q in qs}}


def email_adapter(fn, **kw):
    return EmailClassifierAdapter(enabled=True, predict_fn=fn, **kw)


def laya_adapter(fn, **kw):
    return LayaIntentAdapter(enabled=True, predict_fn=fn, **kw)


GOOD4 = [0.1, 0.7, 0.1, 0.1]


# ------------------------------------------------------------------ DistilBERT adapter

def test_scores_winner_and_unresolved_mapping():
    r = email_adapter(lambda t: GOOD4).classify("hello team")
    assert r.ok and r.probabilities == tuple(GOOD4) and r.winning_index == 1
    assert r.label_mapping == "unresolved" and r.experimental is True
    assert r.revision == "6724dec17360ab1f6450553f1d950404f66a5dde"
    # no field names or labels a class as phishing/legitimate (the model id itself is fine)
    fields = {f for f in vars(r)}
    assert not any(w in f.lower() for f in fields for w in ("phish", "legit", "malicious"))
    assert not hasattr(r, "is_phishing") and not hasattr(r, "label")


@pytest.mark.parametrize("bad", [
    None, "x", 5, [], [0.5, 0.5], [0.2] * 5, [0.1, 0.1, 0.1, 0.1],           # wrong shape / not sum 1
    [float("nan"), 0.5, 0.25, 0.25], [1.5, -0.25, -0.25, 0.0], [True, 0, 0, 0], ["a", "b", "c", "d"],
])
def test_invalid_output_is_malformed_never_a_class(bad):
    r = email_adapter(lambda t: bad).classify("hello team")
    assert r.status is ES.MALFORMED_OUTPUT and r.probabilities is None and r.winning_index is None


def test_validate_probabilities_boundaries():
    assert validate_probabilities([1, 0, 0, 0]) == (1.0, 0.0, 0.0, 0.0)
    assert validate_probabilities([0.25] * 4) is not None
    assert validate_probabilities([0.3, 0.3, 0.3, 0.3]) is None


def test_empty_input_is_never_scored():
    calls = []
    a = email_adapter(lambda t: calls.append(t) or GOOD4)
    for t in ("", "  \n", None, 7):
        assert a.classify(t).status is ES.EMPTY_INPUT
    assert calls == []


def test_input_is_bounded_and_truncation_flagged():
    seen = []
    a = email_adapter(lambda t: seen.append(len(t)) or GOOD4, max_chars=40)
    r = a.classify("x" * 1000)
    assert seen == [40] and r.truncated is True
    assert email_adapter(lambda t: GOOD4).max_chars == E.DEFAULT_MAX_CHARS


def test_disabled_by_default_and_lazy():
    calls = []
    assert EmailClassifierAdapter(predict_fn=lambda t: calls.append(1) or GOOD4).classify("hi").status is ES.DISABLED
    assert calls == []
    loads = []
    orig = EmailClassifierAdapter._load_real_model
    EmailClassifierAdapter._load_real_model = lambda self: loads.append(1) or (lambda t: GOOD4)
    try:
        a = EmailClassifierAdapter(enabled=True)
        assert loads == []
        a.classify("hello there")
        a.classify("again")
        assert loads == [1]
    finally:
        EmailClassifierAdapter._load_real_model = orig


def test_missing_weights_hash_mismatch_and_sticky_failure(tmp_path):
    a = EmailClassifierAdapter(enabled=True, model_dir=str(tmp_path / "none"))
    r = a.classify("hello there")
    assert r.status is ES.UNAVAILABLE and r.detail == "weights_not_cached"
    d = tmp_path / "w"
    d.mkdir()
    (d / "model.safetensors").write_bytes(b"not the weights")
    r = EmailClassifierAdapter(enabled=True, model_dir=str(d)).classify("hello there")
    assert r.status is ES.UNAVAILABLE and r.detail == "weights_hash_mismatch"
    assert a.classify("again").detail == "weights_not_cached"


def test_inference_error_and_timeout_without_leaking_text(capsys):
    def boom(t):
        raise RuntimeError(f"bad {t}")

    r = email_adapter(boom).classify(SECRET)
    assert r.status is ES.INFERENCE_ERROR and r.detail == "RuntimeError" and SECRET not in repr(r)

    gate = threading.Event()
    a = email_adapter(lambda t: gate.wait(2) or GOOD4, timeout_s=0.05)
    assert a.classify("hello").status is ES.TIMEOUT
    assert a.classify("hello").detail == "previous_inference_still_running"
    gate.set()
    assert SECRET not in "".join(capsys.readouterr())


def test_adapter_source_has_no_network_or_remote_code():
    text = (ROOT / "engine" / "models" / "email.py").read_text(encoding="utf-8")
    assert "local_files_only=True" in text and "trust_remote_code=False" in text
    assert "use_safetensors=True" in text
    for token in ("urllib.request", "requests", "http.client", "socket", "subprocess"):
        assert token not in text
    assert not re.search(r"^(import torch|from transformers)", text, re.M)   # lazy imports only


# ------------------------------------------------------------------ runner

def runner(email_fn=lambda t: GOOD4, laya_fn=lambda t: laya_ok(), **_):
    return TwoModelRunner(email_adapter(email_fn), laya_adapter(laya_fn))


def test_both_models_succeed_independently():
    rep = runner().run("some synthetic text")
    assert rep.email.ok and rep.intent.ok
    assert rep.experimental is True and any("not a verdict" in n for n in rep.notes)
    assert rep.email.label_mapping == "unresolved" and rep.intent.calibrated is False
    assert rep.email_seconds >= 0 and rep.intent_seconds >= 0


def test_one_model_unavailable_does_not_affect_the_other():
    down = TwoModelRunner(EmailClassifierAdapter(enabled=True, model_dir="/definitely/missing"),
                          laya_adapter(lambda t: laya_ok(payment_request=0.9)))
    rep = down.run("synthetic text")
    assert rep.email.status is ES.UNAVAILABLE and rep.intent.ok
    assert rep.intent.probabilities["payment_request"] == 0.9

    down2 = TwoModelRunner(email_adapter(lambda t: GOOD4),
                           LayaIntentAdapter(enabled=True, model_dir="/definitely/missing"))
    rep2 = down2.run("synthetic text")
    assert rep2.email.ok and rep2.intent.status is IS.UNAVAILABLE


def test_both_disabled_by_default_and_both_fail_safely():
    rep = TwoModelRunner().run("synthetic text")
    assert rep.email.status is ES.DISABLED and rep.intent.status is IS.DISABLED

    def boom(t):
        raise ValueError("x")

    rep = runner(email_fn=boom, laya_fn=boom).run("synthetic text")
    assert rep.email.status is ES.INFERENCE_ERROR and rep.intent.status is IS.INFERENCE_ERROR


def test_empty_input_and_malformed_outputs_are_reported_per_model():
    rep = runner().run("   ")
    assert rep.email.status is ES.EMPTY_INPUT and rep.intent.status is IS.EMPTY_INPUT
    rep = runner(email_fn=lambda t: [0.9], laya_fn=lambda t: {"answers": {}}).run("hello there")
    assert rep.email.status is ES.MALFORMED_OUTPUT and rep.intent.status is IS.MALFORMED_OUTPUT
    assert rep.email.probabilities is None and rep.intent.probabilities is None


def test_runner_never_raises_even_if_an_adapter_does():
    class Bad:
        def classify(self, text):
            raise RuntimeError("adapter bug")

    rep = TwoModelRunner(Bad(), Bad()).run("hello")
    assert rep.email.status is ES.INFERENCE_ERROR and rep.intent.status is IS.INFERENCE_ERROR


# ------------------------------------------------------------------ verdict safety

def _msg(**kw):
    base = dict(external_id="m1", channel=Channel.EMAIL, sender="a@b.example", subject="Hi",
                body_text="please wire the money today " + SECRET)
    base.update(kw)
    return NormalizedMessage(**base)


def _core(a):
    return a.model_dump(exclude={"created_at", "evidence"}) | {
        "evidence": [(e.type, e.status, e.source) for e in a.evidence]}


def test_model_outputs_cannot_change_the_assessment_or_band():
    m = _msg()
    baseline = analyze(m)
    for email_fn, laya_fn in [
        (lambda t: [0.97, 0.01, 0.01, 0.01], lambda t: laya_ok(payment_request=1.0)),
        (lambda t: [0.0, 1.0, 0.0, 0.0], lambda t: laya_ok(authority_claim_in_content=1.0)),
        (lambda t: [0.9], lambda t: 1 / 0),
    ]:
        a, rep = runner(email_fn, laya_fn).assess(m)
        assert a.risk_band == baseline.risk_band
        assert _core(a) == _core(baseline)
        assert rep.experimental is True


def test_rules_only_path_is_intact_when_models_fail():
    a, rep = TwoModelRunner().assess(_msg())                  # both disabled
    assert a.risk_band == analyze(_msg()).risk_band
    assert rep.email.status is ES.DISABLED


def test_required_checks_stay_incomplete_so_full_profile_is_not_satisfied():
    from dataclasses import replace
    from engine import DEFAULT_CONFIG
    full = replace(DEFAULT_CONFIG, active_profile="full")
    a, rep = runner().assess(_msg(), config=full)
    assert rep.email.ok and rep.intent.ok                      # both models "ran"
    missing = {e.evidence_id for e in a.evidence if e.evidence_id.startswith("missing-")}
    assert {"missing-text_model", "missing-intent_questions"} <= missing
    assert a.risk_band.value == "insufficient_data"


def test_engine_core_does_not_import_the_models_package():
    for path in (ROOT / "engine").rglob("*.py"):
        if "models" in path.parts:
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.match(r"^\s*(from|import)\s", line):
                assert not re.search(r"\bmodels\b|\blaya\b", line), (path.name, line)


# ------------------------------------------------------------------ demo script

@pytest.fixture(scope="module")
def demo():
    spec = importlib.util.spec_from_file_location("two_model_demo", ROOT / "scripts" / "two_model_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_demo(demo, argv, env=None, rn=None):
    out = io.StringIO()
    return demo.main(argv, env=env or {}, out=out, runner=rn), out.getvalue()


def test_demo_default_is_a_dry_run_and_needs_both_gates(demo):
    class Boom:
        def run(self, text):
            raise AssertionError("must not run")

    code, text = run_demo(demo, [], rn=Boom())
    assert code == 0 and "DRY RUN" in text and "UNRESOLVED" in text
    assert run_demo(demo, ["--run"], env={}, rn=Boom())[0] == 3
    assert run_demo(demo, [], env={"TWO_MODEL_DEMO": "1"}, rn=Boom())[0] == 0


def test_demo_prints_statuses_not_text_and_marks_results_experimental(demo):
    code, text = run_demo(demo, ["--run"], env={"TWO_MODEL_DEMO": "1"}, rn=runner())
    assert code == 0 and "EXPERIMENTAL" in text and "mapping=unresolved" in text
    assert "ceo_wire_request" in text and "empty_message" in text
    for _, subject, body in demo.EXAMPLES:
        if body:
            assert body not in text and subject not in text
    assert text.count("distilbert:") == len(demo.EXAMPLES)
