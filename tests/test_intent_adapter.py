"""The optional Laya intent adapter, with a fake model only: no weights, no laya, no network."""
import re
import threading
import time
from pathlib import Path

import pytest

from engine import analyze
from engine.models import intent as I
from engine.models.intent import (
    IntentResult, IntentStatus as St, LayaIntentAdapter, parse_answers,
)
from engine.schemas import Channel, NormalizedMessage

ROOT = Path(__file__).resolve().parents[1]
SECRET_TEXT = "ZXQ-PRIVATE-BODY-7731 please wire the money"


def good(**p):
    return {"answers": {q: {"type": "noul", "noul": p.get(q, 0.3), "confidence": 0.7}
                        for q in I.QUESTION_IDS}}


def adapter(fn, **kw):
    return LayaIntentAdapter(enabled=True, predict_fn=fn, **kw)


# ------------------------------------------------------------------ mapping and validation

def test_ok_result_maps_each_question_to_its_own_probability():
    r = adapter(lambda t: good(authority_claim_in_content=0.9, payment_request=0.1,
                               credential_request=0.5, urgency_secrecy=0.0)).classify(SECRET_TEXT)
    assert r.ok and r.status is St.OK
    assert r.probabilities == {"authority_claim_in_content": 0.9, "payment_request": 0.1,
                               "credential_request": 0.5, "urgency_secrecy": 0.0}
    assert r.calibrated is False
    assert (r.model_id, r.revision) == (I.MODEL_ID, I.MODEL_REVISION)


def test_questions_are_the_four_labels_in_yes_no_form():
    assert I.QUESTION_IDS == ("authority_claim_in_content", "payment_request",
                              "credential_request", "urgency_secrecy")
    assert set(I.QUESTIONS) == set(I.QUESTION_IDS)
    assert all(q["type"] == "noul" and q["instructions"] for q in I.QUESTIONS.values())


@pytest.mark.parametrize("bad", [
    None, "x", [], {}, {"answers": None}, {"answers": []}, {"answers": {}},
])
def test_unusable_results_are_malformed_not_negative(bad):
    r = adapter(lambda t: bad).classify("hello there")
    assert r.status is St.MALFORMED_OUTPUT and r.probabilities is None


@pytest.mark.parametrize("value", [None, True, "0.9", float("nan"), float("inf"), -0.01, 1.01])
def test_one_invalid_answer_invalidates_the_whole_output(value):
    out = good()
    out["answers"]["credential_request"]["noul"] = value
    r = adapter(lambda t: out).classify("hello there")
    assert r.status is St.MALFORMED_OUTPUT and r.probabilities is None     # no partial results


def test_missing_question_is_malformed():
    out = good()
    del out["answers"]["urgency_secrecy"]
    assert adapter(lambda t: out).classify("hello").status is St.MALFORMED_OUTPUT


def test_parse_answers_accepts_boundary_values():
    out = good(payment_request=0.0, credential_request=1.0)
    assert parse_answers(out)["payment_request"] == 0.0
    assert parse_answers(out)["credential_request"] == 1.0


# ------------------------------------------------------------------ inputs

def test_empty_and_whitespace_input_is_not_scored():
    calls = []
    a = adapter(lambda t: calls.append(t) or good())
    for t in ("", "   \n\t ", None, 123):
        r = a.classify(t)
        assert r.status is St.EMPTY_INPUT and r.probabilities is None
    assert calls == []                                    # the model was never invoked


def test_text_is_truncated_to_the_configured_bound_and_flagged():
    seen = []
    a = adapter(lambda t: seen.append(t) or good(), max_chars=50)
    r = a.classify("a" * 500)
    assert len(seen[0]) == 50 and r.truncated is True and r.ok
    r2 = a.classify("short text")
    assert r2.truncated is False and seen[1] == "short text"


def test_default_bound_is_applied():
    seen = []
    adapter(lambda t: seen.append(len(t)) or good()).classify("b" * 10_000)
    assert seen == [I.DEFAULT_MAX_CHARS]


# ------------------------------------------------------------------ failures

def test_disabled_adapter_runs_nothing():
    calls = []
    a = LayaIntentAdapter(predict_fn=lambda t: calls.append(t) or good())     # enabled defaults False
    r = a.classify("wire the money")
    assert r.status is St.DISABLED and r.probabilities is None and calls == []


def test_inference_exception_is_contained_and_reports_only_the_type():
    def boom(t):
        raise ValueError(f"cannot process {t}")           # message text inside the exception

    r = adapter(boom).classify(SECRET_TEXT)
    assert r.status is St.INFERENCE_ERROR and r.detail == "ValueError"
    assert "ZXQ-PRIVATE" not in repr(r) and "ZXQ-PRIVATE" not in r.detail


def test_timeout_is_reported_and_a_busy_model_is_not_stacked():
    gate = threading.Event()

    def slow(t):
        gate.wait(2)
        return good()

    a = adapter(slow, timeout_s=0.05)
    r = a.classify("hello there")
    assert r.status is St.TIMEOUT and r.probabilities is None
    r2 = a.classify("hello again")                        # previous call still running
    assert r2.status is St.INFERENCE_ERROR and r2.detail == "previous_inference_still_running"
    gate.set()
    time.sleep(0.2)
    assert a.classify("third try").ok                      # recovers once the model is free


def test_missing_weights_and_missing_library_are_unavailable_not_negative(tmp_path, monkeypatch):
    a = LayaIntentAdapter(enabled=True, model_dir=str(tmp_path / "nope"))
    r = a.classify("hello there")
    assert r.status is St.UNAVAILABLE and r.detail == "weights_not_cached"

    d = tmp_path / "w"
    d.mkdir()
    (d / "model.safetensors").write_bytes(b"not the real weights")
    r = LayaIntentAdapter(enabled=True, model_dir=str(d)).classify("hello there")
    assert r.status is St.UNAVAILABLE and r.detail == "weights_hash_mismatch"

    monkeypatch.setattr(I, "_sha256", lambda p: I.WEIGHTS_SHA256)       # pass the hash step
    monkeypatch.setitem(__import__("sys").modules, "laya", None)        # make `import laya` fail
    r = LayaIntentAdapter(enabled=True, model_dir=str(d)).classify("hello there")
    assert r.status is St.UNAVAILABLE and r.detail == "laya_not_installed"


def test_load_failure_is_cached_and_not_retried(tmp_path):
    a = LayaIntentAdapter(enabled=True, model_dir=str(tmp_path / "nope"))
    a.classify("x y")
    first = a._load_error
    a._model_dir = str(tmp_path)          # even if the path later changes, the failure is sticky
    assert a.classify("x y").detail == first


def test_loading_is_lazy_construction_never_loads():
    called = []
    orig = LayaIntentAdapter._load_real_model
    LayaIntentAdapter._load_real_model = lambda self: called.append(1) or (lambda t: good())
    try:
        a = LayaIntentAdapter(enabled=True)
        assert called == []                                # constructing loads nothing
        assert a.classify("hello").ok and called == [1]
        a.classify("hello again")
        assert called == [1]                               # loaded once, reused
    finally:
        LayaIntentAdapter._load_real_model = orig


def test_invalid_configuration_is_rejected():
    for kw in (dict(max_chars=0), dict(timeout_s=0), dict(timeout_s=-1)):
        with pytest.raises(ValueError):
            LayaIntentAdapter(**kw)


# ------------------------------------------------------------------ no leakage of content

def test_text_never_appears_in_results_or_output(capsys, caplog):
    r1 = adapter(lambda t: good()).classify(SECRET_TEXT)
    r2 = adapter(lambda t: {"answers": 1}).classify(SECRET_TEXT)
    for r in (r1, r2, adapter(lambda t: 1 / 0).classify(SECRET_TEXT)):
        assert "ZXQ-PRIVATE" not in repr(r) and "ZXQ-PRIVATE" not in str(r.detail)
    out = capsys.readouterr()
    assert "ZXQ-PRIVATE" not in out.out + out.err + caplog.text


# ------------------------------------------------------------------ isolation from the engine

def test_the_verdict_pipeline_does_not_import_the_adapter():
    for path in (ROOT / "engine").rglob("*.py"):
        if "models" in path.parts:
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.match(r"^\s*(from|import)\s", line):
                assert not re.search(r"\bmodels\b|\blaya\b", line), (path.name, line)


def test_adapter_cannot_change_an_assessment():
    msg = NormalizedMessage(external_id="m1", channel=Channel.EMAIL, sender="a@b.example",
                            body_text=SECRET_TEXT)
    before = analyze(msg).model_dump(exclude={"created_at", "evidence"})
    adapter(lambda t: good(payment_request=1.0, authority_claim_in_content=1.0)).classify(
        msg.body_text)
    after = analyze(msg).model_dump(exclude={"created_at", "evidence"})
    assert before == after


def test_module_makes_no_network_or_download_calls():
    text = (ROOT / "engine" / "models" / "intent.py").read_text(encoding="utf-8")
    for token in ("urllib.request", "requests", "http.client", "socket", "snapshot_download(",
                  "from_pretrained", "subprocess"):
        if token == "snapshot_download(":
            assert "local_files_only=True" in text            # the only fetch helper is offline
        else:
            assert token not in text, token
    assert re.search(r"^import laya", text, re.M) is None     # imported lazily, inside a function


def test_result_is_immutable():
    r = IntentResult(St.OK, probabilities={"payment_request": 0.5})
    with pytest.raises(Exception):
        r.status = St.DISABLED          # frozen dataclass
