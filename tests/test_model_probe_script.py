"""The model probe script, driven with a fake loader. No weights, no network, no torch."""
import importlib.util
import io
import json
import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "model_probe.py"


@pytest.fixture(scope="module")
def probe():
    spec = importlib.util.spec_from_file_location("model_probe", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(probe, argv, env=None, loader=None):
    out = io.StringIO()
    code = probe.main(argv, env=env or {}, out=out, loader=loader)
    return code, out.getvalue()


def fake_loader(calls=None, logits=(0.2, 3.0, -1.0, -2.0)):
    def load():
        if calls is not None:
            calls.append("loaded")

        def predict(text):
            return {"logits": list(logits), "tokens": 5, "tokens_untruncated": 5, "truncated": False}
        return predict, {"repo_id": "fake", "revision": "r" * 40}
    return load


def test_importing_the_script_does_not_import_ml_libraries():
    src = SCRIPT.read_text(encoding="utf-8")
    for line in src.splitlines():
        assert not re.match(r"^(import|from)\s+(torch|transformers|huggingface_hub)\b", line)


def test_default_is_a_dry_run_that_never_loads_the_model(probe):
    calls = []
    code, text = run(probe, [], loader=fake_loader(calls))
    assert code == 0 and calls == []
    assert "DRY RUN" in text and probe.REVISION in text and "never 'main'" in text
    assert "model.safetensors" in text and "no pickle" in text


def test_run_requires_the_environment_gate(probe):
    calls = []
    code, text = run(probe, ["--run"], env={}, loader=fake_loader(calls))
    assert code == 3 and calls == [] and "MODEL_PROBE=1" in text


def test_env_alone_does_not_run(probe):
    calls = []
    code, _ = run(probe, [], env={"MODEL_PROBE": "1"}, loader=fake_loader(calls))
    assert code == 0 and calls == []


def test_run_prints_raw_vectors_both_mappings_and_no_accuracy_claim(probe, tmp_path):
    out_file = tmp_path / "r.json"
    code, text = run(probe, ["--run", "--out", str(out_file)], env={"MODEL_PROBE": "1"},
                     loader=fake_loader())
    assert code == 0
    assert "NOT an accuracy" in text and "not calibrated" in text
    assert "phishing_url_alt" in text and "phishing_email" in text      # both documented readings
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data["results"]) == len(probe.EXAMPLES)
    for r in data["results"]:
        assert len(r["scores"]) == 4 and abs(sum(r["scores"]) - 1.0) < 1e-9
        assert r["argmax"] == 1
    assert "accuracy" not in json.dumps(data["info"]).lower()
    assert "not an accuracy" in data["note"]


def test_load_refusals_and_failures_are_reported_not_raised(probe):
    def refuse():
        raise SystemExit("model is not cached and --allow-download was not given")

    code, text = run(probe, ["--run"], env={"MODEL_PROBE": "1"}, loader=refuse)
    assert code == 4 and "REFUSED" in text

    def broken():
        raise RuntimeError("corrupt weights at /secret/path")

    code, text = run(probe, ["--run"], env={"MODEL_PROBE": "1"}, loader=broken)
    assert code == 5 and "RuntimeError" in text and "/secret/path" not in text


def test_per_example_inference_error_is_recorded_not_fatal(probe):
    def load():
        def predict(text):
            raise ValueError("boom")
        return predict, {}
    code, text = run(probe, ["--run"], env={"MODEL_PROBE": "1"}, loader=load)
    assert code == 0 and text.count("ERROR ValueError") == len(probe.EXAMPLES)


def test_examples_cover_the_required_cases_and_are_synthetic(probe):
    ids = {e[0] for e in probe.EXAMPLES}
    groups = {e[1] for e in probe.EXAMPLES}
    assert {"legit_business", "phish_credential", "bec_no_url", "email_with_susp_url",
            "legit_urgent", "edge_empty", "edge_ok"} <= ids
    assert {"email", "edge", "url_only", "diagnostic"} <= groups
    assert len(ids) == len(probe.EXAMPLES)                    # unique ids
    assert next(e for e in probe.EXAMPLES if e[0] == "bec_no_url")[3].count("http") == 0


def test_pinned_revision_and_file_list_are_safe(probe):
    assert re.fullmatch(r"[0-9a-f]{40}", probe.REVISION)
    assert "model.safetensors" in probe.FILES
    assert not any(f.endswith((".bin", ".pt", ".pth", ".pkl", ".ckpt", ".py")) for f in probe.FILES)
    assert probe.REPO_ID == "cybersectony/phishing-email-detection-distilbert_v2.4.1"


def test_card_mappings_are_recorded_as_conflicting(probe):
    assert probe.MODEL_CARD_NAMES != probe.DATASET_CARD_NAMES
    assert probe.MODEL_CARD_NAMES[1] == "phishing_url"
    assert probe.DATASET_CARD_NAMES[1] == "phishing_email"


def test_softmax_is_stable_and_normalised(probe):
    p = probe.softmax([1000.0, 1000.0, -1000.0, 0.0])
    assert abs(sum(p) - 1.0) < 1e-9 and p[0] == pytest.approx(0.5)
