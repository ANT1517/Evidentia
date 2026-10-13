"""The live smoke script, exercised ONLY with a fake transport. Nothing here goes live."""
import importlib.util
import io
import json
from pathlib import Path

import pytest

from ti_helpers import KEY, FakeTransport, jr, route, uh_clean, rdap

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ti_smoke.py"
EXAMPLE = SCRIPT.parent / "smoke_indicators.example.json"


@pytest.fixture(scope="module")
def smoke():
    spec = importlib.util.spec_from_file_location("ti_smoke", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(smoke, argv, env=None, transport=None):
    out = io.StringIO()
    code = smoke.main(argv, env=env or {}, transport=transport, out=out)
    return code, out.getvalue()


def write_indicators(tmp_path, **doc):
    p = tmp_path / "ind.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


ENV_LIVE = {"TI_LIVE_SMOKE": "1", "URLHAUS_AUTH_KEY": KEY, "VIRUSTOTAL_API_KEY": KEY,
            "PHISHTANK_APP_KEY": KEY}


def test_example_indicator_file_is_safe_and_public_only(smoke):
    code, text = run(smoke, ["--indicators", str(EXAMPLE), "--providers", "domain_age,urlhaus"])
    assert code == 0 and "DRY RUN" in text
    doc = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert doc["domains"] == ["example.com"] and doc["urls"] == []
    assert doc["sha256"] == ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]


def test_default_is_a_dry_run_with_no_network_and_no_secrets(smoke):
    tr = FakeTransport()
    code, text = run(smoke, ["--indicators", str(EXAMPLE), "--providers", "urlhaus,domain_age"],
                     env=ENV_LIVE, transport=tr)
    assert code == 0 and tr.calls == []
    assert "DRY RUN" in text and "total requests:" in text
    assert KEY not in text
    assert "URLHAUS_AUTH_KEY: set" in text           # presence only


def test_confirm_flag_alone_is_refused(smoke):
    tr = FakeTransport()
    code, text = run(smoke, ["--indicators", str(EXAMPLE), "--providers", "urlhaus",
                             "--confirm-live"], env={"URLHAUS_AUTH_KEY": KEY}, transport=tr)
    assert code == 3 and tr.calls == [] and "TI_LIVE_SMOKE=1" in text


def test_env_var_alone_does_not_go_live(smoke):
    tr = FakeTransport()
    code, text = run(smoke, ["--indicators", str(EXAMPLE), "--providers", "urlhaus"],
                     env=ENV_LIVE, transport=tr)
    assert code == 0 and tr.calls == [] and "DRY RUN" in text


def test_providers_must_be_named_explicitly(smoke):
    code, _ = run(smoke, ["--indicators", str(EXAMPLE), "--providers", ""])
    assert code == 1
    code, text = run(smoke, ["--indicators", str(EXAMPLE), "--providers", "shodan"])
    assert code == 1 and "subset" in text


def test_live_run_sends_only_listed_indicators_to_selected_providers(smoke, tmp_path):
    f = write_indicators(tmp_path, domains=["example.com"], urls=["http://example.com/test"],
                         sha256=["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"])
    tr = FakeTransport(route(uh=uh_clean, rd=jr(rdap("1995-08-14T04:00:00Z"))))
    code, text = run(smoke, ["--indicators", f, "--providers", "urlhaus,domain_age",
                             "--confirm-live", "--show-shapes"], env=ENV_LIVE, transport=tr)
    assert code == 0
    assert tr.hosts() == {"urlhaus-api.abuse.ch", "rdap.verisign.com"}
    assert not any("virustotal" in c.url or "phishtank" in c.url for c in tr.calls)
    assert "[not_found" in text and "NOT_FOUND means" in text
    assert KEY not in text and KEY not in "".join(c.url for c in tr.calls)
    assert "RESPONSE SHAPES" in text


def test_virustotal_is_only_contacted_when_explicitly_selected(smoke, tmp_path):
    f = write_indicators(tmp_path, domains=["example.com"])
    tr = FakeTransport()
    run(smoke, ["--indicators", f, "--providers", "domain_age", "--confirm-live"],
        env=ENV_LIVE, transport=tr)
    assert not any("virustotal" in c.url for c in tr.calls)
    tr2 = FakeTransport()
    run(smoke, ["--indicators", f, "--providers", "virustotal", "--confirm-live"],
        env=ENV_LIVE, transport=tr2)
    assert tr2.hosts() == {"www.virustotal.com"}


@pytest.mark.parametrize("doc", [
    {"urls": ["http://example.com/a?token=SECRET"]},
    {"urls": ["http://user:pw@example.com/a"]},
    {"urls": ["http://example.com/reset/3f2a9c1e-7b4d-4e2a-9c1e-0a1b2c3d4e5f"]},
    {"urls": ["HTTP://Example.com/a"]},
    {"domains": ["sub.example.com"]},
    {"sha256": ["ABC"]},
])
def test_unsafe_indicator_files_are_refused_before_anything_is_sent(smoke, tmp_path, doc):
    tr = FakeTransport()
    code, text = run(smoke, ["--indicators", write_indicators(tmp_path, **doc),
                             "--providers", "urlhaus", "--confirm-live"],
                     env=ENV_LIVE, transport=tr)
    assert code == 1 and tr.calls == [] and "REFUSED" in text
    assert "SECRET" not in text and "pw@" not in text


def test_missing_or_corrupt_indicator_file(smoke, tmp_path):
    assert run(smoke, ["--indicators", str(tmp_path / "nope.json"), "--providers", "urlhaus"])[0] == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert run(smoke, ["--indicators", str(bad), "--providers", "urlhaus"])[0] == 1


def test_shapes_show_types_never_values(smoke, tmp_path):
    f = write_indicators(tmp_path, domains=["example.com"])
    body = {"query_status": "mystery_value_XYZ", "secret_field": "TOP-SECRET-VALUE", "n": 7}
    tr = FakeTransport(route(uh=jr(body)))
    code, text = run(smoke, ["--indicators", f, "--providers", "urlhaus", "--confirm-live",
                             "--show-shapes"], env=ENV_LIVE, transport=tr)
    assert code == 2 and "COMPATIBILITY PROBLEM" in text
    assert "secret_field" in text and "str" in text                  # key names and types
    assert "TOP-SECRET-VALUE" not in text and "mystery_value_XYZ" not in text


def test_script_refuses_to_build_a_real_transport_under_pytest(smoke, tmp_path):
    f = write_indicators(tmp_path, domains=["example.com"])
    code, text = run(smoke, ["--indicators", f, "--providers", "domain_age", "--confirm-live"],
                     env=ENV_LIVE, transport=None)
    assert code == 4 and "pytest" in text


def test_script_is_not_collected_or_imported_by_the_suite():
    assert not SCRIPT.name.startswith("test_")
    assert SCRIPT.parent.name == "scripts"
