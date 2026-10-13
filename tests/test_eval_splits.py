import copy
import hashlib
import importlib.util
import io
import json
import random
from collections import Counter
from pathlib import Path

import pytest

from evaluation import schema as S
from evaluation.dataset import DatasetInvalid, TestSplitLocked, for_tuning, load_records
from evaluation.splits import (
    SplitConflict, apply_manifest, balance_report, build_manifest, dump_manifest, merge_groups,
)
from evaluation.validate import validate_records
from eval_helpers import entries, jsonl, long_text, rec

ROOT = Path(__file__).resolve().parents[1]


def corpus(n_groups=30, per_group=2, scenario="internal_business_legit", prefix="g"):
    out = []
    for g in range(n_groups):
        for k in range(per_group):
            # members of a group share a template (near-duplicates); groups are unrelated
            body = long_text(f"{prefix}{g}") + (
                "" if k == 0 else " " + long_text(f"{prefix}{g}-ext{k}", 4))
            out.append(rec(f"{prefix}{g:03d}-{k}", body=body, group_id=f"grp-{prefix}{g:03d}",
                           scenario=scenario))
    return out


def splits_of(records, manifest):
    return {r["id"]: r["split"] for r in apply_manifest(records, manifest)}


# ------------------------------------------------------------------ determinism and integrity

def test_same_seed_gives_identical_manifest_and_different_seed_differs():
    recs = corpus()
    a = build_manifest(recs, seed=7)
    b = build_manifest(recs, seed=7)
    c = build_manifest(recs, seed=8)
    assert dump_manifest(a) == dump_manifest(b)
    assert a["assignments"] != c["assignments"]


def test_input_order_does_not_change_assignments():
    recs = corpus()
    shuffled = list(recs)
    random.Random(1).shuffle(shuffled)
    assert build_manifest(recs, seed=3)["assignments"] == build_manifest(shuffled, seed=3)["assignments"]


def test_every_record_of_a_group_lands_in_one_split_and_all_splits_are_used():
    recs = corpus(30, 3)
    m = build_manifest(recs, seed=11)
    assigned = apply_manifest(recs, m)
    by_group = {}
    for r in assigned:
        by_group.setdefault(r["group_id"], set()).add(r["split"])
    assert all(len(v) == 1 for v in by_group.values())
    assert {r["split"] for r in assigned} == {"dev", "calibration", "test"}
    assert validate_records(entries(assigned), manifest=m).ok


def test_fractions_are_approximately_respected_within_a_stratum():
    recs = corpus(60, 1)
    counts = Counter(r["split"] for r in apply_manifest(recs, build_manifest(recs, seed=5)))
    assert counts == {"dev": 24, "calibration": 18, "test": 18}


def test_scenarios_are_spread_across_splits():
    recs = corpus(12, 1, "credential_phish", "c") + corpus(12, 1, "transactional_legit", "t")
    for r in recs:
        r["outcome"] = "malicious" if r["scenario"] == "credential_phish" else "legitimate"
    assigned = apply_manifest(recs, build_manifest(recs, seed=5))
    for sc in ("credential_phish", "transactional_legit"):
        assert {r["split"] for r in assigned if r["scenario"] == sc} == {"dev", "calibration", "test"}


def _mixed(outcome_for):
    """Same texts, groups and scenarios every time; only outcome and labels vary."""
    scenarios = ("internal_business_legit", "credential_phish", "bec_giftcard")
    out = []
    for g in range(48):
        sc = scenarios[g % 3]
        r = rec(f"m{g:03d}-0", body=long_text(f"m{g}"), group_id=f"grp-m{g:03d}", scenario=sc,
                outcome="legitimate")   # placeholder, replaced below
        r["outcome"] = outcome_for(g)
        r["labels"]["payment_request"] = (g % 2 == 0)
        out.append(r)
    return out


def test_labels_and_outcomes_never_influence_assignment():
    # Outcome pattern A follows g % 2; pattern B follows (g // 3) % 2. Both avoid the
    # scenario/outcome validity rules and partition the groups differently, so any
    # label-keyed stratification would produce different assignments for A and B.
    a = _mixed(lambda g: ("suspicious", "ambiguous")[g % 2])
    b = _mixed(lambda g: ("suspicious", "ambiguous")[(g // 3) % 2])
    for r in b:
        r["labels"]["payment_request"] = not r["labels"]["payment_request"]
        r["label_status"] = "needs_review"
    assert [r["outcome"] for r in a] != [r["outcome"] for r in b]
    ma, mb = build_manifest(a, seed=9), build_manifest(b, seed=9)
    assert ma["assignments"] == mb["assignments"] and ma["merged_groups"] == mb["merged_groups"]
    assert ma["records_digest"] == mb["records_digest"]          # digest covers text and ids only


# ------------------------------------------------------------------ near-duplicate safeguard

def test_near_duplicates_in_different_groups_are_merged_before_assignment():
    base = long_text("shared")
    recs = [rec("rec-001", body=base, group_id="grp-aaa"),
            rec("rec-002", body=base + " one extra closing sentence", group_id="grp-bbb")]
    recs += corpus(20, 1, prefix="o")
    units = merge_groups(recs)
    assert units["grp-aaa"] == units["grp-bbb"] == "grp-aaa"
    m = build_manifest(recs, seed=2)
    sp = splits_of(recs, m)
    assert sp["rec-001"] == sp["rec-002"]
    assert m["merged_groups"] == {"grp-bbb": "grp-aaa"}


def test_without_merging_such_pairs_would_be_caught_by_the_validator():
    base = long_text("shared2")
    a = rec("rec-001", body=base, group_id="grp-aaa", split="dev")
    b = rec("rec-002", body=base + " one extra closing sentence", group_id="grp-bbb", split="test")
    rep = validate_records(entries([a, b]))
    assert "near_duplicate_across_splits" in [i.code for i in rep.errors]


# ------------------------------------------------------------------ frozen manifests

def test_frozen_manifest_keeps_existing_assignments_and_assigns_new_groups():
    first = corpus(24, 1)
    m1 = build_manifest(first, seed=4, freeze=True)
    assert m1["frozen"] is True
    more = first + corpus(10, 1, prefix="n")
    m2 = build_manifest(more, seed=4, previous=m1)
    for g, sp in m1["assignments"].items():
        assert m2["assignments"][g] == sp
    new_groups = set(m2["assignments"]) - set(m1["assignments"])
    assert len(new_groups) == 10 and m2["frozen"] is True


def test_frozen_manifest_cannot_be_reseeded():
    m1 = build_manifest(corpus(12, 1), seed=4, freeze=True)
    with pytest.raises(SplitConflict):
        build_manifest(corpus(12, 1), seed=5, previous=m1)


def test_new_record_that_bridges_two_assigned_splits_is_a_conflict():
    recs = corpus(30, 1)
    m1 = build_manifest(recs, seed=4, freeze=True)
    by_split = {}
    for r in apply_manifest(recs, m1):
        by_split.setdefault(r["split"], r)
    a, b = by_split["dev"], by_split["test"]
    # a new record in a's (dev) group whose text duplicates b's (test) message: it would force
    # the two already-assigned groups into one unit
    bridge = rec("bridge-1", body=b["body"], group_id=a["group_id"])
    with pytest.raises(SplitConflict):
        build_manifest(recs + [bridge], seed=4, previous=m1)


def test_validator_flags_edits_after_freezing_and_wrong_assignments():
    recs = corpus(12, 1)
    m = build_manifest(recs, seed=4, freeze=True)
    assigned = apply_manifest(recs, m)
    assert validate_records(entries(assigned), manifest=m).ok

    edited = copy.deepcopy(assigned)
    edited[0]["body"] = long_text("completely-different-text-now")
    codes = [i.code for i in validate_records(entries(edited), manifest=m).errors]
    assert "record_modified_since_manifest" in codes

    wrong = copy.deepcopy(assigned)
    wrong[0]["split"] = "test" if wrong[0]["split"] != "test" else "dev"
    codes = [i.code for i in validate_records(entries(wrong), manifest=m).errors]
    assert "split_disagrees_with_manifest" in codes

    outside = copy.deepcopy(assigned) + [rec("zzz-001", body=long_text("zzz"), group_id="grp-zzz",
                                             split="test")]
    assert "group_not_in_manifest" in [i.code for i in validate_records(entries(outside),
                                                                        manifest=m).errors]


# ------------------------------------------------------------------ inputs and reporting

def test_apply_manifest_changes_only_the_split_field():
    recs = corpus(6, 1)
    out = apply_manifest(recs, build_manifest(recs, seed=1))
    for before, after in zip(recs, out):
        diff = {k for k in before if before[k] != after[k]}
        assert diff <= {"split"}
    assert all(r["split"] == "unassigned" for r in recs)          # input untouched


@pytest.mark.parametrize("kw", [
    dict(seed=True), dict(seed="1"), dict(seed=1, fractions={"dev": 0.5, "test": 0.5}),
    dict(seed=1, fractions={"dev": 0.5, "calibration": 0.5, "test": 0.0}),
    dict(seed=1, fractions={"dev": 0.5, "calibration": 0.4, "test": 0.4}),
])
def test_bad_seed_or_fractions_are_rejected(kw):
    with pytest.raises(ValueError):
        build_manifest(corpus(3, 1), **kw)


def test_balance_report_counts():
    recs = corpus(30, 1)
    assigned = apply_manifest(recs, build_manifest(recs, seed=5))
    rep = balance_report(assigned)
    assert sum(v["records"] for v in rep.values()) == 30
    assert set(rep) == {"dev", "calibration", "test"}


def test_manifest_records_algorithm_seed_and_digests():
    recs = corpus(6, 1)
    m = build_manifest(recs, seed=42, freeze=True)
    assert m["algorithm"] == "group-stratified-hash-v1" and m["seed"] == 42
    assert set(m["record_digests"]) == {r["id"] for r in recs}
    assert m["records_digest"] and m["frozen"] is True
    assert json.loads(dump_manifest(m)) == m


# ------------------------------------------------------------------ test-split lock

def _write_split_file(tmp_path, reviewed_test=True):
    recs = corpus(30, 1)
    m = build_manifest(recs, seed=6)
    data = apply_manifest(recs, m)
    p = tmp_path / "c.jsonl"
    p.write_text(jsonl(data), encoding="utf-8")
    return p, data, m


def test_test_split_is_locked_by_default(tmp_path):
    p, data, m = _write_split_file(tmp_path)
    with pytest.raises(TestSplitLocked):
        load_records(p, split="test")
    default = load_records(p)
    assert default and all(r["split"] != "test" for r in default)
    assert {r["split"] for r in for_tuning(p)} <= {"dev", "calibration"}
    opened = load_records(p, split="test", unlock_test=True)
    assert opened and all(r["split"] == "test" for r in opened)
    assert len(load_records(p, unlock_test=True)) == len(data)


def test_loading_an_invalid_file_raises_instead_of_returning_partial_data(tmp_path):
    p = tmp_path / "bad.jsonl"
    bad = rec("rec-001")
    bad["labels"]["payment_request"] = "maybe"
    p.write_text(jsonl([bad]), encoding="utf-8")
    with pytest.raises(DatasetInvalid):
        load_records(p)


def test_unknown_split_name_is_rejected(tmp_path):
    p, _, _ = _write_split_file(tmp_path)
    with pytest.raises(ValueError):
        load_records(p, split="train")


# ------------------------------------------------------------------ command-line tools

def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_validate_cli_exit_codes_and_no_content_in_output(tmp_path):
    v = _load_script("validate_eval_dataset")
    good = tmp_path / "good.jsonl"
    good.write_text(jsonl(corpus(4, 1)), encoding="utf-8")
    out = io.StringIO()
    assert v.main([str(good)], out=out) == 0

    out = io.StringIO()
    assert v.main([str(good), "--profile", "starter"], out=out) == 2
    assert "NOT MET" in out.getvalue()

    leaky = rec("rec-leak", body="ZXQ-SENTINEL-7731 mail jane.doe@gmail.com today please thanks")
    bad = tmp_path / "bad.jsonl"
    bad.write_text(jsonl([leaky]), encoding="utf-8")
    out = io.StringIO()
    assert v.main([str(bad)], out=out) == 1
    assert "rec-leak" in out.getvalue() and "ZXQ-SENTINEL" not in out.getvalue()
    assert "jane.doe" not in out.getvalue()

    out = io.StringIO()
    assert v.main([str(tmp_path / "missing.jsonl")], out=out) == 3
    out = io.StringIO()
    assert v.main([str(bad), "--json"], out=out) == 1 and json.loads(out.getvalue())["errors"] >= 1


def test_make_splits_cli_writes_a_copy_never_edits_input_and_respects_freezing(tmp_path):
    m = _load_script("make_eval_splits")
    src = tmp_path / "src.jsonl"
    src.write_text(jsonl(corpus(24, 1)), encoding="utf-8")
    before = _sha(src)
    man, outd = tmp_path / "man.json", tmp_path / "out.jsonl"

    out = io.StringIO()
    assert m.main([str(src), "--seed", "13", "--out-manifest", str(man), "--out-data", str(outd),
                   "--freeze"], out=out) == 0
    assert _sha(src) == before                                    # input untouched
    manifest = json.loads(man.read_text(encoding="utf-8"))
    assert manifest["frozen"] is True and manifest["seed"] == 13
    rows = [json.loads(l) for l in outd.read_text(encoding="utf-8").splitlines()]
    assert {r["split"] for r in rows} == {"dev", "calibration", "test"}
    assert validate_records(entries(rows), manifest=manifest).ok

    # a frozen manifest is never overwritten, even with --force
    out = io.StringIO()
    assert m.main([str(src), "--seed", "13", "--out-manifest", str(man), "--force"], out=out) == 4
    assert "frozen" in out.getvalue()

    # extending with --previous writes a NEW manifest and keeps existing assignments
    more = tmp_path / "more.jsonl"
    more.write_text(jsonl(corpus(24, 1) + corpus(6, 1, prefix="n")), encoding="utf-8")
    man2 = tmp_path / "man2.json"
    assert m.main([str(more), "--seed", "13", "--previous", str(man), "--out-manifest", str(man2)],
                  out=io.StringIO()) == 0
    m2 = json.loads(man2.read_text(encoding="utf-8"))
    assert all(m2["assignments"][g] == sp for g, sp in manifest["assignments"].items())


def test_make_splits_cli_requires_a_seed_and_a_valid_input(tmp_path):
    m = _load_script("make_eval_splits")
    src = tmp_path / "src.jsonl"
    src.write_text(jsonl(corpus(4, 1)), encoding="utf-8")
    with pytest.raises(SystemExit):
        m.main([str(src), "--out-manifest", str(tmp_path / "m.json")], out=io.StringIO())
    bad = tmp_path / "bad.jsonl"
    r = rec("rec-001")
    del r["group_id"]
    bad.write_text(jsonl([r]), encoding="utf-8")
    out = io.StringIO()
    assert m.main([str(bad), "--seed", "1", "--out-manifest", str(tmp_path / "m2.json")], out=out) == 1
    assert not (tmp_path / "m2.json").exists()


# ------------------------------------------------------------------ isolation from production

def test_evaluation_package_is_independent_of_the_engine_and_the_network():
    forbidden = ("import engine", "from engine", "import torch", "import transformers",
                 "import socket", "import requests", "urllib.request", "import http.client",
                 "huggingface_hub", "subprocess")
    for path in (ROOT / "evaluation").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{path.name} contains {token!r}"


def test_production_engine_does_not_import_the_evaluation_package():
    for path in (ROOT / "engine").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "import evaluation" not in text and "from evaluation" not in text, path.name
