"""Offline validator for the labelled evaluation corpus.

Nothing here reads the network, loads a model, or rewrites data. Issues name the record id,
field and a fixed rule code, plus character offsets for secret hits. Message text is never
echoed into a report.
"""
from __future__ import annotations

import json
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import schema as S
from .secrets_scan import scan_text
from .similarity import DEFAULT_THRESHOLD, near_duplicate_pairs, text_digest

_ID = re.compile(S.ID_PATTERN)
_GROUP = re.compile(S.GROUP_PATTERN)
_ANNOTATOR = re.compile(S.ANNOTATOR_PATTERN)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_URL = re.compile(r"(?i)(?:https?://|hxxps?://|www\.)\S+")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ATTACK_SCENARIOS = {"credential_phish", "bec_executive_payment", "bec_giftcard",
                    "bec_payroll_change", "malicious_link", "no_url_attack"}


@dataclass(frozen=True)
class Issue:
    severity: str            # "error" | "warning"
    code: str
    record_id: str           # "" for file-level issues
    field: str
    detail: str              # fixed vocabulary, never message content
    line: Optional[int] = None

    def render(self) -> str:
        where = f"line {self.line} " if self.line else ""
        rid = f"[{self.record_id}] " if self.record_id else ""
        fld = f"{self.field}: " if self.field else ""
        return f"{self.severity.upper():7} {self.code:<34} {where}{rid}{fld}{self.detail}".rstrip()


@dataclass(frozen=True)
class CoverageProfile:
    name: str
    min_total: int
    min_pos_per_label: int
    min_neg_per_label: int
    min_per_outcome: dict
    min_per_scenario: int
    test_min_total: int
    test_min_pos_per_label: int


PROFILES = {
    # Starter targets for a first evaluation corpus. They are floors for the experiment to be
    # worth running at all, NOT a guarantee of statistical reliability (see the spec).
    "starter": CoverageProfile(
        name="starter", min_total=300, min_pos_per_label=40, min_neg_per_label=40,
        min_per_outcome={"legitimate": 60, "suspicious": 20, "malicious": 60, "ambiguous": 10},
        min_per_scenario=5, test_min_total=100, test_min_pos_per_label=15,
    ),
}


@dataclass
class Report:
    issues: list = field(default_factory=list)
    n_records: int = 0
    coverage: dict = field(default_factory=dict)
    profile: Optional[str] = None
    coverage_failures: list = field(default_factory=list)

    @property
    def errors(self) -> list:
        return [i for i in self.issues if i.severity == "error"]

    @property
    def warnings(self) -> list:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def coverage_met(self) -> Optional[bool]:
        return None if self.profile is None else not self.coverage_failures


# ---------------------------------------------------------------------------------------------

def load_jsonl(path: Path):
    """-> list of (line_no, obj_or_None, error_or_None). Never raises on bad lines."""
    out = []
    with open(path, encoding="utf-8", errors="strict") as f:
        for n, raw in enumerate(f, 1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except ValueError:
                out.append((n, None, "json_parse_error"))
                continue
            out.append((n, obj, None if isinstance(obj, dict) else "record_not_object"))
    return out


def detect_url(subject: str, body: str) -> bool:
    return bool(_URL.search(f"{subject}\n{body}"))


def _is_str(v) -> bool:
    return isinstance(v, str)


class _Collector:
    def __init__(self, record_id: str, line: Optional[int], sink: list) -> None:
        self.rid, self.line, self.sink = record_id, line, sink

    def error(self, code: str, field_: str = "", detail: str = "") -> None:
        self.sink.append(Issue("error", code, self.rid, field_, detail, self.line))

    def warn(self, code: str, field_: str = "", detail: str = "") -> None:
        self.sink.append(Issue("warning", code, self.rid, field_, detail, self.line))


def _check_record(rec: dict, c: _Collector, *, strict_test: bool, require_spans: bool) -> None:
    for f in S.REQUIRED_FIELDS:
        if f not in rec:
            c.error("missing_field", f)
    for f in rec:
        if f not in S.ALL_FIELDS:
            c.error("unknown_field", str(f)[:40])

    if rec.get("schema_version") != S.SCHEMA_VERSION:
        c.error("bad_schema_version", "schema_version", f"expected {S.SCHEMA_VERSION}")

    subject, body = rec.get("subject"), rec.get("body")
    for name, val, limit in (("subject", subject, S.MAX_SUBJECT_CHARS),
                             ("body", body, S.MAX_BODY_CHARS)):
        if val is None:
            continue
        if not _is_str(val):
            c.error("wrong_type", name, "must be a string")
            continue
        if len(val) > limit:
            c.error("text_too_long", name, f"over {limit} characters")
        if _CONTROL.search(val):
            c.error("control_characters", name)
        if unicodedata.normalize("NFC", val) != val:
            c.warn("not_nfc_normalised", name)
    scenario = rec.get("scenario")
    if _is_str(subject) and _is_str(body):
        if not (subject.strip() or body.strip()) and scenario != "short_or_empty":
            c.error("empty_text_not_declared", "body", "empty text requires scenario short_or_empty")
        if scenario == "short_or_empty" and len((subject + body).strip()) > 200:
            c.warn("short_scenario_but_long", "body")
        has_url = rec.get("has_url")
        if isinstance(has_url, bool) and has_url != detect_url(subject, body):
            c.error("has_url_mismatch", "has_url", "does not match URL detection in the text")
        elif has_url is not None and not isinstance(has_url, bool):
            c.error("wrong_type", "has_url", "must be a boolean")

    for name, allowed in (("language", S.LANGUAGES), ("channel", S.CHANNELS),
                          ("scenario", S.SCENARIOS), ("outcome", S.OUTCOMES),
                          ("label_status", S.LABEL_STATUSES), ("split", S.SPLITS)):
        if name in rec and rec[name] not in allowed:
            c.error("invalid_value", name, "not in the permitted set")

    for name, rx in (("id", _ID), ("group_id", _GROUP)):
        v = rec.get(name)
        if name in rec and not (_is_str(v) and rx.match(v)):
            c.error("bad_identifier", name, "does not match the identifier pattern")

    # ---- labels --------------------------------------------------------------------------
    labels = rec.get("labels")
    outcome, status = rec.get("outcome"), rec.get("label_status")
    if "labels" in rec:
        if not isinstance(labels, dict):
            c.error("wrong_type", "labels", "must be an object")
        else:
            if set(labels) != set(S.INTENT_LABELS):
                c.error("bad_label_keys", "labels", "must contain exactly the four intent labels")
            for k in S.INTENT_LABELS:
                v = labels.get(k, "absent")
                if v is None:
                    if outcome != "ambiguous" and status != "needs_review":
                        c.error("null_label_not_allowed", f"labels.{k}",
                                "null requires outcome ambiguous or status needs_review")
                elif not isinstance(v, bool):
                    c.error("wrong_type", f"labels.{k}", "must be true, false or null")
    if outcome == "legitimate" and isinstance(labels, dict) and labels.get("credential_request") is True:
        c.warn("legitimate_with_credential_request", "labels.credential_request")
    if isinstance(scenario, str):
        if scenario.endswith("_legit") and outcome not in ("legitimate", "ambiguous"):
            c.error("scenario_outcome_conflict", "outcome", "legit scenario needs outcome legitimate")
        if scenario in ATTACK_SCENARIOS and outcome == "legitimate":
            c.error("scenario_outcome_conflict", "outcome", "attack scenario cannot be legitimate")

    # ---- annotation ----------------------------------------------------------------------
    ann = rec.get("annotation")
    if "annotation" in rec:
        if not isinstance(ann, dict):
            c.error("wrong_type", "annotation", "must be an object")
        else:
            author, anns, adj = ann.get("authored_by"), ann.get("annotators"), ann.get("adjudicator")
            if not (_is_str(author) and _ANNOTATOR.match(author)):
                c.error("bad_annotator", "annotation.authored_by")
            ok_list = (isinstance(anns, list) and anns
                       and all(_is_str(a) and _ANNOTATOR.match(a) for a in anns))
            if not ok_list:
                c.error("bad_annotator", "annotation.annotators", "needs a non-empty list of ids")
            elif len(set(anns)) != len(anns):
                c.error("duplicate_annotator", "annotation.annotators")
            if adj is not None and not (_is_str(adj) and _ANNOTATOR.match(adj)):
                c.error("bad_annotator", "annotation.adjudicator")
            disagreed = ann.get("initial_disagreement", False)
            if not isinstance(disagreed, bool):
                c.error("wrong_type", "annotation.initial_disagreement", "must be a boolean")
                disagreed = False
            if ok_list and _is_str(author):
                distinct = set(anns)
                if status == "provisional" and adj is not None:
                    c.error("status_annotation_conflict", "annotation", "provisional has an adjudicator")
                if status == "reviewed":
                    if len(distinct) < 2 or not (distinct - {author}):
                        c.error("status_annotation_conflict", "annotation",
                                "reviewed needs a second annotator who is not the author")
                    if adj is not None or disagreed:
                        c.error("status_annotation_conflict", "annotation",
                                "reviewed cannot have a disagreement or adjudicator")
                if status == "adjudicated":
                    if len(distinct) < 2 or adj is None or not disagreed:
                        c.error("status_annotation_conflict", "annotation",
                                "adjudicated needs 2+ annotators, an adjudicator and initial_disagreement")

    # ---- provenance ----------------------------------------------------------------------
    prov = rec.get("provenance")
    synthetic = isinstance(prov, dict) and prov.get("source_type") == "synthetic"
    if "provenance" in rec:
        if not isinstance(prov, dict):
            c.error("wrong_type", "provenance", "must be an object")
        else:
            st, lic, gen = prov.get("source_type"), prov.get("license"), prov.get("generator")
            if st not in S.SOURCE_TYPES:
                c.error("invalid_value", "provenance.source_type")
            if lic not in S.LICENSES:
                c.error("invalid_value", "provenance.license", "license missing or not allowed")
            if gen not in S.GENERATORS:
                c.error("invalid_value", "provenance.generator")
            if st == "synthetic":
                if lic != "project-synthetic":
                    c.error("provenance_conflict", "provenance.license", "synthetic must be project-synthetic")
                if gen == "dataset":
                    c.error("provenance_conflict", "provenance.generator", "synthetic cannot be 'dataset'")
                if gen == "llm" and not _is_str(prov.get("generator_model")):
                    c.warn("llm_generator_model_missing", "provenance.generator_model")
            elif st in S.SOURCE_TYPES:
                if lic == "project-synthetic":
                    c.error("provenance_conflict", "provenance.license", "non-synthetic needs a real license")
                if not (_is_str(prov.get("source_id")) and prov.get("source_id")):
                    c.error("missing_field", "provenance.source_id")
                if not (_is_str(prov.get("retrieved_on")) and _DATE.match(prov["retrieved_on"])):
                    c.error("missing_field", "provenance.retrieved_on", "needs YYYY-MM-DD")
                if prov.get("redaction_applied") is not True:
                    c.error("redaction_not_attested", "provenance.redaction_applied")

    # ---- evidence spans ------------------------------------------------------------------
    spans = rec.get("evidence_spans")
    spanned = set()
    if spans is not None:
        if not isinstance(spans, dict):
            c.error("wrong_type", "evidence_spans", "must be an object")
        else:
            for lab, items in spans.items():
                if lab not in S.INTENT_LABELS:
                    c.error("invalid_value", "evidence_spans", "unknown label key")
                    continue
                if not (isinstance(labels, dict) and labels.get(lab) is True):
                    c.error("span_for_non_positive_label", f"evidence_spans.{lab}")
                if not isinstance(items, list) or not items:
                    c.error("wrong_type", f"evidence_spans.{lab}", "needs a non-empty list")
                    continue
                for it in items:
                    ok = (isinstance(it, dict) and it.get("field") in ("subject", "body")
                          and isinstance(it.get("start"), int) and isinstance(it.get("end"), int)
                          and not isinstance(it.get("start"), bool))
                    if not ok:
                        c.error("bad_span", f"evidence_spans.{lab}")
                        continue
                    text = rec.get(it["field"])
                    if not (0 <= it["start"] < it["end"] and _is_str(text) and it["end"] <= len(text)):
                        c.error("span_out_of_bounds", f"evidence_spans.{lab}")
                    else:
                        spanned.add(lab)
    if status in S.INDEPENDENT_STATUSES and isinstance(labels, dict):
        for k in S.INTENT_LABELS:
            if labels.get(k) is True and k not in spanned:
                (c.error if require_spans else c.warn)("missing_evidence_span", f"labels.{k}")

    if scenario == "adversarial_instruction" and rec.get("contains_embedded_instruction") is not True:
        c.warn("adversarial_flag_not_set", "contains_embedded_instruction")
    if "contains_embedded_instruction" in rec and not isinstance(rec["contains_embedded_instruction"], bool):
        c.error("wrong_type", "contains_embedded_instruction", "must be a boolean")

    notes = rec.get("notes")
    if notes is not None and (not _is_str(notes) or len(notes) > 500):
        c.error("wrong_type", "notes", "must be a string of at most 500 characters")

    if rec.get("split") == "test" and strict_test:
        if status not in S.INDEPENDENT_STATUSES:
            c.error("test_label_not_independent", "label_status",
                    "test records need reviewed or adjudicated labels")

    # ---- secrets and personal data -------------------------------------------------------
    for name in ("subject", "body", "notes"):
        text = rec.get(name)
        if _is_str(text):
            for fnd in scan_text(text, synthetic=synthetic):
                c.sink.append(Issue(fnd.severity, f"sensitive:{fnd.rule}", c.rid, name,
                                    f"characters {fnd.start}-{fnd.end}", c.line))


def _coverage(records: list) -> dict:
    usable = [r for r in records if r.get("label_status") != "needs_review"
              and isinstance(r.get("labels"), dict) and r.get("language") in S.PRIMARY_LANGUAGES]
    cov = {"records": len(records), "usable_primary_language": len(usable),
           "by_split": dict(Counter(r.get("split") for r in records)),
           "by_outcome": dict(Counter(r.get("outcome") for r in usable)),
           "by_scenario": dict(Counter(r.get("scenario") for r in usable)),
           "by_language": dict(Counter(r.get("language") for r in records)),
           "by_label_status": dict(Counter(r.get("label_status") for r in records)),
           "with_url": sum(1 for r in usable if r.get("has_url") is True),
           "independent": sum(1 for r in usable if r.get("label_status") in S.INDEPENDENT_STATUSES),
           "labels": {}, "test_labels": {}}
    test = [r for r in usable if r.get("split") == "test"]
    cov["test_records"] = len(test)
    for lab in S.INTENT_LABELS:
        cov["labels"][lab] = {
            "pos": sum(1 for r in usable if r["labels"].get(lab) is True),
            "neg": sum(1 for r in usable if r["labels"].get(lab) is False)}
        cov["test_labels"][lab] = {
            "pos": sum(1 for r in test if r["labels"].get(lab) is True),
            "neg": sum(1 for r in test if r["labels"].get(lab) is False)}
    return cov


def _coverage_failures(cov: dict, p: CoverageProfile) -> list:
    f = []
    if cov["usable_primary_language"] < p.min_total:
        f.append(f"total usable records {cov['usable_primary_language']} < {p.min_total}")
    for lab, c in cov["labels"].items():
        if c["pos"] < p.min_pos_per_label:
            f.append(f"{lab}: positives {c['pos']} < {p.min_pos_per_label}")
        if c["neg"] < p.min_neg_per_label:
            f.append(f"{lab}: negatives {c['neg']} < {p.min_neg_per_label}")
    for oc, need in p.min_per_outcome.items():
        have = cov["by_outcome"].get(oc, 0)
        if have < need:
            f.append(f"outcome {oc}: {have} < {need}")
    for sc in S.SCENARIOS:
        if sc == "other":
            continue
        have = cov["by_scenario"].get(sc, 0)
        if have < p.min_per_scenario:
            f.append(f"scenario {sc}: {have} < {p.min_per_scenario}")
    if cov["test_records"] < p.test_min_total:
        f.append(f"test split records {cov['test_records']} < {p.test_min_total}")
    for lab, c in cov["test_labels"].items():
        if c["pos"] < p.test_min_pos_per_label:
            f.append(f"test {lab}: positives {c['pos']} < {p.test_min_pos_per_label}")
    return f


def validate_records(
    entries: list,
    *,
    profile: Optional[str] = None,
    manifest: Optional[dict] = None,
    strict_test: bool = False,
    require_spans: bool = False,
    similarity_threshold: float = DEFAULT_THRESHOLD,
) -> Report:
    """entries: [(line_no, record_dict_or_None, parse_error_or_None)]."""
    rep = Report(profile=profile)
    records, seen_ids = [], {}

    for line, obj, perr in entries:
        if perr:
            rep.issues.append(Issue("error", perr, "", "", "line could not be parsed", line))
            continue
        rid = obj.get("id") if _is_str(obj.get("id")) else ""
        if rid:
            if rid in seen_ids:
                rep.issues.append(Issue("error", "duplicate_id", rid, "id",
                                        f"also on line {seen_ids[rid]}", line))
            else:
                seen_ids[rid] = line
        _check_record(obj, _Collector(rid, line, rep.issues),
                      strict_test=strict_test, require_spans=require_spans)
        records.append(obj)
    rep.n_records = len(records)

    # ---- cross-record checks over well-formed text records --------------------------------
    text_recs = [r for r in records if _is_str(r.get("id")) and _is_str(r.get("subject"))
                 and _is_str(r.get("body"))]
    digests = {r["id"]: text_digest(r["subject"], r["body"]) for r in text_recs}
    by_digest = defaultdict(list)
    for rid, d in digests.items():
        by_digest[d].append(rid)
    for ids in by_digest.values():
        if len(ids) > 1:
            ids = sorted(ids)
            for rid in ids:
                rep.issues.append(Issue("error", "exact_duplicate", rid, "body",
                                        "same normalised text as " + ", ".join(i for i in ids if i != rid)))

    meta = {r["id"]: (r.get("group_id"), r.get("split")) for r in text_recs}
    for a, b, score in near_duplicate_pairs(
            [(r["id"], r["subject"], r["body"]) for r in text_recs], similarity_threshold):
        if digests[a] == digests[b]:
            continue
        (ga, sa), (gb, sb) = meta[a], meta[b]
        if sa in S.SCORED_SPLITS and sb in S.SCORED_SPLITS and sa != sb:
            rep.issues.append(Issue("error", "near_duplicate_across_splits", a, "body",
                                    f"similar to {b} (score {score}) in a different split"))
        elif ga != gb:
            rep.issues.append(Issue("warning", "near_duplicate_different_group", a, "group_id",
                                    f"similar to {b} (score {score}); give them one group_id"))

    groups = defaultdict(lambda: defaultdict(list))
    for r in records:
        if _is_str(r.get("group_id")) and _is_str(r.get("id")):
            groups[r["group_id"]][r.get("split")].append(r["id"])
    for g, by_split in sorted(groups.items()):
        scored = sorted(s for s in by_split if s in S.SCORED_SPLITS)
        if len(scored) > 1:
            rep.issues.append(Issue("error", "group_spans_splits", "", "group_id",
                                    f"group {g} appears in {', '.join(scored)}"))
        elif scored and "unassigned" in by_split:
            rep.issues.append(Issue("warning", "group_partially_assigned", "", "group_id",
                                    f"group {g} has records with and without a split"))

    if manifest is not None:
        _check_manifest(rep, records, digests, manifest)

    rep.coverage = _coverage(records)
    if profile:
        if profile not in PROFILES:
            raise ValueError(f"unknown coverage profile {profile!r}")
        rep.coverage_failures = _coverage_failures(rep.coverage, PROFILES[profile])
    return rep


def _check_manifest(rep: Report, records: list, digests: dict, manifest: dict) -> None:
    assign = manifest.get("assignments", {})
    merged = manifest.get("merged_groups", {})
    frozen = bool(manifest.get("frozen"))
    stored = manifest.get("record_digests", {})
    for r in records:
        rid, g, sp = r.get("id"), r.get("group_id"), r.get("split")
        if not (_is_str(rid) and _is_str(g)):
            continue
        eff = merged.get(g, g)
        want = assign.get(eff)
        if sp in S.SCORED_SPLITS:
            if want is None:
                rep.issues.append(Issue("error", "group_not_in_manifest", rid, "group_id",
                                        "record is assigned a split but its group is not in the manifest"))
            elif want != sp:
                rep.issues.append(Issue("error", "split_disagrees_with_manifest", rid, "split",
                                        f"manifest assigns this group to {want}"))
        elif want is not None:
            rep.issues.append(Issue("warning", "record_unassigned_but_in_manifest", rid, "split",
                                    f"manifest assigns this group to {want}"))
        if rid in stored and rid in digests and stored[rid] != digests[rid]:
            rep.issues.append(Issue("error" if frozen else "warning", "record_modified_since_manifest",
                                    rid, "body", "text changed after the manifest was created"))
        elif frozen and want is not None and rid not in stored:
            rep.issues.append(Issue("warning", "record_added_to_frozen_group", rid, "group_id",
                                    "record is new in an already-assigned group"))


def validate_file(path, **kw) -> Report:
    return validate_records(load_jsonl(Path(path)), **kw)
