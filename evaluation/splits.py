"""Leakage-safe split assignment for the evaluation corpus.

Rules the code enforces (rationale in docs/evaluation_dataset_spec.md):
  * Splits are assigned per GROUP, never per message. Groups that contain near-duplicate
    messages are merged first, so related text cannot straddle splits.
  * Assignment is a pure function of (seed, group ids, scenario mix, sizes): deterministic and
    reproducible. Within each scenario stratum, groups are dealt by hash order towards the
    target fractions, weighted by record count.
  * A manifest records the seed, algorithm, similarity threshold, the group->split table and a
    digest of every record, so later edits are detectable.
  * Once a manifest is frozen, existing assignments are never changed. New groups may be added;
    anything that would force an existing assignment to change raises SplitConflict.

Test labels never influence assignment (labels are not read here), and nothing in this module
selects a threshold.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from typing import Optional

from . import schema as S
from .similarity import DEFAULT_THRESHOLD, near_duplicate_pairs, text_digest

ALGORITHM = "group-stratified-hash-v1"
MANIFEST_VERSION = 1
DEFAULT_FRACTIONS = {"dev": 0.4, "calibration": 0.3, "test": 0.3}
ORDER = ("dev", "calibration", "test")


class SplitConflict(Exception):
    """Raised when keeping a frozen assignment is impossible without leakage."""


def _hash(seed: int, key: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}:{key}".encode()).digest()[:8], "big")


def _find(parent: dict, x: str) -> str:
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def merge_groups(records: list, threshold: float = DEFAULT_THRESHOLD,
                 links: Optional[list] = None) -> dict:
    """{group_id: unit_id}. Groups linked by near-duplicate messages share one unit.

    `links` are extra (group, group) pairs that must stay merged (earlier merges recorded in
    a previous manifest). The unit id is the lexicographically smallest member group, so it is
    stable and independent of record order.
    """
    parent = {r["group_id"]: r["group_id"] for r in records}
    group_of = {r["id"]: r["group_id"] for r in records}
    edges = [(group_of[a], group_of[b]) for a, b, _ in near_duplicate_pairs(
        [(r["id"], r["subject"], r["body"]) for r in records], threshold)]
    edges += [(a, b) for a, b in (links or []) if a in parent and b in parent]
    for ga, gb in edges:
        ra, rb = _find(parent, ga), _find(parent, gb)
        if ra != rb:
            keep, drop = sorted((ra, rb))
            parent[drop] = keep
    return {g: _find(parent, g) for g in parent}


def _records_digest(records: list, digests: dict) -> str:
    lines = sorted(f"{r['id']}\t{r['group_id']}\t{digests[r['id']]}" for r in records)
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def build_manifest(
    records: list,
    *,
    seed: int,
    fractions: Optional[dict] = None,
    threshold: float = DEFAULT_THRESHOLD,
    previous: Optional[dict] = None,
    freeze: bool = False,
) -> dict:
    fractions = dict(fractions or DEFAULT_FRACTIONS)
    if set(fractions) != set(ORDER) or any(v <= 0 for v in fractions.values()) \
            or abs(sum(fractions.values()) - 1.0) > 1e-9:
        raise ValueError("fractions must name dev, calibration and test, be positive, and sum to 1")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer")

    prev = previous or {}
    prev_assign = dict(prev.get("assignments", {}))
    prev_merged = dict(prev.get("merged_groups", {}))
    if previous and prev.get("seed") != seed:
        raise SplitConflict("seed differs from the previous manifest; refusing to re-assign")

    def prev_split(group: str) -> Optional[str]:
        return prev_assign.get(prev_merged.get(group, group))

    present = {r["group_id"] for r in records}
    links = [(g, u) for g, u in prev_merged.items() if g in present and u in present]
    group_to_unit = merge_groups(records, threshold, links)

    members = defaultdict(list)
    for g, u in group_to_unit.items():
        members[u].append(g)

    assignments = {}
    for unit, groups in members.items():
        carried = {prev_split(g) for g in groups} - {None}
        if len(carried) > 1:
            raise SplitConflict(
                f"group unit {unit} now links groups already assigned to {sorted(carried)}")
        if carried:
            assignments[unit] = carried.pop()

    unit_records = defaultdict(list)
    for r in records:
        unit_records[group_to_unit[r["group_id"]]].append(r)

    def stratum(unit: str) -> str:
        c = Counter(r["scenario"] for r in unit_records[unit])
        return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    strata = defaultdict(list)
    for unit in unit_records:
        strata[stratum(unit)].append(unit)

    for _, units in sorted(strata.items()):
        total = sum(len(unit_records[u]) for u in units)
        have = Counter()
        for u in units:
            if u in assignments:
                have[assignments[u]] += len(unit_records[u])
        for u in sorted((u for u in units if u not in assignments),
                        key=lambda u: (_hash(seed, u), u)):
            deficit = {s: fractions[s] * total - have[s] for s in ORDER}
            best = max(ORDER, key=lambda s: (round(deficit[s], 9), -ORDER.index(s)))
            assignments[u] = best
            have[best] += len(unit_records[u])

    digests = {r["id"]: text_digest(r["subject"], r["body"]) for r in records}
    stored = dict(prev.get("record_digests", {}))
    stored.update(digests)
    return {
        "manifest_version": MANIFEST_VERSION,
        "algorithm": ALGORITHM,
        "seed": seed,
        "fractions": fractions,
        "similarity_threshold": threshold,
        "frozen": bool(freeze or prev.get("frozen")),
        "assignments": {u: assignments[u] for u in sorted(assignments)},
        "merged_groups": {g: u for g, u in sorted(group_to_unit.items()) if g != u},
        "record_digests": {k: stored[k] for k in sorted(stored)},
        "records_digest": _records_digest(records, digests),
        "n_records": len(records),
        "n_groups": len(group_to_unit),
        "n_units": len(unit_records),
    }


def apply_manifest(records: list, manifest: dict) -> list:
    """Copies of `records` with only the `split` field set from the manifest."""
    merged = manifest.get("merged_groups", {})
    assign = manifest["assignments"]
    out = []
    for r in records:
        copy = dict(r)
        copy["split"] = assign.get(merged.get(r["group_id"], r["group_id"]), "unassigned")
        out.append(copy)
    return out


def balance_report(records: list) -> dict:
    """Counts per split, for the human reviewing a manifest. Reads labels for REPORTING only."""
    rep = {}
    for sp in ORDER:
        rs = [r for r in records if r.get("split") == sp]
        rep[sp] = {
            "records": len(rs),
            "groups": len({r["group_id"] for r in rs}),
            "outcomes": dict(Counter(r["outcome"] for r in rs)),
            "labels_true": {
                k: sum(1 for r in rs if r["labels"].get(k) is True) for k in S.INTENT_LABELS},
        }
    return rep


def dump_manifest(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True) + "\n"
