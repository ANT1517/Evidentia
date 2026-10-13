#!/usr/bin/env python
"""Create or extend a frozen group-level split manifest, and write an annotated COPY of the data.

Reads labels only for the balance report; assignment never depends on labels. Never edits the
input file. Never overwrites a frozen manifest.

  python scripts/make_eval_splits.py corpus.jsonl --seed 20261013 \\
      --out-manifest splits.json --out-data corpus.split.jsonl
  python scripts/make_eval_splits.py corpus.jsonl --seed 20261013 --previous splits.json \\
      --out-manifest splits.json --force     # add new groups; existing assignments are kept
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.similarity import DEFAULT_THRESHOLD  # noqa: E402
from evaluation.splits import (  # noqa: E402
    DEFAULT_FRACTIONS, SplitConflict, apply_manifest, balance_report, build_manifest, dump_manifest,
)
from evaluation.validate import load_jsonl, validate_records  # noqa: E402


def _fractions(text: str) -> dict:
    out = {}
    for part in text.split(","):
        k, _, v = part.partition("=")
        out[k.strip()] = float(v)
    return out


def main(argv=None, out=None) -> int:
    out = out or sys.stdout
    say = lambda s="": out.write(s + "\n")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", type=Path)
    ap.add_argument("--seed", type=int, required=True, help="required; record it with the manifest")
    ap.add_argument("--fractions", default=",".join(f"{k}={v}" for k, v in DEFAULT_FRACTIONS.items()))
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--previous", type=Path, help="existing manifest whose assignments are kept")
    ap.add_argument("--freeze", action="store_true", help="mark the manifest frozen (irreversible here)")
    ap.add_argument("--out-manifest", type=Path, required=True)
    ap.add_argument("--out-data", type=Path, help="write a copy with only `split` filled in")
    ap.add_argument("--force", action="store_true", help="overwrite an UNFROZEN existing output")
    args = ap.parse_args(argv)

    try:
        entries = load_jsonl(args.path)
        previous = json.loads(args.previous.read_text(encoding="utf-8")) if args.previous else None
        fractions = _fractions(args.fractions)
    except (OSError, UnicodeDecodeError, ValueError) as e:
        say(f"cannot read input ({type(e).__name__})")
        return 3

    rep = validate_records(entries, manifest=None)
    blocking = [i for i in rep.errors if i.code not in ("group_spans_splits",)]
    if blocking:
        say(f"REFUSED: the input has {len(blocking)} validation error(s); run "
            f"validate_eval_dataset.py first")
        return 1
    records = [obj for _, obj, _ in entries if obj is not None]

    target = args.out_manifest
    if target.exists():
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
        if existing.get("frozen"):
            say("REFUSED: the output manifest is frozen and is never overwritten. Write a new "
                "manifest with --previous instead.")
            return 4
        if not args.force:
            say("REFUSED: output manifest exists; pass --force to overwrite an unfrozen one")
            return 4

    try:
        manifest = build_manifest(records, seed=args.seed, fractions=fractions,
                                  threshold=args.threshold, previous=previous, freeze=args.freeze)
    except (SplitConflict, ValueError) as e:
        say(f"REFUSED: {e}")
        return 5

    target.write_text(dump_manifest(manifest), encoding="utf-8")
    say(f"manifest written: {target}  (frozen={manifest['frozen']}, seed={manifest['seed']}, "
        f"algorithm={manifest['algorithm']})")
    say(f"records={manifest['n_records']} groups={manifest['n_groups']} units={manifest['n_units']}")
    assigned = apply_manifest(records, manifest)
    for sp, v in balance_report(assigned).items():
        say(f"  {sp:<12} records={v['records']:<4} groups={v['groups']:<4} outcomes={v['outcomes']}")
    if args.out_data:
        if args.out_data.exists() and not args.force:
            say("REFUSED: output data exists; pass --force")
            return 4
        args.out_data.write_text(
            "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in assigned),
            encoding="utf-8")
        say(f"data copy written: {args.out_data}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
