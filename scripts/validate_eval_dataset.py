#!/usr/bin/env python
"""Validate a labelled evaluation file. Offline; never modifies data; never prints message text.

Exit codes: 0 = no errors (and coverage met if --profile was given), 1 = validation errors,
2 = no errors but the requested coverage profile is not met, 3 = unreadable input.

  python scripts/validate_eval_dataset.py evaluation/data/examples_synthetic.jsonl
  python scripts/validate_eval_dataset.py corpus.jsonl --manifest splits.json --profile starter --strict-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.similarity import DEFAULT_THRESHOLD  # noqa: E402
from evaluation.validate import PROFILES, load_jsonl, validate_records  # noqa: E402


def main(argv=None, out=None) -> int:
    out = out or sys.stdout
    say = lambda s="": out.write(s + "\n")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path", type=Path)
    ap.add_argument("--manifest", type=Path, help="split manifest produced by make_eval_splits.py")
    ap.add_argument("--profile", choices=sorted(PROFILES), help="coverage profile to check")
    ap.add_argument("--strict-test", action="store_true",
                    help="test records must have reviewed/adjudicated labels")
    ap.add_argument("--require-spans", action="store_true",
                    help="independently labelled positives must carry evidence spans")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                    help="near-duplicate similarity threshold")
    ap.add_argument("--max-issues", type=int, default=200)
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args(argv)

    try:
        entries = load_jsonl(args.path)
        manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest else None
    except (OSError, UnicodeDecodeError, ValueError) as e:
        say(f"cannot read input ({type(e).__name__})")
        return 3

    rep = validate_records(entries, profile=args.profile, manifest=manifest,
                           strict_test=args.strict_test, require_spans=args.require_spans,
                           similarity_threshold=args.threshold)

    if args.json:
        say(json.dumps({
            "records": rep.n_records, "errors": len(rep.errors), "warnings": len(rep.warnings),
            "issues": [i.__dict__ for i in rep.issues[:args.max_issues]],
            "coverage": rep.coverage, "profile": rep.profile,
            "coverage_met": rep.coverage_met, "coverage_failures": rep.coverage_failures,
        }, indent=2, sort_keys=True))
    else:
        say(f"records: {rep.n_records}   errors: {len(rep.errors)}   warnings: {len(rep.warnings)}")
        for i in rep.issues[:args.max_issues]:
            say("  " + i.render())
        if len(rep.issues) > args.max_issues:
            say(f"  ... {len(rep.issues) - args.max_issues} more not shown")
        c = rep.coverage
        say("")
        say("COVERAGE (descriptive; counts are not a statement about reliability)")
        say(f"  usable primary-language records: {c['usable_primary_language']}  "
            f"(independently reviewed: {c['independent']})")
        say(f"  by split: {c['by_split']}")
        say(f"  by outcome: {c['by_outcome']}")
        for lab, v in c["labels"].items():
            say(f"  {lab:<28} positives={v['pos']:<4} negatives={v['neg']:<4} "
                f"(test: {c['test_labels'][lab]['pos']}/{c['test_labels'][lab]['neg']})")
        if rep.profile:
            say("")
            if rep.coverage_failures:
                say(f"PROFILE '{rep.profile}': NOT MET")
                for f in rep.coverage_failures:
                    say(f"  - {f}")
            else:
                say(f"PROFILE '{rep.profile}': met (a floor for running the experiment, "
                    f"not a guarantee of reliability)")

    if rep.errors:
        return 1
    if rep.profile and rep.coverage_failures:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
