"""Controlled access to labelled records.

The untouched test split is locked by default. Code that fits or selects anything (thresholds,
temperatures, prompts, templates) must load only `dev` and `calibration` through
`for_tuning()`. Test labels are opened once, explicitly, for the final report.

This is a guard against accidents, not a security boundary: anyone can read the JSONL file.
The real control is procedural (docs/evaluation_dataset_spec.md, section 7).
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import schema as S
from .validate import load_jsonl, validate_records


class TestSplitLocked(RuntimeError):
    __test__ = False        # not a pytest class


class DatasetInvalid(ValueError):
    pass


def load_records(
    path,
    *,
    split: Optional[str] = None,
    unlock_test: bool = False,
    manifest: Optional[dict] = None,
) -> list:
    """Validated records, optionally for one split. Raises DatasetInvalid on any error.

    With split=None the test split is silently excluded unless unlock_test=True. Asking for
    split="test" without unlock_test=True raises TestSplitLocked.
    """
    if split is not None and split not in S.SPLITS:
        raise ValueError(f"unknown split {split!r}")
    if split == "test" and not unlock_test:
        raise TestSplitLocked("the test split is locked; unlock_test=True is for the final report only")

    entries = load_jsonl(Path(path))
    rep = validate_records(entries, manifest=manifest)
    if not rep.ok:
        raise DatasetInvalid(f"{len(rep.errors)} validation error(s); run the validator for details")
    records = [obj for _, obj, _ in entries if obj is not None]

    if split is not None:
        return [r for r in records if r["split"] == split]
    if unlock_test:
        return records
    return [r for r in records if r["split"] != "test"]


def for_tuning(path, *, manifest: Optional[dict] = None) -> list:
    """dev + calibration records only. The function to use when selecting any parameter."""
    return [r for r in load_records(path, manifest=manifest) if r["split"] in ("dev", "calibration")]
