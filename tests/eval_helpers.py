"""Builders for evaluation-dataset tests. Every text here is synthetic and invented."""
import copy
import json

LABELS = ("authority_claim_in_content", "payment_request", "credential_request", "urgency_secrecy")
SENTINEL = "ZXQ-SENTINEL-7731"        # must never appear in any report output


def rec(rid="rec-001", **over):
    r = {
        "schema_version": "1.0", "id": rid, "subject": "Weekly update",
        "body": "Hello team, here is the plan for the week. Please read the attached notes "
                "before our meeting on Thursday afternoon. Thanks, Sam",
        "language": "en", "channel": "email", "has_url": False,
        "scenario": "internal_business_legit",
        "labels": {k: False for k in LABELS},
        "outcome": "legitimate", "label_status": "provisional",
        "annotation": {"authored_by": "author-a", "annotators": ["author-a"],
                       "adjudicator": None, "initial_disagreement": False},
        "provenance": {"source_type": "synthetic", "license": "project-synthetic",
                       "generator": "human", "author": "author-a"},
        "group_id": f"grp-{rid}", "split": "unassigned",
    }
    r.update(copy.deepcopy(over))
    return r


def entries(records):
    return [(i, r, None) for i, r in enumerate(records, 1)]


def jsonl(records) -> str:
    return "".join(json.dumps(r) + "\n" for r in records)


def codes(report):
    return [i.code for i in report.issues]


def reviewed(**over):
    base = dict(label_status="reviewed",
                annotation={"authored_by": "author-a", "annotators": ["author-a", "annot-b"],
                            "adjudicator": None, "initial_disagreement": False})
    base.update(over)
    return base


def long_text(seed_word: str, n: int = 30) -> str:
    """A body of n distinct letter-only words, different for every seed_word.

    Letters only on purpose: near-duplicate detection masks digits, so digit-bearing words
    would make unrelated texts compare equal.
    """
    import hashlib
    words = []
    for i in range(n):
        h = hashlib.sha256(f"{seed_word}:{i}".encode()).hexdigest()[:7]
        words.append("".join("abcdefghijklmnop"[int(c, 16)] for c in h))
    return " ".join(words)
