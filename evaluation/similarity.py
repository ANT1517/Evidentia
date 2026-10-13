"""Text normalisation and near-duplicate detection (stdlib only, deterministic).

Near-duplicate detection is a BACKSTOP. The primary mechanism against leakage is that authors
give related messages the same `group_id`. Entity swaps, paraphrase, or translation can defeat
a shingle measure, so a low score is never proof that two messages are unrelated.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from typing import Iterable

_URL = re.compile(r"(?i)(?:https?://|hxxps?://|www\.)\S+")
_DIGITS = re.compile(r"\d+")
_WORD = re.compile(r"[^\W_]+", re.UNICODE)

SHINGLE_WORDS = 3
DEFAULT_THRESHOLD = 0.75
MIN_TOKENS_FOR_NEAR = 8            # shorter texts are compared for exact equality only


def normalise(text: str) -> str:
    """Case, width, digits, URLs and whitespace folded so templates compare equal."""
    t = unicodedata.normalize("NFKC", text or "").casefold()
    t = _URL.sub(" url ", t)
    t = _DIGITS.sub("0", t)
    return " ".join(_WORD.findall(t))


def tokens(text: str) -> list:
    return normalise(text).split()


def shingles(toks: list, k: int = SHINGLE_WORDS) -> frozenset:
    if len(toks) < k:
        return frozenset([" ".join(toks)]) if toks else frozenset()
    return frozenset(" ".join(toks[i:i + k]) for i in range(len(toks) - k + 1))


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    return inter / (len(a) + len(b) - inter) if (a or b) else 0.0


def text_digest(subject: str, body: str) -> str:
    """Stable digest of the normalised text: equal digests mean exact duplicates after folding."""
    return hashlib.sha256(normalise(f"{subject}\n{body}").encode("utf-8")).hexdigest()


def near_duplicate_pairs(items: Iterable[tuple], threshold: float = DEFAULT_THRESHOLD) -> list:
    """items: (id, subject, body). Returns sorted [(id_a, id_b, score)] with score >= threshold.

    Candidate pairs come from an inverted index on shingles so the cost stays modest for a
    few thousand messages. Texts under MIN_TOKENS_FOR_NEAR tokens only match when identical.
    """
    sets, short = {}, {}
    for rid, subject, body in items:
        toks = tokens(f"{subject}\n{body}")
        if len(toks) < MIN_TOKENS_FOR_NEAR:
            short[rid] = " ".join(toks)
        else:
            sets[rid] = shingles(toks)

    index = defaultdict(list)
    for rid, sh in sets.items():
        for s in sh:
            index[s].append(rid)
    candidates = defaultdict(int)
    for ids in index.values():
        if len(ids) > 1:
            ids = sorted(ids)
            for i, a in enumerate(ids):
                for b in ids[i + 1:]:
                    candidates[(a, b)] += 1

    out = []
    for (a, b), _ in candidates.items():
        score = jaccard(sets[a], sets[b])
        if score >= threshold:
            out.append((a, b, round(score, 4)))
    by_text = defaultdict(list)
    for rid, t in short.items():
        by_text[t].append(rid)
    for ids in by_text.values():
        ids = sorted(ids)
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                out.append((a, b, 1.0))
    return sorted(out)
