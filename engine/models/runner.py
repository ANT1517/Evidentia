"""Experimental two-model runner: DistilBERT class scores + Laya intent scores.

Both adapters are independent: either may be disabled or fail and the other still reports.
The runner NEVER feeds model outputs into the verdict. `assess()` returns the unchanged result
of `analyze()` next to the model report; a model failure cannot affect the rules-only path.
Every output is marked experimental. `text_model` and `intent_questions` are not marked
complete here: the policy's required checks are untouched.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from ..analyze import analyze
from ..schemas import Assessment, NormalizedMessage
from .email import EmailClassifierAdapter, EmailClassResult, EmailModelStatus
from .intent import IntentResult, IntentStatus, LayaIntentAdapter


@dataclass(frozen=True)
class TwoModelReport:
    email: EmailClassResult
    intent: IntentResult
    email_seconds: float
    intent_seconds: float
    experimental: bool = field(default=True, init=False)
    # Fixed statements so consumers cannot mistake these for verdict inputs.
    notes: tuple = field(default=(
        "experimental: not a verdict and not used by the risk policy",
        "email class mapping is unresolved; class indexes are not phishing/legitimate labels",
        "intent probabilities are uncalibrated",
    ), init=False)


class TwoModelRunner:
    def __init__(self, email: Optional[EmailClassifierAdapter] = None,
                 intent: Optional[LayaIntentAdapter] = None) -> None:
        self.email = email or EmailClassifierAdapter()      # disabled by default
        self.intent = intent or LayaIntentAdapter()         # disabled by default

    def run(self, text: str) -> TwoModelReport:
        """Run each model separately and bounded. Never raises."""
        t0 = time.monotonic()
        try:
            e = self.email.classify(text)
        except Exception as ex:                            # adapters should not raise; belt and braces
            e = EmailClassResult(EmailModelStatus.INFERENCE_ERROR, detail=type(ex).__name__)
        t1 = time.monotonic()
        try:
            i = self.intent.classify(text)
        except Exception as ex:
            i = IntentResult(IntentStatus.INFERENCE_ERROR, detail=type(ex).__name__)
        t2 = time.monotonic()
        return TwoModelReport(e, i, round(t1 - t0, 3), round(t2 - t1, 3))

    def assess(self, msg: NormalizedMessage, **analyze_kwargs) -> tuple:
        """-> (Assessment, TwoModelReport). The assessment is exactly analyze(msg, ...)."""
        assessment: Assessment = analyze(msg, **analyze_kwargs)
        report = self.run(f"{msg.subject}\n\n{msg.body_text}".strip())
        return assessment, report
