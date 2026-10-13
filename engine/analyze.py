"""Single entry point of the analysis engine.

Rules-only baseline: deterministic header, identity, domain and attachment checks plus the
versioned policy. No network calls, no model inference. Threat intelligence, the text models
and the intent questions are not part of this version.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .config import DEFAULT_CONFIG, EngineConfig
from .policy import POLICY_VERSION, decide
from .rules import RULES_VERSION, run_rules
from .schemas import (
    Assessment,
    Channel,
    Evidence,
    EvidenceStatus,
    NormalizedMessage,
    Reason,
    ReasonCode,
    RiskBand,
)


def analyze(
    msg: NormalizedMessage,
    *,
    config: EngineConfig = DEFAULT_CONFIG,
    now: Optional[datetime] = None,
) -> Assessment:
    """Assess one message. Deterministic for a fixed message, config and `now`.

    `now` only stamps evidence.observed_at and created_at; pass it to make the whole
    Assessment byte-for-byte reproducible. The band and reasons never depend on it.
    """
    now = now or datetime.now(timezone.utc)

    if msg.channel != Channel.EMAIL:
        return _unsupported(msg, now)

    results = run_rules(msg, config, now)
    decision = decide(results, config, config.active_profile, now)

    evidence = [e for r in results for e in r.evidence] + decision.extra_evidence
    known = {e.evidence_id for e in evidence}
    for reason in decision.reasons:
        dangling = set(reason.evidence_ids) - known
        if dangling or not reason.evidence_ids:
            raise ValueError(f"reason {reason.code} cites missing evidence: {sorted(dangling)}")

    return Assessment(
        external_id=msg.external_id,
        risk_band=decision.band,
        reasons=decision.reasons,
        evidence=evidence,
        data_completeness=decision.data_completeness,
        model_versions={"rules": RULES_VERSION},
        policy_version=POLICY_VERSION,
        analysis_profile=decision.profile,
        policy_rules=decision.policy_rules,
        created_at=now,
    )


def _unsupported(msg: NormalizedMessage, now: datetime) -> Assessment:
    ev = Evidence(
        evidence_id="channel-1",
        type="channel_support",
        value=msg.channel.value,
        source="engine",
        status=EvidenceStatus.NOT_CHECKED,
        observed_at=now,
        detail="Only email rule checks exist in this version of the engine.",
    )
    return Assessment(
        external_id=msg.external_id,
        risk_band=RiskBand.INSUFFICIENT_DATA,
        reasons=[Reason(
            code=ReasonCode.CHECK_INCOMPLETE,
            text="This message type could not be fully checked. Ask IT if unsure.",
            evidence_ids=[ev.evidence_id],
        )],
        evidence=[ev],
        data_completeness="none",
        policy_version=POLICY_VERSION,
        analysis_profile="unsupported_channel",
        policy_rules=["I1_REQUIRED_CHECK_INCOMPLETE"],
        created_at=now,
    )
