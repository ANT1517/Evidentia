"""Single entry point of the analysis engine.

Rules-only baseline: deterministic header, identity, domain and attachment checks plus the
versioned policy. No network calls, no model inference. Threat intelligence, the text models
and the intent questions are not part of this version.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .config import DEFAULT_CONFIG, EngineConfig
from .policy import POLICY_VERSION, PROFILES, decide
from .rules import RULES_VERSION, run_rules
from .threat_intel import TI_VERSION, ThreatIntelService, build_check_result
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
    threat_intel: Optional[ThreatIntelService] = None,
) -> Assessment:
    """Assess one message. Deterministic for a fixed message, config and `now`.

    `now` only stamps evidence.observed_at and created_at; pass it to make the whole
    Assessment byte-for-byte reproducible. The band and reasons never depend on it.

    `threat_intel` is used only when the active profile requires the "threat_intel" check.
    Under `rules_only` it is ignored and no external request is ever made. The call is
    synchronous and may block for up to the service deadline: run it in a worker thread.
    """
    now = now or datetime.now(timezone.utc)

    if msg.channel != Channel.EMAIL:
        return _unsupported(msg, now)

    results = run_rules(msg, config, now)
    model_versions = {"rules": RULES_VERSION}
    if threat_intel is not None and "threat_intel" in PROFILES[config.active_profile].required:
        report = threat_intel.lookup_message(
            msg, denied_domains=frozenset(config.org_domains), now=now
        )
        results.append(build_check_result(report, threat_intel.cfg, now))
        model_versions["threat_intel"] = TI_VERSION
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
        model_versions=model_versions,
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
