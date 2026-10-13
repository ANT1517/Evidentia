"""Versioned policy layer: rule results in, risk band and ordered reasons out.

Precedence (first match wins):  Urgent > Review > Insufficient data > Low

  Urgent   U1  threat-intel match on a URL or attachment hash        (adapters not built yet)
           U2  attachment named like an executable
           U3  VERIFIED authentication failure + identity mismatch / protected-domain sender
           U4  a configured combination of rule facts (EngineConfig.urgent_combinations)
  Review   R1  any single meaningful indicator (reply-to mismatch, lookalike domain, link text
               mismatch, display-name impersonation, macro-capable or other risky attachment,
               a verified auth failure or soft-fail on its own)
  Insufficient data
           any check required by the active profile did not complete (failed, timed out,
           input untrusted, or was never run)
  Low      every required check completed AND no indicator fired

Isolated cues stay at Review. Missing or untrusted evidence is never read as clean.
A Low under a profile that is not "full" is a partial assessment and is labelled as such.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .config import EngineConfig
from .rules import CheckResult
from .schemas import Evidence, EvidenceStatus, Reason, ReasonCode, RiskBand

POLICY_VERSION = "0.1.0"


@dataclass(frozen=True)
class Profile:
    name: str
    required: frozenset
    is_full: bool        # True only for a profile that covers every planned check


_RULES_REQUIRED = frozenset({
    "auth_spf", "auth_dmarc", "reply_to", "identity", "lookalike", "link_mismatch", "attachments",
})

PROFILES: dict[str, Profile] = {
    # Deterministic baseline: header/identity/domain/attachment rules only.
    "rules_only": Profile("rules_only", _RULES_REQUIRED, is_full=False),
    # Target profile once threat intel, text model and intent questions exist.
    "full": Profile(
        "full", _RULES_REQUIRED | {"threat_intel", "text_model", "intent_questions"}, is_full=True
    ),
}

_THREAT_FACTS = {"threat_intel.url_listed", "threat_intel.hash_listed"}
_IDENTITY_FACTS = {
    "identity.brand_mismatch", "identity.exec_mismatch", "identity.person_mismatch",
    "identity.title_claim", "identity.protected_domain_sender",
}
_REVIEW_FACTS = (
    "reply_to.mismatch", "lookalike.domain", "link.mismatch",
    "identity.exec_mismatch", "identity.person_mismatch", "identity.brand_mismatch",
    "identity.title_claim", "identity.display_address_mismatch",
    "attachment.macro", "attachment.risky_other",
    "auth.trusted_fail", "auth.trusted_softfail",
)

_REASON_ORDER = [
    ReasonCode.URL_ON_THREAT_LIST, ReasonCode.HASH_ON_THREAT_LIST, ReasonCode.RISKY_ATTACHMENT,
    ReasonCode.EXEC_IMPERSONATION, ReasonCode.SPF_FAIL, ReasonCode.DMARC_FAIL,
    ReasonCode.DKIM_FAIL, ReasonCode.DISPLAY_NAME_SPOOF, ReasonCode.LOOKALIKE_DOMAIN,
    ReasonCode.REPLY_TO_MISMATCH, ReasonCode.LINK_TEXT_MISMATCH, ReasonCode.NEW_DOMAIN,
    ReasonCode.CHECK_INCOMPLETE,
]
_CHECK_NAMES = {
    "auth_spf": "SPF sender authentication", "auth_dkim": "DKIM signature",
    "auth_dmarc": "DMARC policy", "reply_to": "Reply-To comparison",
    "identity": "sender identity", "lookalike": "look-alike domains",
    "link_mismatch": "link destinations", "attachments": "attachments",
    "threat_intel": "threat-intelligence lookups", "text_model": "text model",
    "intent_questions": "intent questions",
}


@dataclass
class Decision:
    band: RiskBand
    reasons: list[Reason]
    extra_evidence: list[Evidence]
    policy_rules: list[str]
    data_completeness: str                     # "complete" | "partial" | "none"
    profile: str
    missing_checks: list[str] = field(default_factory=list)


def _sort_key(r: Reason) -> int:
    return _REASON_ORDER.index(r.code) if r.code in _REASON_ORDER else len(_REASON_ORDER)


def decide(
    results: list[CheckResult], cfg: EngineConfig, profile_name: str, now: datetime
) -> Decision:
    profile = PROFILES[profile_name]
    by_check = {r.check: r for r in results}
    facts: set[str] = set().union(*(r.facts for r in results)) if results else set()

    # ---- required checks -------------------------------------------------------------
    extra: list[Evidence] = []
    missing: list[str] = []
    incomplete_evidence_ids: list[str] = []
    for check in sorted(profile.required):
        r = by_check.get(check)
        if r is None:
            missing.append(check)
            eid = f"missing-{check}"
            extra.append(Evidence(
                evidence_id=eid, type=check, value="not run", source="policy:missing-check",
                status=EvidenceStatus.NOT_CHECKED, observed_at=now,
                detail="This check is required by the profile but did not run.",
            ))
            incomplete_evidence_ids.append(eid)
        elif not r.completed:
            missing.append(check)
            incomplete_evidence_ids.extend(
                e.evidence_id for e in r.evidence if e.status == EvidenceStatus.NOT_CHECKED
            )

    # Checks that exist in the full profile but are outside this one: recorded, not required.
    for check in sorted(PROFILES["full"].required - profile.required):
        extra.append(Evidence(
            evidence_id=f"out-of-scope-{check}", type=check, value="not run",
            source=f"profile:{profile.name}", status=EvidenceStatus.NOT_CHECKED, observed_at=now,
            detail=f"Not part of the '{profile.name}' profile, so this is not a full assessment.",
        ))

    # ---- band ------------------------------------------------------------------------
    fired: list[str] = []
    if facts & _THREAT_FACTS:
        fired.append("U1_THREAT_INTEL_MATCH")
    if "attachment.executable" in facts:
        fired.append("U2_EXECUTABLE_ATTACHMENT")
    if "auth.trusted_fail" in facts and facts & _IDENTITY_FACTS:
        fired.append("U3_VERIFIED_AUTH_FAIL_WITH_IDENTITY")
    for combo in cfg.urgent_combinations:
        if combo <= facts:
            fired.append("U4_COMBINATION:" + "+".join(sorted(combo)))

    if fired:
        band = RiskBand.URGENT
    else:
        review = [f"R1_INDICATOR:{f}" for f in _REVIEW_FACTS if f in facts]
        if review:
            band, fired = RiskBand.REVIEW, review
        elif missing:
            band, fired = RiskBand.INSUFFICIENT_DATA, ["I1_REQUIRED_CHECK_INCOMPLETE"]
        else:
            band, fired = RiskBand.LOW, ["L1_ALL_REQUIRED_CHECKS_CLEAN"]

    # ---- reasons ---------------------------------------------------------------------
    reasons = sorted((rs for r in results for rs in r.reasons), key=_sort_key)
    if missing and band != RiskBand.LOW:
        names = ", ".join(_CHECK_NAMES.get(c, c) for c in missing)
        reasons.append(Reason(
            code=ReasonCode.CHECK_INCOMPLETE,
            text=f"Some checks could not be completed or trusted: {names}.",
            evidence_ids=incomplete_evidence_ids,
        ))

    completed_any = any(r.completed for r in results)
    if not completed_any:
        completeness = "none"
    elif missing or not profile.is_full:
        completeness = "partial"
    else:
        completeness = "complete"

    return Decision(
        band=band, reasons=reasons, extra_evidence=extra, policy_rules=fired,
        data_completeness=completeness, profile=profile.name, missing_checks=missing,
    )
