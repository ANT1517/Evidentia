"""Turn a ThreatIntelReport into one policy CheckResult named "threat_intel".

Evidence rows: one per distinct (indicator, provider) outcome. To keep the ledger readable,
privacy-blocked lookups are folded into one row per indicator and disabled providers into
one row per provider; neither is ever reported as clean.

`completed` is True only when every checked indicator got a conclusive answer from every
enabled reputation provider (config.completeness_providers) and nothing was skipped.
Domain age is a weak signal and does not gate completeness.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Optional

from ..rules import CheckResult, _safe
from ..schemas import Evidence, EvidenceStatus as S, Reason, ReasonCode as RC
from .config import DOMAIN_AGE, PHISHTANK, URLHAUS, VIRUSTOTAL, ThreatIntelConfig
from .service import ThreatIntelReport
from .types import ErrorCategory as E, FindingCategory as F, IndicatorType as T, LookupResult

CHECK = "threat_intel"
MAX_REASONS = 5


def _classify(r: LookupResult) -> Optional[tuple[str, RC, str]]:
    """-> (policy fact, reason code, plain-language text) for findings that matter."""
    if r.status is not S.FOUND:
        return None
    code_for = RC.HASH_ON_THREAT_LIST if r.indicator_type is T.SHA256 else RC.URL_ON_THREAT_LIST
    what = {T.URL: "this link", T.SHA256: "this attachment (by file hash)",
            T.DOMAIN: f"the domain {r.indicator_ref}"}[r.indicator_type]
    if r.indicator_type is T.URL and r.omitted:
        what = f"the address of this link (its {' and '.join(r.omitted)} withheld)"
    d, c = r.details, r.category
    listed = {T.URL: "threat_intel.url_listed", T.SHA256: "threat_intel.hash_listed",
              T.DOMAIN: "threat_intel.domain_listed"}[r.indicator_type]

    if r.provider == URLHAUS:
        if c is F.MALWARE_DISTRIBUTION:
            return listed, code_for, f"URLhaus lists {what} as distributing malware."
        if c is F.HOST_LISTED:
            return ("threat_intel.domain_listed", RC.URL_ON_THREAT_LIST,
                    f"URLhaus has recorded malware links hosted on {r.indicator_ref}.")
    if r.provider == PHISHTANK:
        if c is F.PHISHING_VERIFIED:
            return "threat_intel.url_listed", RC.URL_ON_THREAT_LIST, \
                f"PhishTank lists {what} as a verified phishing page."
        if c is F.PHISHING_UNVERIFIED:
            return "threat_intel.suspicious", RC.URL_ON_THREAT_LIST, \
                f"{what.capitalize()} was reported to PhishTank as phishing but is not yet verified."
    if r.provider == VIRUSTOTAL:
        mal, total = d.get("malicious"), d.get("vendors")
        if c is F.MALICIOUS:
            return listed, code_for, f"{mal} of {total} VirusTotal engines flag {what} as malicious."
        if c is F.SUSPICIOUS:
            return "threat_intel.suspicious", code_for, \
                f"Several VirusTotal engines ({mal} malicious of {total}) flag {what}."
    if r.provider == DOMAIN_AGE and c is F.RECENTLY_REGISTERED:
        return ("threat_intel.new_domain", RC.NEW_DOMAIN,
                f"The domain {r.indicator_ref} was registered only {d.get('age_days')} days ago.")
    return None


def _describe(r: LookupResult) -> str:
    if r.status is S.NOT_CHECKED:
        base = f"{r.error.value if r.error else 'not_checked'}"
        return f"{base}: {r.error_detail}" if r.error_detail else base
    bits = [r.category.value] + [f"{k}={v}" for k, v in sorted(r.details.items()) if v is not None]
    if r.status is S.NOT_FOUND:
        bits.append("provider has no relevant listing (this is not a safety verdict)")
    if r.omitted:
        bits.append(f"scope: only host and path were looked up; the {' and '.join(r.omitted)} "
                    f"were withheld, so this does not cover the full URL")
    if r.cache_hit:
        bits.append("cached")
    return "; ".join(bits)


def build_check_result(report: ThreatIntelReport, cfg: ThreatIntelConfig,
                       now: Optional[datetime] = None) -> CheckResult:
    now = now or report.now
    res = CheckResult(CHECK, completed=False)
    n = 0
    seen_reasons: set = set()

    def add(type_: str, value: str, source: str, status: S, detail: str, at=None) -> str:
        nonlocal n
        n += 1
        eid = f"{CHECK}-{n}"
        res.evidence.append(Evidence(
            evidence_id=eid, type=type_, value=_safe(value), source=source, status=status,
            observed_at=at or now, detail=_safe(detail, 300) or None,
        ))
        return eid

    blocked: dict[str, list[LookupResult]] = defaultdict(list)
    for r in report.results:
        if r.error is E.PRIVACY_BLOCKED:
            blocked[r.indicator_ref].append(r)
            continue
        if r.provider == "coverage":
            type_, source = "threat_intel_coverage", "threat_intel:coverage"
        else:
            type_ = "domain_age" if r.provider == DOMAIN_AGE else f"threat_intel_{r.indicator_type.value}"
            source = f"threat_intel:{r.provider}"
        hit = _classify(r)
        note = ""
        if (hit and r.indicator_type is T.DOMAIN and r.provider != DOMAIN_AGE
                and r.indicator_ref in cfg.shared_host_domains):
            hit, note = None, "; host-level finding ignored: large shared hosting platform"
        eid = add(type_, r.indicator_ref, source, r.status, _describe(r) + note, at=r.looked_up_at)
        if hit and len(res.reasons) < MAX_REASONS:
            fact, code, text = hit
            res.facts.add(fact)
            if (code, text) not in seen_reasons:
                seen_reasons.add((code, text))
                res.reasons.append(Reason(code=code, text=text, evidence_ids=[eid]))
        elif hit:
            res.facts.add(hit[0])

    # A lookup that really happened on a stripped target says nothing about the original
    # full URL. Record that explicitly: the full-URL check is NOT_CHECKED, never implied clean.
    answered = {r.indicator_ref for r in report.results if r.conclusive}
    for ref, omitted in report.omitted.items():
        if ref in answered:
            add("threat_intel_full_url", ref, "threat_intel:scope", S.NOT_CHECKED,
                f"scope: the {' and '.join(omitted)} of this URL were withheld for privacy and "
                f"never sent; providers were asked about host and path only, so the full URL "
                f"was not checked.")

    for ref, rs in blocked.items():
        provs = ", ".join(sorted({r.provider for r in rs}))
        add(f"threat_intel_{rs[0].indicator_type.value}", ref, "threat_intel:privacy_gate",
            S.NOT_CHECKED, f"privacy_blocked: {rs[0].error_detail}. Not sent to: {provs}.",
            at=rs[0].looked_up_at)

    for prov, why in sorted(report.disabled.items()):
        add("threat_intel_provider", prov, f"threat_intel:{prov}", S.NOT_CHECKED, f"disabled: {why}")

    if report.skipped_indicators:
        add("threat_intel_limit", f"{report.skipped_indicators} indicators", "threat_intel:limit",
            S.NOT_CHECKED, f"limit_exceeded: only the first {cfg.max_indicators_per_message} "
                           f"indicators per message are looked up.")

    # ---- completeness ----
    enabled_rep = bool(cfg.effective_providers & cfg.completeness_providers)
    rep = defaultdict(list)
    for r in report.results:
        if r.provider in cfg.completeness_providers:
            rep[r.indicator_ref].append(r)
    covered = all(rep.get(ref) and all(x.covers_original for x in rep[ref])
                  for ref, _ in report.indicators)
    res.completed = bool(enabled_rep and covered and not report.skipped_indicators
                         and not report.deadline_hit)

    if not report.indicators and not report.disabled and not report.skipped_indicators:
        add(CHECK, "no indicators", "threat_intel", S.NOT_FOUND,
            "The message has no URLs, domains or attachment hashes to look up.")
    if not res.evidence:
        add(CHECK, "not run", "threat_intel", S.NOT_CHECKED,
            "Threat intelligence is disabled or no provider could be used.")
    return res
