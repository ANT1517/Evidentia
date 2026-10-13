"""Threat-intelligence orchestration for one message.

Order of gates for every (indicator, provider) pair:
  provider enabled -> privacy gate -> API key -> cache -> deadline -> local rate limit
  -> HTTP (bounded timeout, limited retries, origin-guarded, no redirects) -> validate

EXECUTION MODEL: `lookup_message` is SYNCHRONOUS and BLOCKING. Worst-case wall time is
bounded by `config.deadline_s`, but it must still never run on an asyncio event loop
thread. Call `analyze(...)` (or this method) from a worker thread / process pool, e.g.
`await asyncio.to_thread(analyze, msg, threat_intel=service)` or a background task queue.
The service is thread-safe; cache and rate limiter are process-local (see runtime.py).
"""
from __future__ import annotations

import dataclasses
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from ..domains import email_domain
from ..schemas import EvidenceStatus as S, NormalizedMessage
from .config import DEFAULT_TI_CONFIG, RATE_LIMIT_BASIS, ThreatIntelConfig, VIRUSTOTAL
from .http import GuardedClient, HttpResponse, OriginNotAllowed, StdlibTransport, Transport, TransportError
from .privacy import audit_policy, check_sharing, normalize_domain, normalize_sha256, normalize_url
from .providers import Provider, default_providers
from .runtime import Cache, Clock, InMemoryTTLCache, RateLimiter, cache_key
from .types import (
    ErrorCategory as E,
    FindingCategory as F,
    Indicator,
    IndicatorType,
    LookupResult,
    ProviderError,
)

log = logging.getLogger("engine.threat_intel")
TI_VERSION = "0.1.1"


@dataclass
class ThreatIntelReport:
    results: list[LookupResult] = field(default_factory=list)
    disabled: dict[str, str] = field(default_factory=dict)   # provider -> why it did not run
    indicators_total: int = 0
    skipped_indicators: int = 0                               # over the per-message cap
    indicators: list[tuple[str, IndicatorType]] = field(default_factory=list)  # (ref, type) checked
    omitted: dict = field(default_factory=dict)               # ref -> URL parts never looked up
    deadline_hit: bool = False
    now: Optional[datetime] = None


class ThreatIntelService:
    def __init__(
        self,
        config: ThreatIntelConfig = DEFAULT_TI_CONFIG,
        *,
        transport: Optional[Transport] = None,
        cache: Optional[Cache] = None,
        clock: Optional[Clock] = None,
        key_provider: Optional[Callable[[str], Optional[str]]] = None,
        limiter: Optional[RateLimiter] = None,
        providers: Optional[list[Provider]] = None,
    ) -> None:
        problems = audit_policy(config.sharing)
        if problems:        # fail closed: never start with an approval list that over-authorises
            raise ValueError("unsafe sharing policy: " + "; ".join(problems))
        self.cfg = config
        self.clock = clock or Clock()
        self._client = GuardedClient(
            transport or StdlibTransport(), config.allowed_origins, config.max_response_bytes
        )
        self._cache = cache if cache is not None else InMemoryTTLCache(self.clock)
        self._limiter = limiter or RateLimiter(self.clock, config.rate_limits)
        self._keys = key_provider or (lambda name: os.environ.get(name))
        self._providers = providers if providers is not None else default_providers()

    # ------------------------------------------------------------------ indicators

    def collect_indicators(self, msg: NormalizedMessage) -> list[Indicator]:
        """Unique, normalised indicators in a fixed priority order: hashes, URLs, domains.

        Forms that normalise to the same target are merged into one lookup. The merged
        indicator keeps the UNION of the flags, so if any original form had a query string or
        fragment the result is treated as partial (conservative).
        """
        groups: dict[str, dict] = {"hash": {}, "url": {}, "domain": {}}

        def add(kind: str, ind: Optional[Indicator]) -> None:
            if ind is None:
                return
            key = (ind.type, ind.value)
            old = groups[kind].get(key)
            groups[kind][key] = (
                ind if old is None
                else dataclasses.replace(old, flags=old.flags | ind.flags)
            )

        for a in msg.attachments:
            if a.sha256:
                add("hash", normalize_sha256(a.sha256))
        for u in msg.urls:
            ind = normalize_url(u)
            add("url", ind)
            if ind is not None:
                add("domain", normalize_domain(_host(ind)))
        for addr in (msg.sender, msg.reply_to):
            if addr:
                add("domain", normalize_domain(email_domain(addr)))
        return [i for kind in ("hash", "url", "domain") for i in groups[kind].values()]

    # ------------------------------------------------------------------ lookup

    def lookup_message(
        self,
        msg: NormalizedMessage,
        *,
        denied_domains: frozenset = frozenset(),
        now: Optional[datetime] = None,
    ) -> ThreatIntelReport:
        return self.lookup_indicators(
            self.collect_indicators(msg), denied_domains=denied_domains, now=now
        )

    def lookup_indicators(
        self,
        everything: list,
        *,
        denied_domains: frozenset = frozenset(),
        now: Optional[datetime] = None,
    ) -> ThreatIntelReport:
        """Look up already-normalised indicators (used by lookup_message and the smoke test)."""
        started = self.clock.monotonic()
        deadline_at = started + self.cfg.deadline_s
        now = now or self.clock.now()
        policy = dataclasses.replace(
            self.cfg.sharing, denied_domains=self.cfg.sharing.denied_domains | denied_domains
        )
        report = ThreatIntelReport(now=now)
        report.indicators_total = len(everything)
        chosen = everything[: self.cfg.max_indicators_per_message]
        report.skipped_indicators = len(everything) - len(chosen)
        report.indicators = [(i.ref, i.type) for i in chosen]
        report.omitted = {i.ref: i.omitted for i in chosen if i.omitted}

        for ind in chosen:
            covering = [
                p for p in self._providers
                if ind.type in p.supported and p.name in self.cfg.completeness_providers
                and p.name in self.cfg.effective_providers
            ]
            reputation_active = bool(self.cfg.effective_providers & self.cfg.completeness_providers)
            if reputation_active and not covering:
                # Some reputation provider is on, but none can answer for this indicator
                # type. Say so explicitly: silence would look like "nothing to check".
                report.results.append(LookupResult(
                    provider="coverage", indicator_type=ind.type, indicator_ref=ind.ref,
                    status=S.NOT_CHECKED, category=F.NOT_AVAILABLE, looked_up_at=now,
                    error=E.NO_COVERAGE, omitted=ind.omitted,
                    error_detail=f"no enabled reputation provider supports {ind.type.value} indicators",
                ))
            for prov in self._providers:
                if ind.type not in prov.supported:
                    continue
                if not self.cfg.provider_enabled(prov.name):
                    report.disabled.setdefault(prov.name, "provider is not enabled")
                    continue
                if prov.name == VIRUSTOTAL and not self.cfg.virustotal_live_enabled:
                    report.disabled.setdefault(prov.name, "VirusTotal live lookups are switched off")
                    continue
                res = self._lookup_one(ind, prov, policy, deadline_at, now)
                if res.error is E.DEADLINE_EXCEEDED:
                    report.deadline_hit = True
                report.results.append(res)
                log.info(
                    "lookup provider=%s type=%s ref=%s status=%s error=%s cache=%s",
                    res.provider, res.indicator_type.value, res.indicator_ref,
                    res.status.value, res.error.value if res.error else "-", res.cache_hit,
                )
        return report

    # ------------------------------------------------------------------ one pair

    def _lookup_one(self, ind, prov, policy, deadline_at, now) -> LookupResult:
        def fail(err: E, detail: str = "") -> LookupResult:
            return LookupResult(
                provider=prov.name, indicator_type=ind.type, indicator_ref=ind.ref,
                status=S.NOT_CHECKED, category=F.NOT_AVAILABLE, looked_up_at=now,
                error=err, error_detail=detail[:200], omitted=ind.omitted,
            )

        reason = check_sharing(ind, policy)
        if reason:
            return fail(E.PRIVACY_BLOCKED, reason)

        key = None
        if prov.key_env_attr:
            env = getattr(self.cfg, prov.key_env_attr)
            key = (self._keys(env) or "").strip() or None
            if prov.key_required and not key:
                return fail(E.NO_API_KEY, f"environment variable {env} is not set")

        ck = cache_key(prov.name, ind)
        hit = self._cache.get(ck)
        if hit is not None:
            return dataclasses.replace(hit, cache_hit=True, omitted=ind.omitted)

        try:
            req = prov.build_request(ind, key, self.cfg)
        except ProviderError as e:
            return fail(e.category, e.detail)

        last: Optional[LookupResult] = None
        for attempt in range(self.cfg.max_retries + 1):
            remaining = deadline_at - self.clock.monotonic()
            if remaining <= 0:
                return last or fail(E.DEADLINE_EXCEEDED, "per-message lookup deadline reached")
            if not self._limiter.try_acquire(prov.name):
                return last or fail(
                    E.RATE_LIMITED,
                    f"local request budget exhausted ({RATE_LIMIT_BASIS.get(prov.name, 'configured budget')})",
                )

            retryable = False
            try:
                resp = self._client.send(req, timeout=min(self.cfg.timeout_s, remaining))
            except OriginNotAllowed as e:
                return fail(E.NETWORK_ERROR, str(e))
            except TransportError as e:
                retryable = True
                last = fail(E.TIMEOUT if e.kind == "timeout" else E.NETWORK_ERROR, e.kind)
            else:
                outcome_or_err = self._handle(prov, ind, resp, now)
                if isinstance(outcome_or_err, LookupResult):
                    last = outcome_or_err
                    retryable = outcome_or_err.error is E.SERVER_ERROR
                    if not retryable:
                        return last
                else:
                    result = LookupResult(
                        provider=prov.name, indicator_type=ind.type, indicator_ref=ind.ref,
                        status=outcome_or_err.status, category=outcome_or_err.category,
                        looked_up_at=now, details=dict(outcome_or_err.details),
                        omitted=ind.omitted,
                    )
                    if result.conclusive:       # only conclusive results are ever cached
                        ttl = (self.cfg.ttl_found_s if result.status is S.FOUND
                               else self.cfg.ttl_not_found_s)
                        self._cache.set(ck, result, ttl)
                    return result

            if attempt < self.cfg.max_retries and retryable:
                self.clock.sleep(min(self.cfg.retry_backoff_s, max(0.0, remaining)))
                continue
            return last  # type: ignore[return-value]
        return last or fail(E.UNKNOWN_FORMAT)

    def _handle(self, prov: Provider, ind: Indicator, resp: HttpResponse, now: datetime):
        """-> Outcome on success, or a NOT_CHECKED LookupResult describing the failure."""
        def fail(err: E, detail: str = "") -> LookupResult:
            return LookupResult(
                provider=prov.name, indicator_type=ind.type, indicator_ref=ind.ref,
                status=S.NOT_CHECKED, category=F.NOT_AVAILABLE, looked_up_at=now,
                error=err, error_detail=detail, omitted=ind.omitted,
            )

        st = resp.status
        if st in prov.rate_limit_statuses:
            return fail(E.PROVIDER_RATE_LIMITED, f"HTTP {st}")
        if st in (401, 403):
            return fail(E.AUTH_FAILED, f"HTTP {st}")
        if 300 <= st < 400:
            return fail(E.REDIRECT_REFUSED, f"HTTP {st}; redirects are never followed")
        if st >= 500:
            return fail(E.SERVER_ERROR, f"HTTP {st}")
        if st == 400:
            return fail(E.INVALID_INDICATOR, "HTTP 400")
        if st not in prov.handled_statuses:
            return fail(E.UNKNOWN_FORMAT, f"unexpected HTTP {st}")
        try:
            return prov.interpret(ind, resp, now, self.cfg)
        except ProviderError as e:
            return fail(e.category, e.detail)


def _host(ind: Indicator) -> str:
    from urllib.parse import urlsplit
    return urlsplit(ind.value).hostname or ""
