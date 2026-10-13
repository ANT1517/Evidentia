"""Provider-neutral types for threat-intelligence lookups.

Outcomes reuse the engine's EvidenceStatus; no second status system exists:

  FOUND        the provider returned a relevant listing or finding
  NOT_FOUND    the lookup succeeded and returned no relevant listing.
               This NEVER means "safe": a provider may simply have no record.
  NOT_CHECKED  disabled, privacy-blocked, unavailable, rate-limited, invalid, timed out,
               or the response could not be understood
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Union
from urllib.parse import urlsplit

from ..schemas import EvidenceStatus


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    SHA256 = "sha256"


class FindingCategory(str, Enum):
    NONE = "none"                                  # lookup succeeded, nothing relevant
    MALICIOUS = "malicious"                        # strong listing (VirusTotal >= urgent threshold)
    SUSPICIOUS = "suspicious"                      # several detections, below the strong threshold
    LOW_CONFIDENCE = "low_confidence"              # a single detection: preserved, not acted on
    PHISHING_VERIFIED = "phishing_verified"        # PhishTank: verified and valid
    PHISHING_UNVERIFIED = "phishing_unverified"    # PhishTank: reported, not yet verified
    MALWARE_DISTRIBUTION = "malware_distribution"  # URLhaus URL / payload listing
    HOST_LISTED = "host_listed"                    # URLhaus knows malicious URLs on this host
    RECENTLY_REGISTERED = "recently_registered"    # domain younger than the configured limit
    REGISTRATION_KNOWN = "registration_known"      # age known, not recent
    NOT_AVAILABLE = "not_available"                # no conclusion could be drawn


class ErrorCategory(str, Enum):
    DISABLED = "disabled"
    NO_API_KEY = "no_api_key"
    PRIVACY_BLOCKED = "privacy_blocked"
    INVALID_INDICATOR = "invalid_indicator"
    RATE_LIMITED = "rate_limited_locally"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    AUTH_FAILED = "auth_failed"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    SERVER_ERROR = "server_error"
    REDIRECT_REFUSED = "redirect_refused"
    MALFORMED_RESPONSE = "malformed_response"
    UNKNOWN_FORMAT = "unknown_format"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    LIMIT_EXCEEDED = "limit_exceeded"
    NO_DATA = "no_data"
    NO_COVERAGE = "no_coverage"      # no enabled reputation provider supports this indicator type


Detail = Union[str, int, bool, None]


@dataclass(frozen=True)
class Indicator:
    """One thing we might look up.

    `value` is the normalised form: the only form that may be sent to a provider, and the
    cache key. `original` is what the message contained, kept only for correlation; it is
    never sent and never logged. Neither appears in repr(); use `ref` for display.
    """
    type: IndicatorType
    value: str = field(repr=False)
    original: str = field(default="", repr=False, compare=False)
    flags: frozenset = field(default_factory=frozenset, compare=False)

    @property
    def omitted(self) -> tuple:
        """URL components that were present in the message but are NOT part of the lookup
        target (and are never sent). Non-empty means any answer covers host and path only."""
        if self.type is not IndicatorType.URL:
            return ()
        return tuple(name for flag, name in (("had_query", "query"), ("had_fragment", "fragment"))
                     if flag in self.flags)

    @property
    def ref(self) -> str:
        """Redacted reference, safe for evidence rows and logs."""
        if self.type is IndicatorType.SHA256:
            return f"sha256:{self.value[:12]}..."
        if self.type is IndicatorType.DOMAIN:
            return self.value
        parts = urlsplit(self.value)
        fp = hashlib.sha256(self.value.encode()).hexdigest()[:8]
        return f"{parts.scheme}://{parts.netloc}/...[{fp}]"


@dataclass
class LookupResult:
    provider: str
    indicator_type: IndicatorType
    indicator_ref: str
    status: EvidenceStatus
    category: FindingCategory
    looked_up_at: datetime
    details: dict[str, Detail] = field(default_factory=dict)
    error: Optional[ErrorCategory] = None
    error_detail: str = ""
    cache_hit: bool = False
    # Components of the ORIGINAL URL left out of the lookup target. Set from the indicator on
    # every return (never cached), so a cached answer cannot inherit another message's scope.
    omitted: tuple = ()

    @property
    def conclusive(self) -> bool:
        """The provider gave a usable answer about the looked-up target (cacheable)."""
        return self.status in (EvidenceStatus.FOUND, EvidenceStatus.NOT_FOUND)

    @property
    def partial(self) -> bool:
        return bool(self.omitted)

    @property
    def covers_original(self) -> bool:
        """Conclusive AND about the whole indicator, not just a stripped part of it."""
        return self.conclusive and not self.omitted


@dataclass(frozen=True)
class Outcome:
    """What a provider concluded from a response, before the service stamps time and ref."""
    status: EvidenceStatus
    category: FindingCategory
    details: dict[str, Detail] = field(default_factory=dict)


class ProviderError(Exception):
    """Raised inside a provider when a lookup cannot yield a conclusion."""

    def __init__(self, category: ErrorCategory, detail: str = "") -> None:
        super().__init__(f"{category.value}: {detail}")
        self.category = category
        self.detail = detail
