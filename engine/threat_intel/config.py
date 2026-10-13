"""Threat-intelligence configuration. Everything is OFF by default.

API keys are NOT stored here: they are read from the environment at lookup time
(VIRUSTOTAL_API_KEY, URLHAUS_AUTH_KEY, PHISHTANK_APP_KEY) and never appear in a config repr.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Optional
from urllib.parse import urlsplit

from ..domains import is_ip

# Provider names are used in evidence `source` ("threat_intel:<name>") and as config keys.
VIRUSTOTAL = "virustotal"
URLHAUS = "urlhaus"
PHISHTANK = "phishtank"
DOMAIN_AGE = "domain_age"
ALL_PROVIDERS = (URLHAUS, PHISHTANK, VIRUSTOTAL, DOMAIN_AGE)   # lookup order: scarce quota last

# RDAP servers per TLD, copied from the IANA bootstrap file (data.iana.org/rdap/dns.json,
# published 2026-09-30). Hard-coded on purpose: requests may only go to configured origins
# and must never follow a redirect, so the redirect-based rdap.org aggregator is not used.
# TLDs absent here simply give NOT_CHECKED("no RDAP server configured").
_RDAP = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "in": "https://rdap.nixiregistry.in/rdap/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "biz": "https://rdap.nic.biz/",
    "xyz": "https://rdap.centralnic.com/xyz/",
    "online": "https://rdap.radix.host/rdap/",
    "site": "https://rdap.radix.host/rdap/",
    "top": "https://rdap.zdnsgtld.com/top/",
    "uk": "https://rdap.nominet.uk/uk/",
    "app": "https://pubapi.registry.google/rdap/",
    "dev": "https://pubapi.registry.google/rdap/",
}


def usable_rdap_base(value) -> Optional[str]:
    """First https:// RDAP base URL in `value` (a str or a list of str), else None.

    IANA's bootstrap lists http:// alternatives and some TLDs have none over https. Anything
    that is not plain https, carries credentials/query/fragment, or is an IP literal is
    unusable: the TLD then yields NOT_CHECKED rather than an insecure or redirected request.
    """
    candidates = [value] if isinstance(value, str) else list(value or ())
    for c in candidates:
        try:
            p = urlsplit(str(c))
        except ValueError:
            continue
        if (p.scheme == "https" and p.hostname and not is_ip(p.hostname)
                and not p.username and not p.password and not p.query and not p.fragment):
            return c if c.endswith("/") else c + "/"
    return None


def rdap_servers_from_bootstrap(doc: Mapping) -> dict:
    """Convert an IANA dns.json document into {tld: https base URL}, dropping TLDs that have
    no usable https endpoint. Offline helper for operators refreshing the snapshot; the
    engine itself never fetches the bootstrap file."""
    out: dict = {}
    for svc in doc.get("services", []) if isinstance(doc, Mapping) else []:
        if not (isinstance(svc, (list, tuple)) and len(svc) == 2):
            continue
        tlds, urls = svc
        base = usable_rdap_base(urls)
        if base:
            for t in tlds:
                out[str(t).lower()] = base
    return out


# What each local request budget is based on. Only VirusTotal's is a provider-published quota.
RATE_LIMIT_BASIS = MappingProxyType({
    "virustotal": "documented VirusTotal public API quota (4/min, 500/day, non-commercial)",
    "urlhaus": "application-side safety budget; URLhaus documents no numeric limit",
    "phishtank": "application-side safety budget; PhishTank documents only that limits exist",
    "domain_age": "application-side safety budget; RDAP servers set their own limits",
})

# (name, default, calibrated_against_data, note). Nothing here is evidence-calibrated: there is
# no labelled data yet. Kept next to the config so the table cannot drift (a test compares).
THRESHOLD_REGISTRY = (
    ("vt_urgent_min", 5, False, "VT malicious engines for a strong (Urgent) listing; provisional"),
    ("vt_review_min", 2, False, "VT engines for a Review signal; provisional"),
    ("new_domain_days", 30, False, "domain age below which it counts as new; common heuristic"),
    ("ttl_found_s", 21_600, False, "cache lifetime for listings; operational choice"),
    ("ttl_not_found_s", 3_600, False, "cache lifetime for no-listing results; operational choice"),
    ("deadline_s", 15.0, False, "per-message lookup budget; operational choice"),
    ("max_indicators_per_message", 10, False, "lookup cap; operational choice"),
)


@dataclass(frozen=True)
class SharingPolicy:
    """What may leave this process. Deny by default: an empty policy shares nothing.

    Approvals are exact matches written by an operator in server-side configuration.
    Nothing is approved because it "looks public". Use public, explicitly shareable test
    indicators for the demo.
    """
    approved_domains: frozenset = frozenset()   # registered domains; allow DOMAIN lookups only
    approved_urls: frozenset = frozenset()      # exact normalised URLs (no query/fragment)
    approved_sha256: frozenset = frozenset()    # exact lower-case hex digests
    denied_domains: frozenset = frozenset()     # always refused, even if also approved
    # Approved URLs whose path or host looks like it embeds a token or identifier. They are
    # refused unless an operator lists them here too, after confirming they are public (for
    # example a known phishing URL with a random path). Credentials are never overridable.
    reviewed_token_like_urls: frozenset = frozenset()


@dataclass(frozen=True)
class ThreatIntelConfig:
    enabled: bool = False
    enabled_providers: frozenset = frozenset()
    # Second, independent switch: VirusTotal retains and may scan what it is sent, and has a
    # tiny public quota. Needs "virustotal" in enabled_providers AND this flag AND a key.
    virustotal_live_enabled: bool = False
    sharing: SharingPolicy = SharingPolicy()

    # --- endpoints (origins are the ONLY hosts the engine will contact) ---
    virustotal_origin: str = "https://www.virustotal.com"
    urlhaus_origin: str = "https://urlhaus-api.abuse.ch"
    phishtank_origin: str = "https://checkurl.phishtank.com"
    rdap_servers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType(dict(_RDAP)))
    phishtank_user_agent: str = "phishtank/phishing-engine"

    # --- key environment variables ---
    virustotal_key_env: str = "VIRUSTOTAL_API_KEY"
    urlhaus_key_env: str = "URLHAUS_AUTH_KEY"
    phishtank_key_env: str = "PHISHTANK_APP_KEY"

    # --- performance and limits ---
    timeout_s: float = 5.0              # per HTTP request
    max_retries: int = 1                # extra attempts for timeout / network / 5xx only
    retry_backoff_s: float = 0.5
    deadline_s: float = 15.0            # total wall time budget for one message
    max_indicators_per_message: int = 10
    max_response_bytes: int = 1_048_576

    # --- cache (process-local) ---
    ttl_found_s: int = 6 * 3600
    ttl_not_found_s: int = 3600

    # (max_requests, window_seconds) windows per provider, process-local, configurable.
    # Only VirusTotal's values are a provider-published quota. The URLhaus, PhishTank and RDAP
    # values are application-side safety budgets chosen by us, NOT verified provider quotas;
    # see RATE_LIMIT_BASIS. Raising them does not raise the provider's real limit.
    rate_limits: Mapping[str, tuple] = field(default_factory=lambda: MappingProxyType({
        VIRUSTOTAL: ((4, 60), (500, 86_400)),
        URLHAUS: ((30, 60),),
        PHISHTANK: ((10, 60),),
        DOMAIN_AGE: ((20, 60),),
    }))

    # --- how provider findings are normalised (untuned: no labelled data yet) ---
    vt_urgent_min: int = 5              # VT "malicious" engines needed for a strong listing
    vt_review_min: int = 2              # engines needed for a Review-level signal
    new_domain_days: int = 30
    # Providers whose inconclusive result makes the threat_intel check incomplete. Domain age
    # is a weak signal and is excluded so a missing RDAP server cannot block everything.
    completeness_providers: frozenset = frozenset({URLHAUS, PHISHTANK, VIRUSTOTAL})
    # Large legitimate hosting platforms. Host-level reputation (URLhaus host listing, VT domain
    # detections) is not informative for them because they always carry some bad content, so
    # those findings are kept as evidence but raise no signal. URL- and hash-level findings
    # are unaffected. Provisional.
    shared_host_domains: frozenset = frozenset({
        "github.com", "githubusercontent.com", "dropbox.com", "google.com",
        "googleusercontent.com", "microsoft.com", "sharepoint.com", "live.com",
        "amazonaws.com", "cloudfront.net", "wetransfer.com", "box.com",
    })

    def provider_enabled(self, name: str) -> bool:
        return self.enabled and name in self.enabled_providers

    @property
    def effective_providers(self) -> frozenset:
        """Providers that can actually run (VirusTotal also needs its live switch)."""
        if not self.enabled:
            return frozenset()
        return frozenset(p for p in self.enabled_providers
                         if p != VIRUSTOTAL or self.virustotal_live_enabled)

    def origin_of(self, provider: str) -> str:
        return {
            VIRUSTOTAL: self.virustotal_origin,
            URLHAUS: self.urlhaus_origin,
            PHISHTANK: self.phishtank_origin,
        }[provider]

    @property
    def allowed_origins(self) -> frozenset:
        rdap = set()
        for v in self.rdap_servers.values():
            base = usable_rdap_base(v)
            if base:
                rdap.add("https://" + urlsplit(base).netloc)       # https origins only
        return frozenset({self.virustotal_origin, self.urlhaus_origin, self.phishtank_origin} | rdap)


DEFAULT_TI_CONFIG = ThreatIntelConfig()
