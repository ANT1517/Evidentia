"""Security configuration for the rule checks and policy. Demo placeholders only.

Nothing here is real employee data. Rule logic lives in rules.py and policy.py and reads
everything environment-specific from an EngineConfig, so deployments override this file
(or build their own EngineConfig) without touching the rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schemas import IngestSource


@dataclass(frozen=True)
class Person:
    name: str
    role: str
    email: str
    executive: bool = False


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]          # registered domains the brand really sends from


@dataclass(frozen=True)
class EngineConfig:
    # --- protected identities -------------------------------------------------
    org_domains: tuple[str, ...] = ("ourcompany.example",)
    directory: tuple[Person, ...] = (
        Person("Alex Morgan", "CEO", "alex.morgan@ourcompany.example", executive=True),
        Person("Jordan Lee", "CFO", "jordan.lee@ourcompany.example", executive=True),
        Person("Priya Nair", "Finance Manager", "priya.nair@ourcompany.example"),
        Person("Sam Rivera", "IT Security Lead", "sam.rivera@ourcompany.example"),
    )
    brands: tuple[Brand, ...] = (
        Brand("Microsoft", ("microsoft.com", "office.com", "microsoftonline.com", "live.com")),
        Brand("Google", ("google.com", "gmail.com", "accounts.google.com")),
        Brand("PayPal", ("paypal.com",)),
        Brand("Amazon", ("amazon.com", "amazon.in")),
        Brand("SBI", ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in")),
        Brand("HDFC", ("hdfcbank.com", "hdfcbank.net")),
    )
    # Words in a display name that claim executive authority.
    executive_titles: tuple[str, ...] = (
        "ceo", "cfo", "coo", "cto", "cio", "ciso", "chief", "president", "chairman",
        "managing director",
    )

    # --- authentication trust -------------------------------------------------
    # Auth results count as verified only if the message came through one of these paths
    # AND the Authentication-Results authserv-id is one of ours. Uploaded .eml files are
    # excluded by default because anyone can forge those headers. Add EML_UPLOAD here only
    # for a demo, knowing that doing so lets a forged header be believed.
    trusted_ingest_sources: frozenset = frozenset({IngestSource.GMAIL_API})
    trusted_authserv_ids: frozenset = frozenset({"mx.google.com", "mx.ourcompany.example"})

    # --- attachments ----------------------------------------------------------
    executable_exts: frozenset = frozenset({
        "exe", "scr", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1",
        "msi", "jar", "hta", "lnk", "pif", "cpl", "dll", "reg", "chm", "apk",
    })
    macro_exts: frozenset = frozenset({
        "docm", "dotm", "xlsm", "xltm", "xlam", "xlsb", "pptm", "potm", "ppam", "sldm",
    })
    # Not executables, but common phishing carriers (HTML smuggling, disk images).
    risky_other_exts: frozenset = frozenset({"iso", "img", "vhd", "vhdx", "html", "htm", "svg"})
    decoy_exts: frozenset = frozenset({
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
        "jpg", "jpeg", "png", "gif",
    })
    executable_mime_types: frozenset = frozenset({
        "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
        "application/vnd.microsoft.portable-executable", "application/x-sh",
        "application/java-archive", "application/x-msi",
    })

    # --- policy ---------------------------------------------------------------
    active_profile: str = "rules_only"
    # Contextual combinations of rule facts that justify Urgent. Each is a heuristic, not
    # verified fact, and is reported as such. Edit here to tune.
    urgent_combinations: tuple[frozenset, ...] = (
        frozenset({"identity.exec_mismatch", "reply_to.mismatch"}),
        frozenset({"identity.brand_mismatch", "lookalike.domain"}),
    )

    # --- caps (keep ledgers small) ---------------------------------------------
    max_items_per_check: int = 5

    @property
    def protected_domains(self) -> tuple[str, ...]:
        return self.org_domains + tuple(d for b in self.brands for d in b.domains)

    @property
    def lookalike_targets(self) -> tuple[str, ...]:
        """Domains imitations are compared against: org domains and each brand's primary
        (first) domain. Secondary brand domains are legitimate but too generic to imitate-check."""
        return self.org_domains + tuple(b.domains[0] for b in self.brands if b.domains)


DEFAULT_CONFIG = EngineConfig()
