from .base import Provider
from .domain_age import DomainAge
from .phishtank import PhishTank
from .urlhaus import URLhaus
from .virustotal import VirusTotal


def default_providers() -> list[Provider]:
    """Fixed order: scarce-quota VirusTotal last, so a deadline cuts it first."""
    return [URLhaus(), PhishTank(), VirusTotal(), DomainAge()]


__all__ = ["Provider", "DomainAge", "PhishTank", "URLhaus", "VirusTotal", "default_providers"]
