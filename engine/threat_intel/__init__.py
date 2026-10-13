"""Threat-intelligence adapters: VirusTotal, URLhaus, PhishTank, RDAP domain age.

Everything is disabled and deny-by-default until an operator configures it.
See service.py for the execution model and runtime.py for the process-local caveats.
"""
from .config import DEFAULT_TI_CONFIG, SharingPolicy, ThreatIntelConfig
from .evidence import build_check_result
from .http import HttpRequest, HttpResponse, StdlibTransport, TransportError
from .runtime import Clock, InMemoryTTLCache, RateLimiter
from .service import TI_VERSION, ThreatIntelReport, ThreatIntelService
from .types import ErrorCategory, FindingCategory, Indicator, IndicatorType, LookupResult

__all__ = [
    "DEFAULT_TI_CONFIG", "SharingPolicy", "ThreatIntelConfig", "build_check_result",
    "HttpRequest", "HttpResponse", "StdlibTransport", "TransportError",
    "Clock", "InMemoryTTLCache", "RateLimiter", "TI_VERSION", "ThreatIntelReport",
    "ThreatIntelService", "ErrorCategory", "FindingCategory", "Indicator", "IndicatorType",
    "LookupResult",
]
