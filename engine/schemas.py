"""Shared contract between the platform (Shyamanth) and the analysis engine (Member B).

Change this file only by agreement: both sides code against it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Channel(str, Enum):
    EMAIL = "email"
    SMS = "sms"
    WHATSAPP = "whatsapp"


class IngestSource(str, Enum):
    """How the message reached the engine. Set by the platform, never by message content."""
    GMAIL_API = "gmail_api"        # fetched by our own Gmail OAuth poller
    EML_UPLOAD = "eml_upload"      # arbitrary user-supplied file: headers can be forged
    TWILIO = "twilio"
    UNKNOWN = "unknown"            # default: treated as untrusted


class RiskBand(str, Enum):
    URGENT = "urgent"
    REVIEW = "review"
    LOW = "low"
    INSUFFICIENT_DATA = "insufficient_data"


class EvidenceStatus(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    NOT_CHECKED = "not_checked"  # timeout, missing header, skipped: never treated as clean


class ReasonCode(str, Enum):
    REPLY_TO_MISMATCH = "REPLY_TO_MISMATCH"
    SPF_FAIL = "SPF_FAIL"
    DKIM_FAIL = "DKIM_FAIL"
    DMARC_FAIL = "DMARC_FAIL"
    DISPLAY_NAME_SPOOF = "DISPLAY_NAME_SPOOF"
    LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN"
    RISKY_ATTACHMENT = "RISKY_ATTACHMENT"
    LINK_TEXT_MISMATCH = "LINK_TEXT_MISMATCH"
    URL_ON_THREAT_LIST = "URL_ON_THREAT_LIST"
    HASH_ON_THREAT_LIST = "HASH_ON_THREAT_LIST"
    NEW_DOMAIN = "NEW_DOMAIN"
    TEXT_MODEL_PHISHING = "TEXT_MODEL_PHISHING"
    SMS_MODEL_SCAM = "SMS_MODEL_SCAM"
    EXEC_IMPERSONATION = "EXEC_IMPERSONATION"
    PAYMENT_CHANGE_REQUEST = "PAYMENT_CHANGE_REQUEST"
    CREDENTIAL_REQUEST = "CREDENTIAL_REQUEST"
    URGENCY_CUE = "URGENCY_CUE"
    SECRECY_CUE = "SECRECY_CUE"
    UNOFFICIAL_SENDER_ID = "UNOFFICIAL_SENDER_ID"
    NEW_NUMBER_CLAIM = "NEW_NUMBER_CLAIM"
    CHECK_INCOMPLETE = "CHECK_INCOMPLETE"


class Attachment(BaseModel):
    """Metadata only. Attachments are never opened."""
    filename: str
    content_type: str = ""
    size: int = 0
    sha256: Optional[str] = None


class AuthResults(BaseModel):
    """SPF/DKIM/DMARC outcome from headers. None means the header was missing (not checked)."""
    spf: Optional[str] = None    # pass / fail / softfail / neutral / none ...
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    # authserv-id of the Authentication-Results header the values came from (None if the
    # values came from a fallback header such as Received-SPF, or no header existed).
    authserv_id: Optional[str] = None


class LinkMismatch(BaseModel):
    """A link whose visible text shows one domain but whose href points to another."""
    shown_domain: str
    href: str
    href_domain: str


class NormalizedMessage(BaseModel):
    """One message from any channel, already parsed safely."""
    external_id: str                       # Gmail message id / Twilio SID; unique per message
    channel: Channel
    user_id: Optional[int] = None          # employee who received / reported it
    sender: str = ""                       # email address, SMS sender ID, or phone number
    sender_display_name: str = ""
    reply_to: str = ""
    subject: str = ""
    body_text: str = ""                    # HTML already converted to text
    urls: list[str] = Field(default_factory=list)   # plain strings, never fetched
    attachments: list[Attachment] = Field(default_factory=list)
    link_mismatches: list[LinkMismatch] = Field(default_factory=list)
    auth: AuthResults = Field(default_factory=AuthResults)
    ingest_source: IngestSource = IngestSource.UNKNOWN
    received_at: datetime = Field(default_factory=_utcnow)


class Evidence(BaseModel):
    """One row of the evidence ledger."""
    evidence_id: str
    type: str                              # e.g. "spf", "url_lookup", "domain_age", "laya_answer"
    value: str                             # what was checked or observed
    source: str                            # e.g. "rules", "virustotal", "whois", "laya"
    status: EvidenceStatus
    observed_at: datetime = Field(default_factory=_utcnow)
    detail: Optional[str] = None           # short human-readable note


class Reason(BaseModel):
    code: ReasonCode
    text: str                              # plain-language sentence shown to the employee
    evidence_ids: list[str] = Field(default_factory=list)


class Assessment(BaseModel):
    external_id: str
    risk_band: RiskBand
    reasons: list[Reason] = Field(default_factory=list)       # ordered, most important first
    evidence: list[Evidence] = Field(default_factory=list)
    data_completeness: str = "complete"    # "complete" | "partial" | "none"
    model_versions: dict[str, str] = Field(default_factory=dict)
    policy_version: str = "0"
    analysis_profile: Optional[str] = None     # e.g. "rules_only": which checks were required
    policy_rules: list[str] = Field(default_factory=list)   # ids of policy rules that fired
    created_at: datetime = Field(default_factory=_utcnow)
