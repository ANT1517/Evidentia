"""Request/response models for the employee web app (these drive /docs)."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from shared.schemas import Evidence, Reason

Band = Literal["LOW", "REVIEW", "URGENT", "INSUFFICIENT_DATA"]
Channel = Literal["email", "sms", "whatsapp"]
Source = Literal["gmail", "check", "whatsapp"]


class Detail(BaseModel):
    """Every error response has this shape."""
    detail: str

    model_config = ConfigDict(json_schema_extra={"examples": [{"detail": "message not found"}]})


class MeOut(BaseModel):
    id: int
    name: str
    email: str
    title: str | None
    gmail_connected: bool
    whatsapp_number: str | None

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "id": 1, "name": "Asha Rao", "email": "asha@corp.com", "title": "Accountant",
        "gmail_connected": True, "whatsapp_number": "+919876543210"}]})


class MePatch(BaseModel):
    whatsapp_number: str | None = Field(None, description="Any format; stored as E.164. null or empty clears it.")

    model_config = ConfigDict(json_schema_extra={"examples": [{"whatsapp_number": "98765 43210"}]})


class ScanOut(BaseModel):
    new_messages: int

    model_config = ConfigDict(json_schema_extra={"examples": [{"new_messages": 3}]})


class MessageItem(BaseModel):
    id: int
    channel: Channel
    source: Source
    sender: str
    sender_display_name: str | None
    preview: str = Field(description="Subject, else first 120 chars of the body, else \"Couldn't read this email\"")
    received_at: datetime
    risk_band: Band
    top_reason: str | None = Field(description="Text of the first reason, if any")
    colleague_count: int
    escalated: bool
    readable: bool = Field(description="false for placeholder messages we could not parse")

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "id": 42, "channel": "email", "source": "gmail", "sender": "helpdesk@c0rp-support.com",
        "sender_display_name": "IT Helpdesk", "preview": "Password expires today",
        "received_at": "2026-10-13T09:00:00Z", "risk_band": "URGENT",
        "top_reason": "Asks for login or bank details.", "colleague_count": 2,
        "escalated": False, "readable": True}]})


class MessageList(BaseModel):
    items: list[MessageItem]
    next_cursor: str | None = Field(description="Pass as ?cursor= for the next page; null on the last page")

    model_config = ConfigDict(json_schema_extra={"examples": [{"items": [], "next_cursor": None}]})


class AttachmentOut(BaseModel):
    filename: str
    mime_type: str
    size: int
    sha256: str | None = None


class AssessmentOut(BaseModel):
    risk_band: Band
    reasons: list[Reason]
    evidence: list[Evidence]
    data_completeness: Literal["COMPLETE", "PARTIAL", "UNKNOWN"]
    model_versions: dict[str, str]
    colleague_count: int


class MessageDetail(BaseModel):
    """A message as plain text. Never HTML; URLs are plain strings, not links."""
    id: int
    channel: Channel
    source: Source
    sender: str
    sender_display_name: str | None
    reply_to: str | None
    subject: str | None
    body_text: str
    urls: list[str]
    attachments: list[AttachmentOut]
    received_at: datetime
    readable: bool
    assessment: AssessmentOut
    escalated_at: datetime | None
    feedback: Literal["fine"] | None
    what_to_do: list[str]

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "id": 42, "channel": "email", "source": "gmail", "sender": "helpdesk@c0rp-support.com",
        "sender_display_name": "IT Helpdesk", "reply_to": None, "subject": "Password expires today",
        "body_text": "Reset your password here: http://c0rp-support.com/reset",
        "urls": ["http://c0rp-support.com/reset"], "attachments": [],
        "received_at": "2026-10-13T09:00:00Z", "readable": True,
        "assessment": {
            "risk_band": "URGENT",
            "reasons": [{"code": "CREDENTIAL_REQUEST", "text": "Asks for login or bank details.",
                         "evidence_ids": ["ev-1"]}],
            "evidence": [{"evidence_id": "ev-1", "type": "keyword", "value": "CREDENTIAL_REQUEST",
                          "source": "stub", "observed_at": "2026-10-13T09:00:05Z", "status": "found"}],
            "data_completeness": "COMPLETE", "model_versions": {"engine": "stub"}, "colleague_count": 0},
        "escalated_at": None, "feedback": None,
        "what_to_do": ["Don't click any links", "Don't reply or send money", "Report this to IT"]}]})


class EscalateIn(BaseModel):
    note: str | None = Field(None, max_length=500)

    model_config = ConfigDict(json_schema_extra={"examples": [{"note": "Looks like the CEO but the address is off"}]})


class EscalationOut(BaseModel):
    id: int
    message_id: int
    sent_to: str
    sent_at: datetime
    employee_note: str | None

    model_config = ConfigDict(from_attributes=True, json_schema_extra={"examples": [{
        "id": 7, "message_id": 42, "sent_to": "security@corp.com",
        "sent_at": "2026-10-13T09:05:00Z", "employee_note": None}]})


class FeedbackIn(BaseModel):
    verdict: Literal["fine"]

    model_config = ConfigDict(json_schema_extra={"examples": [{"verdict": "fine"}]})


class FeedbackOut(BaseModel):
    message_id: int
    verdict: Literal["fine"]

    model_config = ConfigDict(json_schema_extra={"examples": [{"message_id": 42, "verdict": "fine"}]})


class CheckText(BaseModel):
    """JSON body of POST /check for a pasted SMS or WhatsApp message."""
    channel: Literal["sms", "whatsapp"]
    sender: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=5000)

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "channel": "sms", "sender": "+91 98765 43210",
        "text": "Your KYC expires today. Update now: http://sbi-kyc.example.com"}]})


class ImportRowError(BaseModel):
    row: int = Field(description="Spreadsheet row number (header is row 1)")
    error: str


class ImportResult(BaseModel):
    created: int
    updated: int
    errors: list[ImportRowError]

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "created": 8, "updated": 2, "errors": [{"row": 5, "error": "invalid phone number"}]}]})


class DirectoryUser(BaseModel):
    id: int
    name: str
    title: str | None
    email: str
    phone: str | None
    whatsapp_number: str | None
    gmail_connected: bool
    is_admin: bool

    model_config = ConfigDict(json_schema_extra={"examples": [{
        "id": 1, "name": "Asha Rao", "title": "Accountant", "email": "asha@corp.com",
        "phone": "+919876543210", "whatsapp_number": None, "gmail_connected": True, "is_admin": False}]})


class DirectoryList(BaseModel):
    items: list[DirectoryUser]
    next_cursor: str | None

    model_config = ConfigDict(json_schema_extra={"examples": [{"items": [{
        "id": 1, "name": "Asha Rao", "title": "Accountant", "email": "asha@corp.com", "phone": "+919876543210",
        "whatsapp_number": None, "gmail_connected": True, "is_admin": False}], "next_cursor": None}]})


class OkOut(BaseModel):
    ok: bool

    model_config = ConfigDict(json_schema_extra={"examples": [{"ok": True}]})


class DisconnectOut(BaseModel):
    gmail_connected: bool

    model_config = ConfigDict(json_schema_extra={"examples": [{"gmail_connected": False}]})


class HealthOut(BaseModel):
    status: str

    model_config = ConfigDict(json_schema_extra={"examples": [{"status": "ok"}]})
