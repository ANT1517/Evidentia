"""Contract between the platform (app/) and the analysis engine (engine/).

Message content is attacker-controlled data: never execute, render or fetch it.
"""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class AttachmentMeta(BaseModel):
    """Metadata only. Attachments are never opened."""

    filename: str
    mime_type: str
    size: int
    sha256: str | None = None


class NormalizedMessage(BaseModel):
    """One message from any channel, in the shape the engine analyzes."""

    user_id: int
    channel: Literal["email", "sms", "whatsapp"]
    external_id: str
    sender: str
    sender_display_name: str | None = None
    reply_to: str | None = None
    subject: str | None = None
    body_text: str  # plain text; HTML is converted to text, never rendered
    urls: list[str]
    attachments: list[AttachmentMeta]
    # Auth-relevant headers only: Authentication-Results, Received-SPF,
    # DKIM-Signature (presence), From, Reply-To, Return-Path.
    headers: dict[str, list[str]]
    received_at: datetime


class Evidence(BaseModel):
    """One finding. status 'not_checked' means the check failed or was skipped, NOT safe."""

    evidence_id: str
    type: str
    value: str
    source: str
    observed_at: datetime
    status: Literal["found", "not_found", "not_checked"]


class Reason(BaseModel):
    """A plain-language reason (e.g. SPF_FAIL) pointing at evidence."""

    code: str
    text: str
    evidence_ids: list[str]


class Assessment(BaseModel):
    """Engine output for one message."""

    risk_band: Literal["LOW", "REVIEW", "URGENT", "INSUFFICIENT_DATA"]
    reasons: list[Reason]
    evidence: list[Evidence]
    data_completeness: Literal["COMPLETE", "PARTIAL", "UNKNOWN"]
    model_versions: dict[str, str]
    colleague_count: int = 0
