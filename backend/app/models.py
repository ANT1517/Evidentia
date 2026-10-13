from datetime import datetime

from sqlalchemy import (
    ARRAY, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _now():
    return mapped_column(DateTime(timezone=True), server_default=func.now())


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    title: Mapped[str | None] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True)
    phone: Mapped[str | None] = mapped_column(String, unique=True)  # E.164
    whatsapp_number: Mapped[str | None] = mapped_column(String, unique=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    gmail_refresh_token_enc: Mapped[str | None] = mapped_column(Text)
    gmail_connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        UniqueConstraint("user_id", "channel", "external_id"),
        Index("ix_messages_user_received", "user_id", "received_at"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    channel: Mapped[str] = mapped_column(String)
    external_id: Mapped[str] = mapped_column(String)
    sender: Mapped[str] = mapped_column(String)
    sender_display_name: Mapped[str | None] = mapped_column(String)
    reply_to: Mapped[str | None] = mapped_column(String)
    subject: Mapped[str | None] = mapped_column(String)
    body_text: Mapped[str] = mapped_column(Text)
    urls: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    attachments: Mapped[list] = mapped_column(JSONB, default=list)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String, default="gmail", server_default="gmail")  # gmail | check | whatsapp
    readable: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")  # false = placeholder
    created_at: Mapped[datetime] = _now()


class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"), index=True)
    risk_band: Mapped[str] = mapped_column(String)
    reasons: Mapped[list] = mapped_column(JSONB, default=list)
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    data_completeness: Mapped[str] = mapped_column(String)
    model_versions: Mapped[dict] = mapped_column(JSONB, default=dict)
    colleague_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = _now()


class Escalation(Base):
    __tablename__ = "escalations"
    __table_args__ = (UniqueConstraint("message_id"),)  # one escalation per message
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    sent_to: Mapped[str] = mapped_column(String)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    employee_note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()


class Feedback(Base):
    __tablename__ = "feedback"
    __table_args__ = (UniqueConstraint("user_id", "message_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    verdict: Mapped[str] = mapped_column(String)  # "fine"
    created_at: Mapped[datetime] = _now()


class Campaign(Base):
    __tablename__ = "campaigns"
    id: Mapped[int] = mapped_column(primary_key=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String, default="candidate")
    created_at: Mapped[datetime] = _now()


class CampaignLink(Base):
    __tablename__ = "campaign_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id"))
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"))
    link_type: Mapped[str] = mapped_column(String)
    shared_value: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = _now()


class PendingReport(Base):
    __tablename__ = "pending_reports"
    whatsapp_number: Mapped[str] = mapped_column(String, primary_key=True)
    message_text: Mapped[str] = mapped_column(Text)
    stage: Mapped[str] = mapped_column(String, default="awaiting_sender")
    message_sid: Mapped[str | None] = mapped_column(String)  # Twilio MessageSid of the original message
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    created_at: Mapped[datetime] = _now()


class TwilioEvent(Base):
    """MessageSids already handled, so Twilio retries never run a report twice."""
    __tablename__ = "twilio_events"
    sid: Mapped[str] = mapped_column(String, primary_key=True)
    created_at: Mapped[datetime] = _now()
