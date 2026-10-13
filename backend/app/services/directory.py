"""Employee directory lookups (used by the engine for sender-ID / impersonation checks)."""
import phonenumbers
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import User


def normalize_phone(phone: str, region: str = "IN") -> str | None:
    """Return E.164 or None if unparseable."""
    try:
        n = phonenumbers.parse(phone, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_possible_number(n):
        return None
    return phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)


def find_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.email) == email.strip().lower()))


def find_by_phone(db: Session, phone: str) -> User | None:
    e164 = normalize_phone(phone)
    if not e164:
        return None
    return db.scalar(select(User).where((User.phone == e164) | (User.whatsapp_number == e164)))


def find_by_name(db: Session, name: str) -> list[User]:
    pat = f"%{name.strip().lower()}%"
    return list(db.scalars(select(User).where(func.lower(User.name).like(pat))))
