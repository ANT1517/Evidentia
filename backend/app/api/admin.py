import csv
import io
import re

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api_models import Detail, DirectoryList, ImportResult
from app.db import get_db
from app.deps import admin_user
from app.models import User
from app.services.directory import normalize_phone
from app.services.messages import decode_cursor, encode_cursor

router = APIRouter(tags=["admin"], dependencies=[Depends(admin_user)])
MAX_CSV = 1024 * 1024
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ADMIN = {401: {"model": Detail}, 403: {"model": Detail, "description": "Admins only"}}


@router.post("/admin/users/import", response_model=ImportResult,
             responses={**ADMIN, 400: {"model": Detail}, 413: {"model": Detail}},
             summary="Seed the employee directory from a CSV (name,title,email,phone); upserts by email")
async def import_users(file: UploadFile, db: Session = Depends(get_db)):
    raw = await file.read(MAX_CSV + 1)
    if len(raw) > MAX_CSV:
        raise HTTPException(413, "file too large (max 1 MB)")
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
        reader.fieldnames = [(h or "").strip().lower() for h in (reader.fieldnames or [])]
    except UnicodeDecodeError:
        raise HTTPException(400, "file must be UTF-8 CSV")
    if not {"name", "email"} <= set(reader.fieldnames):
        raise HTTPException(400, "CSV must have the columns: name,title,email,phone")

    created = updated = 0
    errors: list[dict] = []
    for i, row in enumerate(reader, start=2):  # row 1 is the header
        get = lambda k: (row.get(k) or "").strip()
        name, title, email, phone = get("name"), get("title"), get("email").lower(), get("phone")
        if not email or not _EMAIL.match(email):
            errors.append({"row": i, "error": "email is required" if not email else "invalid email"})
            continue
        if not name:
            errors.append({"row": i, "error": "name is required"})
            continue
        e164 = None
        if phone:
            e164 = normalize_phone(phone)
            if not e164:
                errors.append({"row": i, "error": "invalid phone number"})
                continue
        try:
            with db.begin_nested():  # a bad row rolls back alone
                u = db.scalar(select(User).where(func.lower(User.email) == email))
                is_new = u is None
                if is_new:
                    u = User(email=email, name=name)
                    db.add(u)
                u.name = name
                u.title = title or u.title
                u.phone = e164 or u.phone
                db.flush()
        except IntegrityError:
            errors.append({"row": i, "error": "phone number already belongs to another employee"})
            continue
        created, updated = created + is_new, updated + (not is_new)
    db.commit()
    return {"created": created, "updated": updated, "errors": errors}


@router.get("/admin/users", response_model=DirectoryList, responses=ADMIN, summary="List the employee directory")
def list_users(limit: int = Query(50, ge=1, le=100), cursor: str | None = None, db: Session = Depends(get_db)):
    q = select(User).order_by(User.id)
    if cursor:
        try:
            q = q.where(User.id > int(decode_cursor(cursor)[0]))
        except (ValueError, TypeError, IndexError):
            raise HTTPException(400, "invalid cursor")
    rows = list(db.scalars(q.limit(limit + 1)))
    page = rows[:limit]
    return {
        "items": [{"id": u.id, "name": u.name, "title": u.title, "email": u.email, "phone": u.phone,
                   "whatsapp_number": u.whatsapp_number, "gmail_connected": bool(u.gmail_refresh_token_enc),
                   "is_admin": u.is_admin} for u in page],
        "next_cursor": encode_cursor(page[-1].id) if len(rows) > limit else None,
    }
