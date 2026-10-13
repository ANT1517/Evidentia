import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session
from twilio.request_validator import RequestValidator
from twilio.twiml.messaging_response import MessagingResponse

from app.api_models import Detail
from app.config import get_settings
from app.db import get_db
from app.models import TwilioEvent
from app.services import whatsapp as bot

log = logging.getLogger(__name__)
router = APIRouter(tags=["webhooks"])


class XMLResponse(Response):
    media_type = "application/xml"


def _twiml(text: str | None) -> Response:
    r = MessagingResponse()
    if text:
        r.message(text)
    return Response(str(r), media_type="application/xml")


def _handle(db: Session, from_number: str, sid: str, body: str, num_media: int):
    """One transaction: dedupe, find the employee, advance the conversation. A crash rolls back all of it,
    so Twilio's retry is processed normally."""
    # RETURNING, not rowcount: psycopg reports -1 for this statement
    first = db.execute(pg_insert(TwilioEvent).values(sid=sid).on_conflict_do_nothing()
                       .returning(TwilioEvent.sid)).first()
    if first is None:
        return bot.Reply(None), True
    user = bot.find_employee(db, from_number)
    if not user:
        db.commit()
        return bot.Reply(bot.UNKNOWN_NUMBER), False
    reply = bot.handle_message(db, user, from_number, sid, body, num_media)
    db.commit()
    return reply, False


@router.post("/webhooks/twilio/whatsapp", response_class=XMLResponse,
             responses={
                 200: {"description": "TwiML reply", "content": {"application/xml": {
                     "example": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Message>Checking...</Message></Response>"}}},
                 403: {"model": Detail}, 503: {"model": Detail}},
             summary="Twilio WhatsApp webhook (form-encoded, X-Twilio-Signature required)")
async def twilio_whatsapp(request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
    s = get_settings()
    if not (s.TWILIO_AUTH_TOKEN and s.TWILIO_ACCOUNT_SID and s.TWILIO_WHATSAPP_FROM):
        log.error("twilio webhook called but TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_WHATSAPP_FROM are not set")
        raise HTTPException(503, "WhatsApp bot is not configured")

    form = await request.form()
    params = {k: str(v) for k, v in form.items()}
    # ngrok rewrites the host, so sign-check against our public URL, not the one the request arrived on
    url = s.PUBLIC_BASE_URL.rstrip("/") + request.url.path + (f"?{request.url.query}" if request.url.query else "")
    sig = request.headers.get("X-Twilio-Signature", "")
    if not sig or not RequestValidator(s.TWILIO_AUTH_TOKEN).validate(url, params, sig):
        log.warning("twilio webhook rejected: bad or missing signature")
        raise HTTPException(403, "invalid signature")

    from_number, sid = params.get("From", ""), params.get("MessageSid", "")
    if not from_number or not sid:
        raise HTTPException(403, "invalid request")
    try:
        num_media = int(params.get("NumMedia") or 0)
    except ValueError:
        num_media = 0

    reply, duplicate = await run_in_threadpool(_handle, db, from_number, sid, params.get("Body", ""), num_media)
    if duplicate:
        log.info("twilio duplicate sid ignored from=***%s", bot.last4(from_number))
        return _twiml(None)
    if reply.job:
        background.add_task(reply.job)
    return _twiml(reply.text)
