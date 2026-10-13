import logging
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api_models import HealthOut
from app.api import admin, auth, check, me, webhooks
from app.config import get_settings
from app.workers.gmail_poller import start_scheduler


class _RedactOAuth(logging.Filter):
    """uvicorn logs the full request path; keep OAuth codes and state out of the logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and len(record.args) >= 3 and isinstance(record.args[2], str):
            args = list(record.args)
            args[2] = re.sub(r"(code|state|scope)=[^&\s]+", r"\1=[redacted]", args[2])
            record.args = tuple(args)
        return True


logging.getLogger("uvicorn.access").addFilter(_RedactOAuth())


@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler = None if get_settings().DISABLE_SCHEDULER else start_scheduler()
    app.state.scheduler = scheduler
    yield
    if scheduler:
        scheduler.shutdown(wait=False)


app = FastAPI(title="Evedentia", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list({"http://localhost:5173", get_settings().FRONTEND_URL}),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=get_settings().SECRET_KEY)  # OAuth state only
for m in (auth, me, check, admin, webhooks):
    app.include_router(m.router)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    """Same {"detail": "..."} shape as every other error."""
    parts = []
    for e in exc.errors():
        loc = ".".join(str(x) for x in e.get("loc", ()) if x not in ("body", "query", "path"))
        parts.append(f"{loc}: {e['msg']}" if loc else str(e["msg"]))
    return JSONResponse({"detail": "; ".join(parts) or "invalid request"}, status_code=422)


@app.get("/health", tags=["system"], response_model=HealthOut)
def health():
    return {"status": "ok"}
