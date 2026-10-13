"""Check a replacement engine against the platform.

Run from the repo root after replacing the stubs in backend/engine/:
    docker compose exec backend python scripts/swap_check.py

It feeds every .eml in tests/fixtures/ through engine.parser.parse_mime, engine.analyze.analyze and
app.services.pipeline.process_message (the same path the Gmail poller and /check use), prints the band and reasons,
and removes everything it stored. Exit code 1 if the signatures are wrong or anything raised.
"""
import inspect
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import delete, select  # noqa: E402

from app.db import SessionLocal  # noqa: E402
from app.models import Assessment, Message, User  # noqa: E402
from app.services.pipeline import fallback, process_message  # noqa: E402
from engine.analyze import analyze  # noqa: E402
from engine.parser import parse_mime  # noqa: E402
from shared.schemas import Assessment as AssessmentSchema  # noqa: E402
from shared.schemas import NormalizedMessage  # noqa: E402

FIXTURES = sorted((Path(__file__).resolve().parent.parent / "tests" / "fixtures").glob("*.eml"))
EMAIL = "swap-check@swap.test"


def main() -> int:
    problems = 0
    if list(inspect.signature(parse_mime).parameters) != ["raw", "user_id", "external_id"]:
        print("FAIL parse_mime must be parse_mime(raw, user_id, external_id)")
        problems += 1
    if list(inspect.signature(analyze).parameters) != ["msg"]:
        print("FAIL analyze must be analyze(msg)")
        problems += 1
    print(f"engine: {parse_mime.__module__}.parse_mime, {analyze.__module__}.analyze; {len(FIXTURES)} fixtures\n")

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == EMAIL)) or User(name="Swap Check", email=EMAIL)
        db.add(user)
        db.commit()
        try:
            for i, f in enumerate(FIXTURES):
                print(f"== {f.name}")
                try:
                    msg = parse_mime(f.read_bytes(), user.id, f"swap-{i}-{f.stem}")
                    assert isinstance(msg, NormalizedMessage), f"parse_mime returned {type(msg).__name__}"
                except Exception as e:
                    print(f"   PARSE ERROR {type(e).__name__}: {str(e)[:200]}")
                    problems += 1
                    continue
                print(f"   from={msg.sender!r} subject={msg.subject!r} urls={msg.urls} "
                      f"attachments={[a.filename for a in msg.attachments]} body_chars={len(msg.body_text)}")
                try:
                    a = analyze(msg)
                    assert isinstance(a, AssessmentSchema), f"analyze returned {type(a).__name__}"
                except Exception as e:
                    print(f"   ANALYZE ERROR {type(e).__name__}: {str(e)[:200]}  (platform would store INSUFFICIENT_DATA)")
                    problems += 1
                    a = fallback()
                _, row = process_message(db, msg, a, source="check")
                print(f"   band={row.risk_band} completeness={row.data_completeness} models={row.model_versions}")
                for r in row.reasons:
                    print(f"     - [{r['code']}] {r['text']} (evidence: {r['evidence_ids']})")
                if row.risk_band == "LOW" and not msg.body_text.strip():
                    print("   WARN empty body scored LOW; expected INSUFFICIENT_DATA")
                    problems += 1
        except Exception:
            traceback.print_exc()
            problems += 1
        finally:
            db.rollback()
            mids = list(db.scalars(select(Message.id).where(Message.user_id == user.id)))
            db.execute(delete(Assessment).where(Assessment.message_id.in_(mids)))
            db.execute(delete(Message).where(Message.id.in_(mids)))
            db.execute(delete(User).where(User.id == user.id))
            db.commit()
    print(f"\n{'OK' if not problems else 'PROBLEMS: ' + str(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
