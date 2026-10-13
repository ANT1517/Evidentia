import os

import psycopg
import pytest
from cryptography.fernet import Fernet
from sqlalchemy.engine import make_url

# Tests run against their own database, never the dev one. Must happen before app modules read settings.
_dev = make_url(os.environ.get("DATABASE_URL", "postgresql+psycopg://evedentia:evedentia@localhost:5432/evedentia"))
TEST_DB = "evedentia_test"
_test = _dev.set(database=TEST_DB)

with psycopg.connect(
    host=_dev.host, port=_dev.port, user=_dev.username, password=_dev.password, dbname="postgres", autocommit=True
) as _c:
    if not _c.execute("select 1 from pg_database where datname=%s", (TEST_DB,)).fetchone():
        _c.execute(f'create database "{TEST_DB}"')

os.environ["DATABASE_URL"] = _test.render_as_string(hide_password=False)
os.environ["DISABLE_SCHEDULER"] = "1"
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["SECRET_KEY"] = "test-secret-test-secret-test-secret-32b"
os.environ["ALLOWED_EMAIL_DOMAIN"] = ""
os.environ["FRONTEND_URL"] = "http://localhost:5173"
os.environ["PUBLIC_BASE_URL"] = "http://localhost:8000"
os.environ["TWILIO_ACCOUNT_SID"] = "ACtest"
os.environ["TWILIO_AUTH_TOKEN"] = "test-twilio-token"
os.environ["TWILIO_WHATSAPP_FROM"] = "whatsapp:+14155238886"


@pytest.fixture(scope="session", autouse=True)
def _migrated_test_db():
    from alembic import command
    from alembic.config import Config

    from app.db import engine

    assert engine.url.database == TEST_DB, "tests must never touch the dev database"
    command.upgrade(Config("alembic.ini"), "head")
