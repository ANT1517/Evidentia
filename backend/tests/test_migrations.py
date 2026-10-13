from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from app.db import engine


def test_upgrade_head():
    command.upgrade(Config("alembic.ini"), "head")
    assert {"users", "messages", "assessments", "pending_reports"} <= set(inspect(engine).get_table_names())
