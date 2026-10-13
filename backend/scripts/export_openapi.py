"""Print the OpenAPI schema to stdout. From the repo root:

    docker compose exec -T backend python scripts/export_openapi.py > frontend-contract/openapi.json
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import app  # noqa: E402

print(json.dumps(app.openapi(), indent=2, sort_keys=True))
