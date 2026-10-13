# Phishing & Social Engineering Detection: analysis engine

Member B's part of the project: everything behind

```python
from engine import analyze
assessment = analyze(normalized_message)
```

`engine/schemas.py` is the contract shared with the platform side
(`NormalizedMessage`, `Evidence`, `Reason`, `Assessment`).

## Status

| Component | Status |
|---|---|
| Schemas + `analyze()` entry point | done |
| MIME parser (`engine/parser.py`) | done |
| Rule checks (`engine/rules.py`) + config (`engine/config.py`) | done (rules-only baseline) |
| Policy layer (`engine/policy.py`, version 0.1.0) | done (rules-only baseline) |
| Threat-intel adapters | todo |
| DistilBERT / Laya / SMS-Shield wrappers | todo |
| Campaign linker | todo |
| Test set + tuning | todo |

`analyze()` currently runs the `rules_only` profile. A `Low` result under that profile means
"no rule fired and every rules check completed", **not** "safe": threat intelligence, the text
models and the intent questions have not run, and the assessment says so
(`analysis_profile="rules_only"`, `data_completeness="partial"`).

## Authentication trust

SPF/DKIM/DMARC results count as verified only if the platform marked the message
`ingest_source=GMAIL_API` **and** the `Authentication-Results` authserv-id is in
`EngineConfig.trusted_authserv_ids`. Uploaded `.eml` files are untrusted by default because
their headers can be forged; their auth results show as `not_checked`.

## Run tests

```bash
pip install -r requirements.txt
python -m pytest -q
```

Tests make no network calls (`tests/conftest.py` fails any socket use).
