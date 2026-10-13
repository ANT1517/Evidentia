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
| Policy layer (`engine/policy.py`, version 0.2.0) | done |
| Threat-intel adapters (`engine/threat_intel/`) | done (mocked tests only; **never run live**) |
| Email DistilBERT (`cybersectony/...v2.4.1`) | **evaluated, not integrated**: label mapping unresolved and fails basic cases, see `docs/email_model_suitability.md` |
| Laya intent questions (`Ankit1106/laya-typed-decisions`) | **optional isolated adapter** (`engine/models/intent.py`, disabled by default, not called by `analyze()`, cannot change a band); raw uncalibrated probabilities only. Assessed by smoke test: ranking signal but uncalibrated; recommendation is a larger labelled evaluation first, see `docs/intent_model_suitability.md` |
| SMS-Shield wrapper | todo |
| Labelled evaluation dataset **tooling** (`evaluation/`) | schema, annotation guide, validator and split tools done; **no evaluation corpus exists yet** (11 synthetic format examples, all provisional). See `docs/evaluation_dataset_spec.md` |
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

## Threat intelligence (Step 4, reviewed)

Disabled and deny-by-default. `analyze()` only uses it when the active profile requires the
`threat_intel` check (`full`); under `rules_only` no external request is ever made.
**No live provider call has been made by the test suite or by the author.** Use the smoke
test below to find out whether the adapters match the real services.

```python
from dataclasses import replace
from engine import analyze, DEFAULT_CONFIG
from engine.threat_intel import ThreatIntelService, ThreatIntelConfig, SharingPolicy

ti_cfg = ThreatIntelConfig(
    enabled=True,
    enabled_providers=frozenset({"urlhaus", "phishtank", "domain_age"}),
    sharing=SharingPolicy(approved_domains=frozenset({"public-test-domain.example"}),
                          approved_urls=frozenset({"http://public-test-domain.example/x"})),
)
svc = ThreatIntelService(ti_cfg)       # raises ValueError if the approval lists are unsafe
assessment = analyze(msg, config=replace(DEFAULT_CONFIG, active_profile="full"), threat_intel=svc)
```

| Provider | Endpoint | Key (environment variable) |
|---|---|---|
| URLhaus | `POST https://urlhaus-api.abuse.ch/v1/{url,host,payload}/` | `URLHAUS_AUTH_KEY` (required, `Auth-Key` header) |
| PhishTank | `POST https://checkurl.phishtank.com/checkurl/` (https only, never downgraded) | `PHISHTANK_APP_KEY` (optional) |
| VirusTotal | `GET https://www.virustotal.com/api/v3/{urls,domains,files}/...` | `VIRUSTOTAL_API_KEY` (required, `x-apikey`); also needs `virustotal_live_enabled=True` |
| Domain age | RDAP over https from the configured per-TLD map | none |

### What is documented vs provisional

| Item | Basis |
|---|---|
| VirusTotal 4 requests/min, 500/day | **Provider-documented** public quota (non-commercial use) |
| URLhaus 30/min, PhishTank 10/min, RDAP 20/min | **Application-side safety budgets**, configurable, *not* verified provider quotas |
| `vt_urgent_min = 5` (VT malicious engines for Urgent) | **Provisional**, not calibrated |
| `vt_review_min = 2` | **Provisional**, not calibrated |
| `new_domain_days = 30` | Common heuristic, not calibrated; never Urgent alone |
| Cache TTLs, 15 s deadline, 10 indicators/message | Operational choices |
| URLhaus URL/payload listing, PhishTank verified+valid -> Urgent | Rely on the provider's own curation; stale entries are possible |
| `shared_host_domains` (github.com, dropbox.com, ...) | Provisional list; host-level findings kept as evidence, no signal |

`engine/threat_intel/config.py::THRESHOLD_REGISTRY` and `engine/policy.py::RULE_BASIS` carry
the same information in code, and a test keeps the registry equal to the defaults. Policy
version is `0.3.0` (threat-intel component `0.1.1`); any change to these values or rules should bump it.

### Sharing policy (what may leave the process)

Approvals are exact, operator-written, and audited when the service starts (it refuses to
start otherwise). Entries are rejected if a URL has a query string, fragment or credentials, is
not in normalised form, or has a path or host label that looks like a token, UUID, long hex or
numeric id, JWT, e-mail address or session parameter. A public URL of that shape can be
listed under `reviewed_token_like_urls` after a human confirms it is public. Credentials can
never be approved. Domain approvals allow domain lookups only, never URLs.

### URL scope: stripped lookups are partial

Query strings and fragments are never sent. A URL that had either is looked up as
`scheme://host/path`, and every result for it records what was withheld (`omitted`). A
**negative** answer for that target is stored as a real `NOT_FOUND` but does **not** cover the
original URL: the evidence ledger gets a separate `threat_intel_full_url` row with status
`NOT_CHECKED`, and the `threat_intel` check is incomplete, so such a message can never be Low
under a profile that requires it. A **positive** listing stays `FOUND` (and can drive Urgent);
its reason says it matched "the address of this link" with the query/fragment withheld.
Duplicate forms of a URL are merged and treated as partial if any form was. Scope is derived
per message and never inherited through the cache. Practical consequence: tracking-link URLs
make the check incomplete by design, so under the `full` profile expect Insufficient data
for them unless another signal fires.

### RDAP (domain age)

Only `https://` RDAP servers are used. A TLD whose configured entry is missing, http-only or
otherwise unusable returns `NOT_CHECKED` without any request. Redirects are refused, so the
`rdap.org` redirector is not used. Refresh the map offline with
`rdap_servers_from_bootstrap(json.load(open("dns.json")))` from IANA's `dns.json`.

### Live smoke test (opt in, operator only)

`scripts/ti_smoke.py` is the only code that can contact a provider. It is not in the test
suite and refuses to build a real transport under pytest.

1. Put **public test indicators only** in a copy of `scripts/smoke_indicators.example.json`
   (bare http(s) URLs, no query/fragment/credentials; the defaults are `example.com` and the
   public EICAR test-file SHA-256). Everything listed is approved verbatim.
2. Export keys in the shell, never in a file in the repo:
   `URLHAUS_AUTH_KEY` (free from auth.abuse.ch), optionally `PHISHTANK_APP_KEY`, and
   `VIRUSTOTAL_API_KEY` (public quota, 4/min).
3. Dry run (default, no network). It prints each provider, redacted indicator, and the
   endpoint that would be called:
   `python scripts/ti_smoke.py --indicators my_indicators.json --providers urlhaus,domain_age`
4. Go live by setting **both** `TI_LIVE_SMOKE=1` and `--confirm-live`:
   `TI_LIVE_SMOKE=1 python scripts/ti_smoke.py --indicators my_indicators.json --providers urlhaus,domain_age --confirm-live --show-shapes`
5. Read the output. Exit `0` means no compatibility problem, `2` means a provider answered
   in an unexpected format or rejected the credentials (re-read `--show-shapes`, which
   prints key names and types only), `3` means the live guard refused, `1` means unsafe input.
   Key values, request headers and bodies are never printed.
6. Add `virustotal` to `--providers` last and only deliberately: VirusTotal may retain what
   is queried and has a very small quota.

**Execution model.** The service is synchronous and blocking (bounded by `deadline_s`,
default 15 s). Never call it on an asyncio event-loop thread: use
`await asyncio.to_thread(analyze, msg, config=..., threat_intel=svc)` or a worker/queue.

**Process-local.** The cache and rate limiter live in memory in one process. Several workers
each get their own, so duplicate lookups and combined quota overruns are possible. No
distributed cache or global rate limiter exists; implement `Cache` / `RateLimiter` over a
shared store before scaling out.

## Evaluation dataset (tooling only)

`evaluation/` holds the record schema, an offline validator, and leakage-safe split tools. It is
independent of `engine/` and loads no model. There is no evaluation corpus in the repository
yet: `evaluation/data/examples_synthetic.jsonl` is 11 synthetic format examples with
provisional labels. Specification: `docs/evaluation_dataset_spec.md`; labelling rules:
`docs/annotation_guide.md`; open questions: `docs/outstanding_review_items.md`.

```bash
python scripts/validate_eval_dataset.py evaluation/data/examples_synthetic.jsonl
python scripts/make_eval_splits.py FILE.jsonl --seed 20261013 --out-manifest splits.json --out-data FILE.split.jsonl
```

## Two-model prototype (experimental, not in the verdict)

`engine/models/email.py` (DistilBERT class scores, label mapping `unresolved`), `engine/models/intent.py` (Laya intent probabilities) and `engine/models/runner.py` run side by side on synthetic text via `scripts/two_model_demo.py` (`TWO_MODEL_DEMO=1 ... --run`; local cached weights only, never downloads). Outputs are raw and experimental: `analyze()` does not use them, they cannot change a risk band, and the `text_model` / `intent_questions` required checks remain incomplete.

## Run tests

```bash
pip install -r requirements.txt
python -m pytest -q
```

Tests make no network calls (`tests/conftest.py` fails any socket use). The live smoke
script is separate and never run by the suite.
