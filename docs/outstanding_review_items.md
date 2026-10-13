# Outstanding review items

A running list of known open questions and unresolved discrepancies. Items stay here until a
decision is made and recorded; nothing on this list has been silently resolved. Facts below were
checked against the repository when this file was written.

Note: no written list existed before this file. The `auth_dkim` item was raised in conversation
and is recorded here for the first time so that it cannot be lost.

## Resolved

### 1. `auth_dkim` was evaluated but not a required check (resolved, policy 0.3.0)

* **Was.** `engine/rules.py` computed DKIM, but `_RULES_REQUIRED` in `engine/policy.py` held
  only `auth_spf` and `auth_dmarc`, so a missing, untrusted or inconclusive DKIM result could
  still produce `Low`. A test pinned that behaviour.
* **Now.** `auth_dkim` is required in both profiles. A missing, untrusted (e.g. uploaded
  `.eml`) or inconclusive (`none`, `neutral`, `temperror`) DKIM result gives
  `Insufficient data`, never `Low`. A verified DKIM `fail` remains an indicator (Review).
* **Consequence to be aware of.** Real mail without a DKIM signature, or mail whose DKIM result
  the receiving server did not report, can no longer be `Low`. That is the intended strictness
  ("unknown is not safe") but will show as "could not fully check" more often.
* **Tests.** `tests/test_policy.py`: the three auth checks are required; incomplete DKIM alone
  prevents Low; missing, untrusted and inconclusive DKIM end to end; a verified failure is
  still an indicator. The old test that pinned DKIM as non-required was replaced.

## Open decisions about unimplemented required checks

### 2. `text_model` check

The `full` profile requires `text_model`, but there is no implementation and the proposed model
was rejected (`docs/email_model_suitability.md`). Until a candidate passes evaluation, or the
check is removed from the required set, the `full` profile stays `Insufficient data`.

### 3. `intent_questions` check

The `full` profile requires `intent_questions`. The one candidate assessed is not approved for
an adapter (`docs/intent_model_suitability.md`); the recommendation is a larger labelled
evaluation first (`docs/evaluation_dataset_spec.md`).

## Unvalidated assumptions

### 4. Threat-intelligence adapters have never run against live providers

All provider tests use mocked transports. Unconfirmed: PhishTank over HTTPS and current key
issuance, VirusTotal response bodies beyond the documented object shapes, URLhaus
authentication-failure shape. `scripts/ti_smoke.py` exists to find out; it has not been run.

### 5. Gmail `Authentication-Results` trust

Header trust assumes the authserv-id `mx.google.com` for Gmail-fetched mail. This was not
checked against a real Gmail message, and trust also depends on the platform setting
`ingest_source` correctly.

### 6. Tracking-URL messages are incomplete by design under `full`

Query strings and fragments are never sent to providers, so a URL carrying either is a partial
lookup and the `threat_intel` check is incomplete. Real mail often contains such links, so the
`full` profile will report Insufficient data for them unless another signal fires. An operator
policy for known-benign hosts has not been designed.

## Housekeeping

### 7. Work not yet committed

At the time of writing, the model-suitability probes, their reports and tests, the documents
under `docs/`, and the evaluation tooling are uncommitted. `reports/*.json` are generated
outputs; decide whether to keep them in version control.

### 8. Local artefacts from opt-in runs

The `laya==0.4.6` package (user site-packages) and cached model weights under
`~/.cache/huggingface` (about 269 MB and 847 MB) remain on the machine that ran the probes.
Cleanup commands are in `docs/intent_model_suitability.md`.
