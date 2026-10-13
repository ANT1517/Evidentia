# Outstanding review items

A running list of known open questions and unresolved discrepancies. Items stay here until a
decision is made and recorded; nothing on this list has been silently resolved. Facts below were
checked against the repository when this file was written.

Note: no written list existed before this file. The `auth_dkim` item was raised in conversation
and is recorded here for the first time so that it cannot be lost.

## Open discrepancies

### 1. `auth_dkim` is evaluated but not a required check

* **What the code does.** `engine/rules.py` runs `check_auth(..., "dkim")` for every email and
  records evidence (`auth_dkim-N`), and `engine/policy.py` gives it a display name. But
  `_RULES_REQUIRED` in `engine/policy.py` contains `auth_spf` and `auth_dmarc` only, so
  `auth_dkim` is **not** in the `rules_only` or `full` required set.
* **Effect.** A message whose DKIM result is missing, untrusted or inconclusive can still be
  `Low` (under `rules_only`) as long as SPF and DMARC are clean and trusted. A verified DKIM
  *failure* is still an indicator (Review, or Urgent with an identity mismatch).
* **Why it is a discrepancy.** The project plan lists SPF, DKIM and DMARC as header checks, and
  the code computes all three, but only two gate completeness.
* **Pinned by a test.** `tests/test_policy.py::test_failed_non_required_check_does_not_block_low`
  asserts the current behaviour (`"auth_dkim" not in PROFILES["rules_only"].required`).
* **Decision needed.** Either add `auth_dkim` to the required set (and change that test, bump
  the policy version) or document why DMARC alignment makes it redundant. Not changed here.

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
