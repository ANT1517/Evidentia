# Deviations from the master plan

Source of truth for "the plan": **"Phishing & Social Engineering Detection -- Project Plan"**
(15 pages, dated 13 Oct 2026). This file records everything that was built differently from,
added beyond, or left out of that plan, and why. It describes the **Member B analysis engine**
only (the plan's section 12 split), because that is the part built in this repository.

How to read it: **Not built** means the plan asked for it and it does not exist. **Changed**
means it exists but works differently. **Added** means it was not in the plan. Nothing here
claims model accuracy or production readiness.

Current state: 562 offline tests passing; baseline commit `9350438` plus 5 later commits on
`main` (`5667d4c`, `62c4456`, `83e9584`, `8e3cdc2`, `e8479e5`).

---

## 1. Summary

| Plan area | Status |
|---|---|
| Analysis engine contract (`analyze(msg) -> Assessment`) | **Built, extended** |
| Safe MIME parser | **Built** |
| Rule checks (SPF/DKIM/DMARC, Reply-To, display name, lookalike, attachments) | **Built, extended** |
| Risk bands + evidence ledger + reason codes | **Built, changed** |
| Threat intelligence (VirusTotal, PhishTank, URLhaus, domain age) | **Built, changed (privacy-gated, never run live)** |
| Text model (cybersectony DistilBERT) | **Evaluated and rejected for the verdict; experimental adapter only** |
| Intent questions (Laya typed-decisions) | **Evaluated, not approved; optional isolated adapter only** |
| SMS text model (SMS-Shield via Ollama) | **Not built** |
| Campaign detection | **Not built** |
| WhatsApp bot (Twilio), Gmail polling/OAuth | **Not built** (Shyamanth's part) |
| FastAPI, PostgreSQL, Docker, React PWA, escalation email | **Not built** (Shyamanth's part) |
| 20-message test set + results table (rules vs +models vs +Laya) | **Not produced**; replaced by evaluation-dataset tooling (no corpus yet) |
| Demo script | **Not built** |

The engine can currently produce a **rules-only** assessment with deterministic reasons and a
partial threat-intel check. Neither model contributes to any verdict.

---

## 2. Scope and platform

| # | Plan said | What happened | Why |
|---|---|---|---|
| 2.1 | Two people: Shyamanth builds platform + frontend; Member B builds the engine behind one function. | Only Member B's engine was built, in `C:\Users\Sreesatvik\Documents\HACK`. | This was the requested scope. No platform code exists. |
| 2.2 | FastAPI + Pydantic, Python 3.12, Docker Compose, PostgreSQL, Alembic. | Pydantic only; Python 3.13; no API, DB, Docker or migrations. | Platform side not in scope. |
| 2.3 | No RabbitMQ/Celery; background tasks or one worker loop. | The threat-intel service is **synchronous and blocking** (bounded by a 15 s per-message deadline) and must be run from a worker thread, not an event loop. | Documented as an integration requirement in the README. |
| 2.4 | `schemas.py` agreed on day 1 with Shyamanth. | Contract extended unilaterally (section 3). **Shyamanth has not approved the additions.** | No counterpart available; additions were backward compatible. |

---

## 3. Shared contract changes (`engine/schemas.py`, `engine/analyze.py`)

The plan fixed four models and one function. The additions below are all optional or
defaulted, but each needs Shyamanth's sign-off before the platform relies on them.

| # | Addition | Reason |
|---|---|---|
| 3.1 | `NormalizedMessage.link_mismatches` (`LinkMismatch`) | The plan lists anchor-vs-destination tricks but the contract had nowhere to carry them. |
| 3.2 | `NormalizedMessage.ingest_source` (`IngestSource`, default `UNKNOWN`) | Uploaded `.eml` files can forge `Authentication-Results`; the platform must say how a message arrived. |
| 3.3 | `AuthResults.authserv_id` | Needed to decide whether an authentication result can be believed. |
| 3.4 | `Assessment.evidence` (full ledger), `analysis_profile`, `policy_rules` | The plan's `Assessment` carried reasons only; the DB needs the ledger, and the profile/rules fired make decisions auditable. |
| 3.5 | New `ReasonCode` values: `DKIM_FAIL`, `DMARC_FAIL`, `DISPLAY_NAME_SPOOF`, `LOOKALIKE_DOMAIN`, `RISKY_ATTACHMENT`, `LINK_TEXT_MISMATCH`, `HASH_ON_THREAT_LIST`, `TEXT_MODEL_PHISHING`, `SMS_MODEL_SCAM`, `NEW_NUMBER_CLAIM`, `CHECK_INCOMPLETE` | Plan listed ten example codes only. |
| 3.6 | `analyze(msg, *, config=..., now=None, threat_intel=None)` | Keyword-only; positional call is unchanged. `now` makes assessments reproducible; `threat_intel` is optional. |
| 3.7 | Evidence ids such as `auth_spf-1`, `threat_intel-3`, `missing-text_model`, `incomplete-<check>`, `out-of-scope-<check>` | Unique per assessment only; the DB must key them with the message id. |
| 3.8 | Plan reason codes `PAYMENT_CHANGE_REQUEST`, `CREDENTIAL_REQUEST`, `URGENCY_CUE`, `SECRECY_CUE`, `UNOFFICIAL_SENDER_ID` exist in the enum but **nothing produces them**. | They depend on the intent and SMS components that are not integrated. |

---

## 4. Parser and rule checks

| # | Plan said | What happened | Why |
|---|---|---|---|
| 4.1 | Parse headers, text, HTML to text, links, attachment metadata. | Built with the standard library only. HTML is flattened by a tokenizer (script/style dropped), never rendered; attachments are only named and hashed. | As planned. |
| 4.2 | SPF/DKIM/DMARC results read from headers. | **Only the topmost `Authentication-Results` header is read.** Results count as verified only if the platform marked the message `GMAIL_API` **and** the header's authserv-id is on a configured list. `Received-SPF` is never trusted. | The plan did not address header forgery; a forged "spf=pass" in an uploaded file would otherwise be believed. |
| 4.3 | `.eml` upload "as a backup for the demo". | An uploaded `.eml` can never reach **Low**: its authentication shows as `not_checked`, so the result is Insufficient data (unless an operator explicitly trusts uploads in config, which re-opens the forgery hole). | Direct consequence of 4.2. The demo's "legitimate invoice shows no badge" needs the Gmail path. |
| 4.4 | Lookalike domains (unspecified method). | Registered domain via a bundled Public Suffix List snapshot (`tldextract`, new dependency); confusable-character skeletons, edit distance, name-plus-lure-word, IDN/punycode. Compared only against the org domain and each brand's primary domain. | Needed a defensible, offline method. Heuristic; thresholds untuned. |
| 4.5 | Display-name tricks. | Matches configured directory people, brand names, executive titles ("CEO"), and addresses embedded in display names. | Plan did not define the checks. Demo directory is placeholder data (`ourcompany.example`, Alex Morgan). |
| 4.6 | Risky attachments (`.exe`, double extensions, macros). | As planned, judged by file name and declared type only, with an explicit note that contents were never examined. | Metadata is not proof of content. |
| 4.7 | (not in plan) | **Added** a rule that the protected organisation's own domains are never sent to external lookup services, even if an operator lists them. | Privacy; see section 6. |

---

## 5. Risk bands, policy and required checks

| # | Plan said | What happened | Why |
|---|---|---|---|
| 5.1 | Four bands: Urgent / Review / Low / Insufficient data. | Same four bands, with "no percentages". | As planned. |
| 5.2 | Urgent if SPF/DMARC fail with a known brand or exec name; URL/hash on a threat list; **or Laya says yes to "exec" and "money"**. | Auth-fail Urgent requires **trusted** provenance. Threat-list Urgent exists (via the threat-intel check). **The Laya rule is not implemented.** Added Urgent triggers: executable-named attachment; two configured contextual combinations (executive-name mismatch + Reply-To mismatch; brand mismatch + lookalike domain). | Models are not integrated. The added combinations make the rules-only baseline useful without a model. |
| 5.3 | Review if the text model/SMS-Shield crosses a hand-set threshold, or two or more Laya cues are yes. | **Not implemented.** Review fires for single rule indicators (Reply-To mismatch, lookalike, link mismatch, display-name spoof, macro attachment, verified auth fail, listed domain, very new domain, etc.). | No model signal is allowed to reach the policy. |
| 5.4 | Review also when "models disagree". | Not implemented. | No models in the policy. |
| 5.5 | Low only when every check ran and nothing fired. | Same, enforced per **analysis profile**. **Added** profiles: `rules_only` (default) and `full`. A `rules_only` Low is stamped `data_completeness="partial"` and the threat-intel/text/intent checks are listed as out of scope. | The plan had one implicit profile; with models unavailable a Low would otherwise overstate coverage. |
| 5.6 | Insufficient data when a check that matters fails. | Same. Required checks (`rules_only`): `auth_spf`, `auth_dkim`, `auth_dmarc`, `reply_to`, `identity`, `lookalike`, `link_mismatch`, `attachments`. `full` adds `threat_intel`, `text_model`, `intent_questions`. | **DKIM fix:** it was computed but not required (policy 0.3.0 corrected this). |
| 5.7 | "Very new domains raise risk." | A domain under 30 days is Review-level only and **can never be Urgent alone**. A single VirusTotal detection is evidence only. | Avoid over-escalating weak signals. Thresholds are provisional. |
| 5.8 | Policy "written as code, versioned". | Versions: `0.1.0` rules baseline, `0.2.0`/`0.2.1` threat intel, `0.3.0` DKIM required. A table records each rule's basis, none calibrated. | As planned, plus transparency about calibration. |
| 5.9 | Evidence status found / not found / not checked. | Same, with strict semantics: `not_found` never means safe; unsupported or privacy-blocked lookups are `not_checked` with explicit coverage-gap rows. An incomplete check can never produce a reason without evidence. | "Unknown is not safe". |
| 5.10 | A hand-set threshold on a test set. | No thresholds were tuned on any data. The VirusTotal counts (5 / 2), 30-day age and request budgets are **untuned provisional values**. | No labelled data exists. |

---

## 6. Threat intelligence

| # | Plan said | What happened | Why |
|---|---|---|---|
| 6.1 | Look up each URL, domain and attachment hash. | **Deny by default.** Nothing leaves the process unless an operator lists the exact URL, domain or hash. Company domains, private/internal hosts, URLs with credentials, and token- or id-like paths are refused even if listed. The service refuses to start with an unsafe approval list. | VirusTotal retains/scans what it receives; real messages contain private data. Largest behavioural deviation: out of the box **no lookups happen**. |
| 6.2 | WHOIS lookup for domain age. | **RDAP over HTTPS only**, from a snapshot of IANA's bootstrap file. WHOIS (port 43) not implemented. TLDs without a usable HTTPS server (e.g. `.io`, `.co` in the snapshot) are `not_checked`. | WHOIS needs raw sockets to arbitrary hosts; redirects are refused. |
| 6.3 | Cache threat-intel results. | In-memory TTL cache and rate limiter, **process-local**. No shared cache or global limiter. | Documented limitation; not suitable for several workers on the VirusTotal public quota. |
| 6.4 | VirusTotal, PhishTank, URLhaus. | Built to their documented endpoints (URLhaus `Auth-Key`, PhishTank HTTPS only, VirusTotal `x-apikey`). VirusTotal also needs a second `virustotal_live_enabled` switch. | Its documentation says queried domains may be scanned and retained. |
| 6.5 | (not in plan) | **Query strings and fragments are never sent.** A stripped lookup is recorded as *partial*; a negative on the stripped URL does not cover the original, so the check is incomplete. | Privacy. Consequence: tracking-link emails stay Insufficient data under `full`. |
| 6.6 | (not in plan) | Large shared-hosting domains (github.com, dropbox.com ...) get no host-level signal. | Avoid flagging every message that links to them. Provisional list. |
| 6.7 | Pre-run demo messages to avoid rate limits. | **The adapters have never run against live services.** All provider tests are mocked. An opt-in `scripts/ti_smoke.py` exists and has not been run. | No keys or approvals were available. Unconfirmed: PhishTank HTTPS and key issuance, VirusTotal response bodies, URLhaus auth-failure shape. |

---

## 7. Text model (cybersectony DistilBERT)

| # | Plan said | What happened |
|---|---|---|
| 7.1 | Use it off the shelf as the email text score; "verify which output label means phishing email on known samples first." | Verified, and the result was negative. `config.json` has only `LABEL_0..3`; the model card and the dataset card **contradict each other** on classes 1 and 3. The dataset is ~89% URLs and carries no provenance or licence. |
| 7.2 | (implicit: it works) | A 30-string synthetic probe showed false alarms on routine mail (invoices, shipping, IT reminders), misses on two no-URL BEC variants (gift card, payroll), degenerate input (`""`, `ok`, `hello`) scored as class 1 at ~1.0, and a long padded message diluted a phishing sentence. |
| 7.3 | Contributes a Review signal. | **Not integrated in the verdict.** `text_model` remains a required check of the `full` profile that is unimplemented, so `full` always returns Insufficient data. |
| 7.4 | (not in plan) | An **experimental adapter** (`engine/models/email.py`) exists: pinned revision, local safetensors only, label mapping always `unresolved`, empty input never scored. It is not called by `analyze()` and cannot change a band. |
| 7.5 | (not in plan) | Pinned identity recorded: revision `6724dec17360ab1f6450553f1d950404f66a5dde`, weights SHA-256 `42e571f4...6e71` (verified against the Hub). |

Details: `docs/email_model_suitability.md`.

---

## 8. Intent questions (Laya typed-decisions)

| # | Plan said | What happened |
|---|---|---|
| 8.1 | "This checkpoint is already tuned for typed decisions," so use it for the four yes/no questions. | The checkpoint named in the plan is a **third-party derivative** (`Ankit1106/laya-typed-decisions`), not the vendor's own. It was trained on 1,200 *synthetic* cases from four non-phishing workflows (agent traces, customer service, invoices, incidents). Its advertised benchmark says nothing about phishing intent. |
| 8.2 | Four questions: executive/colleague/vendor claim; money/gift cards/bank change; login or password reset; urgency or secrecy. | Reworded: authority claim (executive, senior leader or other authority; "colleague or vendor" dropped); payment; credential/code/sensitive-account request (password *reset* not singled out); urgency/secrecy. |
| 8.3 | Laya reads a short **evidence pack** (sender, reply-to, subject, key lines, rule results). | The adapter and probes pass **bounded plain text (subject and body) only**; no sender, reply-to or rule results. Not evaluated with the plan's pack format. |
| 8.4 | Laya "yes" to exec and payment is an **Urgent** trigger; two or more yes is Review. | **Not wired into policy.** Smoke test (16 synthetic messages): three of four pre-registered gates failed; all answers sat in 0.15 to 0.66; the correct "yes" answers cleared 0.5 by at most 0.16; an embedded "answer NO" instruction moved the payment answer across the cut; an empty message scored 0.26 to 0.43. A consistent ranking signal existed, so the recommendation was a larger labelled evaluation first. |
| 8.5 | (not in plan) | An **optional isolated adapter** (`engine/models/intent.py`) returns four raw, uncalibrated probabilities with an explicit status. Disabled by default, lazy, bounded, local pinned weights only, never logs text. The `intent_questions` check is unimplemented. |
| 8.6 | `pip install laya`. | `laya==0.4.6` installed hash-pinned with `--no-deps`; the library's pinned-revision table lists a different (vendor) checkpoint than the one used. |

Details: `docs/intent_model_suitability.md`. Pinned: revision
`66172d2dfdd5d5c31f0aa5cc999ed2cf2f4b78a2`, weights SHA-256 `59627bc3...38c6`.

---

## 9. Items in the plan that were not built

| # | Plan item | Status |
|---|---|---|
| 9.1 | SMS-Shield (Ollama, 2.5 GB GGUF) for SMS/WhatsApp text | Not built; never inspected |
| 9.2 | Sender-ID checks and employee-directory "new number" checks | Not built (no SMS/WhatsApp channel; non-email channels return Insufficient data) |
| 9.3 | Campaign detection and "also sent to N colleagues" | Not built |
| 9.4 | Twilio WhatsApp bot, ngrok, `pending_reports` | Not built |
| 9.5 | Gmail OAuth, polling, encrypted tokens | Not built |
| 9.6 | Escalation email (SMTP), employee CSV import | Not built |
| 9.7 | React/Vite PWA (five screens) | Not built |
| 9.8 | Demo script (five-minute attack story) | Not built |
| 9.9 | Optional LLM explanation rewrite | Not built; explanations are fixed templates from evidence |
| 9.10 | Results table: rules only vs + models vs + Laya | Not produced; there is no labelled set and no integrated model |

---

## 10. Testing and evaluation (plan section 13)

| # | Plan said | What happened |
|---|---|---|
| 10.1 | Write a ~20-message test set ourselves and tune thresholds on it. | Not done as described. The 20-message set would have been too small and template-like to tune on or to support any claim. |
| 10.2 | (not in plan) | **Added** an evaluation-dataset foundation (`evaluation/`): record schema, annotation guide, specification, offline validator (duplicates, near-duplicates, group leakage, secret/PII patterns, provenance/licence, coverage), group-level split tool with a freezable manifest, and a test-split lock. Independent of `engine/`. |
| 10.3 | (not in plan) | The only data is **11 synthetic format examples**, all provisional and written by one author. **No evaluation corpus exists**, no labels have been independently reviewed, and no split is frozen. |
| 10.4 | (not in plan) | Source curation was started and interrupted. Primary-source licence review found: Nazario corpus CC-BY-4.0 (not downloaded); SpamAssassin corpus has no formal licence, copyright stays with senders (3 ham archives downloaded, **local only, not processed, not committed**); LLMGen is uploader-licensed synthetic text (not downloaded); two other candidates blocked for unverifiable provenance. No real phishing or BEC text was obtained. |
| 10.5 | (not in plan) | **Added** opt-in probe scripts for both models and the two-model runner. These are experimental, dry-run by default, and need explicit flags and environment variables. |

---

## 11. Plan principles: still honoured

| Principle | Status |
|---|---|
| No AI agents with power | Held. The adapters are encoders with no tools; nothing acts. |
| No training | Held. Nothing is trained or fine-tuned. |
| Evidence first | Held. Every reason cites existing evidence rows (enforced by `analyze()`). |
| Unknown is not safe | Held, and strengthened (untrusted, partial and unsupported results are never clean). |
| Rules beat models | Held. Models are outside the verdict and tests prove they cannot change a band. |
| Humans decide | Held. No quarantine or automatic action exists. |
| Never "AI-written" as a reason | Held. No such signal exists. |

---

## 12. Open items and caveats

Tracked in `docs/outstanding_review_items.md`:

1. `text_model` and `intent_questions` required checks unimplemented, so `full` is always Insufficient data. Decide whether to remove them from `full`, replace the models, or keep waiting for evaluation.
2. Live threat-intel behaviour is unverified.
3. Gmail trust assumes authserv-id `mx.google.com`, unchecked against a real message.
4. Tracking-URL messages are incomplete by design under `full`.
5. Evaluation corpus does not exist; independent annotators are not available.
6. Shyamanth must approve section 3 before the platform depends on it.

Local artefacts on the build machine: `laya==0.4.6` in user site-packages; cached model
weights under `~/.cache/huggingface` (about 269 MB and 847 MB); three SpamAssassin archives in
git-ignored `evaluation/data/raw/`. Cleanup commands are in `docs/intent_model_suitability.md`.

---

## 13. Timeline of changes

| Step | Outcome | Tests |
|---|---|---|
| 1 | Contract and stub `analyze()` | 4 |
| 2 | Safe MIME parser | 15 |
| 3 | Rules + versioned policy (`rules_only`) | 122 |
| 4 | Threat-intel adapters, privacy gate, scope handling (`5667d4c`) | 370 |
| 5A | DistilBERT suitability: rejected | 381 |
| 5B | Laya suitability: not approved, evaluate first | 415 |
| 5C | Evaluation dataset tooling | 493 |
| DKIM | `auth_dkim` required, policy 0.3.0 (`83e9584`) | 499 |
| Laya adapter | Optional isolated adapter (`8e3cdc2`) | 532 |
| 5F | DistilBERT adapter + two-model runner (`e8479e5`) | 562 |

Related documents: `README.md`, `docs/email_model_suitability.md`,
`docs/intent_model_suitability.md`, `docs/evaluation_dataset_spec.md`,
`docs/annotation_guide.md`, `docs/outstanding_review_items.md`.
