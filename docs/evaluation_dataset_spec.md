# Evaluation dataset specification

Status: **specification and tooling only.** The repository holds 11 wholly synthetic format
examples (`evaluation/data/examples_synthetic.jsonl`), all provisional and unassigned to splits.
It does not yet contain an evaluation corpus. Nothing in this document, and no schema test,
supports any claim about model accuracy.

## 1. Purpose and tasks

The corpus exists to decide, with honest uncertainty, whether any model should be allowed to
influence the engine. Two model tasks are in scope (both currently unintegrated):

1. **Intent questions.** Predict the four content labels (`authority_claim_in_content`,
   `payment_request`, `credential_request`, `urgency_secrecy`). Candidate: a Laya
   typed-decisions checkpoint (see `docs/intent_model_suitability.md`). The vendor's own
   checkpoint is a comparison, not an assumed equivalent of the third-party derivative.
2. **Message-level outcome.** Predict `outcome` for a whole message (see
   `docs/email_model_suitability.md` for the rejected candidate and what a replacement must show).

The same corpus also serves as a regression set for the deterministic rules where they read
text. It is **not** a corpus for authentication, headers, attachments or threat-intelligence
lookups: those are decided by other components and need message headers this corpus does not
carry.

**Languages.** Scored language: English (`en`). Hindi (`hi`), Hinglish (`hi-Latn`), `mixed` and
`other` may be recorded and are reported separately; they are never pooled into English results
and carry no coverage requirement in v1.

**Channel.** Email only in v1.

## 2. Inclusion and exclusion

Include a message when it is (a) wholly synthetic, or (b) taken from a public or licensed
source whose licence permits this use and whose text has been sanitised (section 5), and it
supports at least one stratification cell in section 8.

Exclude: real confidential, customer, employee or third-party mail; anything whose provenance
or licence cannot be stated; text containing unredacted personal, financial, credential or
authentication data; bulk scraped phishing feeds with no licence; machine-translated copies of
existing records presented as new messages; messages that exist only to mirror a model's known
weakness without independent authorship.

Target for the first corpus: **several hundred independently authored or sourced messages**.
That number is a floor for the experiment to be worth running, not a statement that it is
statistically sufficient (section 9).

### Scenarios that must be represented

Hard negatives and relevant positives (see `evaluation/schema.py:SCENARIOS`): legitimate
transactional mail (invoices, receipts), internal business mail, executive announcements,
security notices including benign password reminders, legitimate urgent operations messages;
credential phishing, executive-impersonation payment requests, gift-card BEC, payroll-change
BEC, vendor bank-detail changes, link-led attacks, **no-URL attacks**; short or empty messages;
ambiguous cases; and messages that embed instructions aimed at a classifier.

## 3. Record format

JSON Lines, one record per line, UTF-8 (NFC). Machine-readable structure:
`evaluation/schema/record.schema.json` (generated from `evaluation/schema.py`; cross-field
rules are enforced by `evaluation/validate.py`).

| Field | Meaning |
|---|---|
| `schema_version` | `"1.0"` |
| `id` | unique, `^[a-z0-9][a-z0-9_-]{2,63}$` |
| `subject`, `body` | plain text; HTML already flattened; at most 300 / 20,000 characters |
| `language`, `channel` | `en`, `hi`, `hi-Latn`, `mixed`, `other`; `email` |
| `has_url` | whether the text contains a URL (checked against the text) |
| `scenario` | broad category (stratification aid, not a label) |
| `labels` | the four content labels: `true` / `false` / `null` |
| `outcome` | `legitimate` / `suspicious` / `malicious` / `ambiguous`, separate from `labels` |
| `label_status` | `provisional` / `reviewed` / `adjudicated` / `needs_review` |
| `annotation` | `authored_by`, `annotators[]`, `adjudicator`, `initial_disagreement` |
| `provenance` | `source_type`, `license`, `generator` (+ `generator_model`, `source_id`, `retrieved_on`, `redaction_applied`) |
| `group_id` | template / campaign / thread / source identifier (leakage unit) |
| `split` | `dev`, `calibration`, `test`, or `unassigned` (assigned by tool, never by hand) |
| `evidence_spans` | optional, per true label: `{field, start, end}` |
| `contains_embedded_instruction` | optional boolean for adversarial text |
| `notes` | optional, at most 500 characters |

The labels describe the **message text**. They do not authenticate a sender and do not decide
whether a message is malicious. See `docs/annotation_guide.md` for definitions with positive,
negative, ambiguous and boundary examples.

## 4. Label definitions and disagreement resolution

Definitions live in `docs/annotation_guide.md` and are part of this specification.
Annotators work independently; disagreements go to an adjudicator; unresolved cases become
`ambiguous` / `needs_review` and are excluded from scoring (guide, section 6). Every
adjudicated rule is added to the guide so the same case is not decided twice differently.

**Label status honesty.** Until a second annotator has independently labelled a record it is
`provisional`, and any result that depends on it must say so. Today every record is
`provisional` and authored by the project author.

## 5. Sources, licensing and privacy

* **Synthetic.** Authored for this project, `license: project-synthetic`, `generator` is
  `human`, `template` or `llm` (name the model). Synthetic text must use reserved domains
  (`.example`, `.test`, `.invalid`, `example.com/org/net`) and invented people and companies;
  the validator rejects other hosts and non-reserved email addresses in synthetic records.
* **Public or licensed.** Record `source_id` (dataset name and version), an allowed `license`
  (`CC0-1.0`, `CC-BY-4.0`, `CC-BY-SA-4.0`, `MIT`, `Apache-2.0`, `ODC-By-1.0`),
  `retrieved_on`, and set `redaction_applied: true` only after sanitising. A source with no
  stated licence is not eligible. Attribution and share-alike obligations must be met in any
  redistribution; check them before publishing the corpus.
* **Never include:** real confidential mail; real personal, financial, credential or
  authentication data; working account numbers, card numbers, IDs, tokens or keys. The
  validator flags obvious patterns (card numbers passing a Luhn check, IBANs, SSN/Aadhaar-like
  numbers, common key and token formats, private-key blocks, non-reserved email addresses). It
  is a safety net and **cannot prove** a text is free of personal data; sanitise before adding.
* **Sanitisation.** Replace people, organisations, addresses, phone numbers, account and
  reference numbers and URLs with invented values before the text is stored. Keep the
  linguistic cues that the labels depend on.
* **Handling.** Anything not wholly synthetic and reviewed belongs under
  `evaluation/data/private/` or `evaluation/data/raw/`, which are git-ignored. Validator reports
  print record ids, rule codes and character offsets, never message text.
* Do not fetch external datasets automatically. A person records the source and licence, then
  adds sanitised records.

## 6. De-duplication and near-duplicates

1. **Group identifiers are the primary control.** Authors give every message that shares a
   template, campaign, thread or source the same `group_id` at creation time.
2. **Exact duplicates** (equal after case, width, digit and URL folding) are validation errors,
   across groups and splits.
3. **Near-duplicates** are detected with word-3-gram Jaccard similarity on the normalised text,
   threshold 0.75, as a backstop. Texts under 8 tokens match only when identical.
   * Across different splits: **error**.
   * In different groups within one split: warning; give them one `group_id`.
   * The split tool also merges groups connected by near-duplicates *before* assigning splits.
4. A similarity score is evidence, not proof. Paraphrase, translation and entity swaps can evade
   it, so reviewers must still judge whether two messages are the same template.

## 7. Splits and leakage controls

| Split | Role | May be used for |
|---|---|---|
| `dev` | development | error analysis, prompt or question-wording iteration, template fixes |
| `calibration` | calibration | fitting per-question thresholds or temperatures |
| `test` | untouched test | one final report per frozen candidate configuration |

Rules:

1. Assign by **group**, never by message (`scripts/make_eval_splits.py`). Default fractions
   0.4 / 0.3 / 0.3, stratified by majority scenario, deterministic from a **required integer
   seed**. The manifest records seed, algorithm, similarity threshold, assignments, merged
   groups and a text digest of every record.
2. **Freeze before first scoring.** Once frozen, assignments never change. New groups may be
   added; any change that would force a reassignment is a `SplitConflict`. A frozen manifest is
   never overwritten by the tools.
3. **The test split never informs a decision.** Select thresholds, temperatures, prompts, label
   wording and templates using `dev` and `calibration` only (`evaluation.dataset.for_tuning`).
   The test split is locked in code by default and opened once, explicitly, for the final report.
   If test results lead to any change, the test split is spent for that experiment: build a new
   untouched split rather than reusing it.
4. **Test records must be independently labelled.** Run the validator with `--strict-test`
   before freezing: test records need `reviewed` or `adjudicated` labels. Where independent
   annotation is not yet available the labels stay `provisional` and results are reported as
   provisional.
5. **No model output reaches the annotators** before they label.
6. Do not train on `calibration` or `test`. (No model is trained in this project today; if one
   is, a separate train split is required.)

## 8. Minimum coverage and when to expand

`python scripts/validate_eval_dataset.py FILE --profile starter` reports whether these floors
are met (they are descriptive floors for a first experiment, not reliability guarantees):

* at least 300 usable English records;
* for each intent label, at least 40 positives and 40 negatives;
* outcomes: at least 60 `legitimate`, 20 `suspicious`, 60 `malicious`, 10 `ambiguous`;
* at least 5 records for every scenario except `other`;
* a test split of at least 100 records with at least 15 positives per intent label.

**Expand** before any claim when: a confidence interval on a decision-relevant metric is too
wide to separate candidates; a scenario cell is below its floor; independent labels cover less
than the test split; or an error-analysis finding names a scenario the corpus under-represents.
Add new groups through the frozen-manifest path; never refill the test split with items chosen
after seeing model behaviour.

## 9. Known limitations and permitted claims

Limitations of any corpus built to this spec:

* Mostly synthetic and author-written: wording is cleaner and more template-like than real
  mail, and the authors' ideas of "typical" shape the labels.
* Text-only: no headers, sender authentication, attachments or thread history.
* Small cells: with 15 positives, a 95% interval on a recall estimate can span 40+ points.
  As arithmetic only: estimating a proportion near 0.9 to within plus or minus 0.05 needs on the
  order of 140 positives, and that is before correlation between related messages.
* Group-level splitting reduces but cannot remove leakage; paraphrase evades similarity checks.
* Provisional labels carry the annotators' blind spots and any author bias.
* English-centred; Indian-language and code-mixed coverage is exploratory.

**Permitted claims** (always with n, group structure and label status stated):
"On the frozen test split of N messages from G groups (P positives for label L, labels
independently reviewed / provisional), candidate C achieved precision p and recall r at a
threshold fixed on the calibration split, with 95% interval [a, b]." Per-question and
per-scenario results, never pooled across questions.

**Not permitted:** production accuracy or detection rates; "representative" or "real-world"
coverage; a single pooled score across questions or languages; claims about unseen attack
styles; thresholds chosen on test data; treating provisional labels as ground truth; any
statement that a model is safe to integrate on the basis of schema tests or synthetic examples.

## 10. Evidence still required before evaluating or integrating either model

1. A corpus meeting section 8 with independently reviewed labels on the test split.
2. A frozen manifest, recorded seed, and a validator report with zero errors.
3. Pre-registered, per-question gates stated in policy terms (for example precision at a
   chosen operating point), written before scoring.
4. Candidates pinned to immutable revisions with weight hashes: for the intent task, the
   vendor checkpoint and the third-party derivative as separate arms, plus a rules-only
   baseline; for the outcome task, a candidate that first passes the controls listed in
   `docs/email_model_suitability.md`.
5. Calibration fitted on `calibration` only, then one scoring run on `test`.
6. A written decision on what role, if any, a model may play in the policy.
