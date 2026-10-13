# Email model suitability: `cybersectony/phishing-email-detection-distilbert_v2.4.1`

Status: **evaluated, NOT integrated.** No wrapper was built because the label semantics are
unresolved and the observed behaviour fails basic cases of the task. This document records the
evidence so the decision can be revisited. Reproduce everything with
`scripts/model_probe.py` (opt-in; see its header).

## 1. Identity (reproducibility)

| Item | Value |
|---|---|
| Repository | `cybersectony/phishing-email-detection-distilbert_v2.4.1` |
| Pinned revision | `6724dec17360ab1f6450553f1d950404f66a5dde` (commit; last modified 2024-10-28) |
| `model.safetensors` SHA-256 | `42e571f4e66cc6e34f949ebbcc61d7d2299fbfda29d2ebbbcfe11225133e6e71` (matches the Hub's published LFS digest for that commit) |
| Weight format | `model.safetensors` only (no pickle). Loaded with `use_safetensors=True`, `trust_remote_code=False` |
| Architecture | `DistilBertForSequenceClassification`, 66,956,548 F32 parameters, base `distilbert-base-uncased` |
| Task head | 4 outputs, `problem_type=single_label_classification`, max 512 tokens |
| License | Apache-2.0 (model). The training dataset card states no license |
| Probe environment | transformers 5.15.0, torch 2.7.1 (CPU) |

## 2. Label mapping: unresolved

`config.json` only contains `LABEL_0` to `LABEL_3`. Two documents give semantic names and they
**disagree**:

| Output | Model card example code | Dataset card (`cybersectony/PhishingEmailDetectionv2.0`) |
|---|---|---|
| 0 | legitimate_email | legitimate_email |
| 1 | **phishing_url** | **phishing_email** |
| 2 | legitimate_url | legitimate_url |
| 3 | **phishing_url_alt** | **phishing_url** |

What supports which reading:

* Sampled dataset rows: URLs carry only labels 2 and 3, emails only 0 and 1. This matches the
  dataset card, not the model card's name for output 1.
* Probe: email text lands on outputs 0 and 1 and almost never on 2 or 3, and bare URL text
  lands on output 3. Consistent with the dataset card.
* **But** it is not verified: the model author documents a different mapping; the model was
  versioned `v2.4.1` against a dataset named `v2.0`; and output 2 ("legitimate URL") **never**
  won on any probe input, including a plainly legitimate URL (see 4). Nothing authoritative
  confirms that the label ids used at training time equal the dataset card's.

No mapping was adopted. Outputs are reported by index.

## 3. Suitability findings

The training data is 22,644 emails and 177,356 URLs (about 11% email), source and collection
method unstated. Sampled "legitimate" emails are ordinary work or academic mail; sampled
class-1 emails include promotional/spam-style mail and rows whose entire text is the word
`empty`. The model is therefore closer to "does this look like ordinary correspondence" than to
"is this a phishing attempt".

## 4. Probe observations (30 synthetic strings; raw softmax, not calibrated, not accuracy)

Output 1 is called "P1" below. Full vectors are in `reports/model_probe_results.json`.

| Case | Human label | Top output (score) | Reading |
|---|---|---|---|
| Credential phish with link; bank-account phish; CEO wire request | phishing | 1 (>=0.99) | plausible |
| Vendor bank-detail change, no URL | phishing | 1 (0.996) | plausible |
| Gift-card request | phishing | **0 (0.999)** | missed |
| Payroll direct-deposit change | phishing | **0 (0.999)** | missed |
| Ordinary invoice notice ("Dear customer ...") | legitimate | **1 (0.996, 0.995)** | false alarm |
| Shipping notification | legitimate | **1 (1.000)** | false alarm |
| IT password-policy reminder | legitimate | **1 (0.994)** | false alarm |
| Meeting reschedule; internal invoice reminder; urgent ops mail | legitimate | 0 (1.000) | plausible |
| Empty string, whitespace only | n/a | **1 (1.000)** | degenerate input reads as phishing |
| `ok`, `empty`, `hello`, `...`, `lorem ipsum ...` | n/a | **1 (0.85 to 1.00)** | same |
| Hindi account-suspension text | n/a | 1 (1.000) | not meaningful (English-only model) |
| Phishing sentence + ~500 tokens of benign filler, either end | phishing | **0 (1.000)** | diluted; truncated at 512 |
| Bare legitimate URL (`python.org`) | legitimate | **3 (1.000)** | wrong under either mapping |

These are anecdotes, not a measurement; the point is that a model with a clean signal would not
fail these particular cases at near-certain confidence.

## 5. What is and is not established

Established: output shape (4 logits), tokenizer and 512-token limit, safetensors loading, the
hash of the exact weights, and that email text is routed to outputs 0/1.

Not established: what output 1 means in the author's own terms; any detection rate;
calibration (the maximum softmax score is **not** a probability of phishing: wrong answers
above arrive at 0.99+); robustness to padding, other languages or modern AI-written messages.

## 6. Recommendation

Do not wire this model into the policy as a phishing verdict or as a blocker. If the
`text_model` check stays in the `full` profile, evaluate a replacement first.

Candidates seen on the Hub (metadata only; none downloaded):

| Candidate | Notes from its card |
|---|---|
| `eduardocastellon/roberta-phishing-email-detector` | emails only; about 284k emails from eight classic corpora (CEAS_08, Enron, Nazario, SpamAssassin, Nigerian fraud, ...); MIT; safetensors; **labels not stated**, two inconsistent metric sets |
| `dima806/phishing-email-detection` | Apache-2.0, safetensors; **no data, labels or metrics stated** |
| `ealvaradob/bert-finetuned-phishing` | Apache-2.0; trained on a mix of URLs, SMS, emails and websites (not email-specific); labels not stated; weight format unconfirmed |

Evaluation protocol before adopting any of them:

1. Require explicit label semantics from the model author, or settle them with a labelled
   sample; record the pinned revision and weight hash.
2. Prefer email-only training data and a license that allows use; require `safetensors`.
3. Run `scripts/model_probe.py`-style controls and require sane behaviour on: empty and
   degenerate input (must be handled by the wrapper, not scored), benign transactional mail,
   no-URL BEC (gift card, payroll, vendor change), non-English, and padded long messages.
4. Evaluate on the project's own hand-written test set (plan section 13) and a larger labelled
   sample, then choose any threshold on that data. Report bands, not probabilities.
5. Keep rules and threat intelligence above any model signal, as the plan already states.

The plan's intent questions (Laya) target the BEC cases that this model missed. A rules + threat
intelligence + intent-question pipeline needs no text classifier, so making `text_model`
optional in the `full` profile is a legitimate alternative.

## 7. Decision required before any policy integration

Choose one: (a) evaluate one or more alternatives with the protocol above; (b) evaluate this
model on the project's labelled set anyway and accept only a weak, informational role; or
(c) remove `text_model` from the required checks of the `full` profile. Until then the
engine's `text_model` check remains unimplemented and the `full` profile stays Insufficient.
