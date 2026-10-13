# Phishing & Social Engineering Detection — Project Plan

Oct 13, 2026 · @Shyamanth

## 1. Problem statement

Employees receive convincing phishing emails, AI-written impersonation messages and social-engineering attacks that slip past static rules. They lead to two losses: stolen credentials and business email compromise (BEC), where a fake boss or vendor gets money or data moved.

**Domain:** Cybersecurity / Email Security (VNRVJIET · Cybervie · ISTE).

**Objectives the system must meet**

1. Use NLP/LLM classification on email text, headers, URLs and attachment metadata.
2. Detect impersonation and urgency cues.
3. Correlate with threat intelligence.
4. Explain risk factors.
5. Route suspicious messages for analyst review.

**Outcomes judges will look for**

1. Prioritized phishing alerts.
2. Earlier detection of targeted campaigns.
3. Explainable risk scores.
4. Reduced triage effort.
5. Faster user reporting and response.

The statement says "messages", not only emails, so we cover SMS and WhatsApp as a second channel. Email stays the core.

## 2. Solution and design principles

We build a safety app for employees: they connect their work Gmail and share suspicious SMS or WhatsApp messages to our bot. The app checks each message with rules and ready-made models and tells them in seconds how risky it is, why, and what to do. Anything they escalate reaches the security team with the evidence attached.

**Principles**

- **No AI agents with power.** Email text is written by the attacker, so no model can call tools, open links or take actions. The workflow is fixed code; models only answer questions.
- **No training.** We use pretrained models off the shelf and set thresholds by hand on our own test set.
- **Evidence first.** Every finding is stored with an ID, source and status; every reason shown to a user points to evidence.
- **Unknown is not safe.** A failed lookup or missing header shows as "not checked", never as clean.
- **Rules beat models.** Hard facts (SPF fail, blocklisted URL) always flag, whatever the models say.
- **Humans decide.** No automatic delete or quarantine. The app warns the employee and lets them escalate to IT in one tap.
- **Never "AI-written" as a reason.** We flag intent (money, credentials, pressure), not writing style.

**Pitch line:** "We deliberately gave AI no power, because in email security the attacker writes the input."

## 3. Model and tool stack

Every model is used as downloaded; none is trained or fine-tuned by us.

| Job | Choice | How it runs | Notes |
| --- | --- | --- | --- |
| Email text phishing score | [cybersectony DistilBERT v2.4.1](https://huggingface.co/cybersectony/phishing-email-detection-distilbert_v2.4.1) | Hugging Face Inference API, or local Transformers | 67M params, Apache-2.0. Verify which output label means phishing email on known samples first. |
| SMS text verdict | [SMS-Shield](https://huggingface.co/ganmoor-ai-labs/sms-shield) | Ollama (2.5 GB GGUF) as a small HTTP service | Returns verdict, scam type, risk 0–100, red flags, explanation. English/Hindi/Hinglish. Takes seconds per message. |
| Impersonation, payment request, credential request, urgency | Laya `laya-typed-decisions` checkpoint | `pip install laya`, local | Ask simple yes/no questions only. Base Laya is too weak without training; this checkpoint is already tuned for typed decisions. |
| Sender authentication | Rule code | Python | SPF, DKIM, DMARC results from headers; From vs Reply-To mismatch; display-name tricks; lookalike domains. |
| Threat intelligence | VirusTotal, PhishTank, URLhaus lookups | Python adapters with a cache | Store source, time and status; a timeout is "not checked". |
| Domain age | WHOIS lookup | Python | Very new domains raise risk. |
| Explanation text | Template from evidence | Python | Optional LLM rewrite later, only from the evidence pack. |
| Backend | FastAPI + Pydantic | Python 3.12 | Background tasks or one worker loop; no RabbitMQ/Celery for the demo. |
| Database | PostgreSQL | Docker | Messages, evidence, assessments, cases, campaigns. |
| Frontend | React + TypeScript | Vite | Employee web app (installable PWA): inbox check, message check, report history. |
| Email source | Gmail API (OAuth, polling) | Python | `.eml` upload as a backup for the demo. |
| SMS/WhatsApp source | Twilio WhatsApp sandbox | Webhook into FastAPI | Testers must send the sandbox join code first. |

## 4. System architecture

Employees bring messages in three ways and get the verdict back in the app or on WhatsApp; the security team only sees what an employee escalates.

&#91;embedded content: System architecture · 2 intakes, 3 check paths, 1 policy layer\]

Email and shared messages go through the same fixed workflow, with plain code choosing the path by channel. The campaign linker runs in the background and adds "also sent to N colleagues" to results. Report to IT can be tapped in the app or triggered by replying "escalate" to the bot.

## 5. Email flow

Each email takes the same fixed path; nothing in the email can change that path.

1. **Fetch.** Each employee signs in with Google and connects their work Gmail; we poll it every minute through the Gmail API. Skip message IDs already processed.
2. **Parse safely.** Read headers, plain text, HTML (converted to text, never rendered), links and attachment metadata (name, type, size, hash). Never open attachments or click links.
3. **Normalize.** Save one `message` record with `channel = email`.
4. **Rule checks.** SPF/DKIM/DMARC results, Reply-To mismatch, display-name spoofing, lookalike domains, risky attachment types (`.exe`, double extensions, macro files).
5. **Threat intelligence.** Look up each URL, domain and attachment hash; check domain age.
6. **Text model.** cybersectony DistilBERT scores the body.
7. **Intent questions.** Laya answers yes/no on a short evidence pack (sender, reply-to, subject, key lines, rule results):
   - Does the sender claim to be an executive, colleague or vendor?
   - Does it ask for money, gift cards or bank-detail changes?
   - Does it ask for login details or a password reset?
   - Does it create urgency or ask for secrecy?
8. **Fuse.** Combine everything into a risk band with reasons (section 7).
9. **Warn.** Urgent and Review emails get a warning badge and reasons in the employee's inbox view; Urgent also sends a browser notification. The employee can tap Report to IT.
10. **Campaign check.** In the background, link the email to related messages (section 8).

## 6. WhatsApp bot (Twilio)

Employees report suspicious SMS or WhatsApp messages by sharing them to our bot on WhatsApp; nothing is read from their phone automatically.

**Setup:** Twilio WhatsApp sandbox number, webhook `POST /webhooks/twilio/whatsapp` on FastAPI, exposed with ngrok during development. Each demo phone sends the sandbox join code once before judging.

**Flow**

1. The employee long-presses the suspicious SMS, taps **Share → WhatsApp**, and picks the bot. Copy-paste or forwarding a WhatsApp message also works.
2. Twilio posts the message to our webhook. We check Twilio's signature, save it, and reply at once: "Got it, checking…".
3. Sharing loses the original sender, so the bot asks: "Who sent this? Paste the sender ID or number." A `pending_report` row per WhatsApp number holds this state.
4. The employee replies with the sender (for example `JD-SBIINB` or `+91 98xxxxxx10`). We normalize it into a `message` record with `channel = sms` or `whatsapp`.
5. The message path runs: SMS-Shield verdict and red flags, sender-ID check (official header vs plain mobile number, and the employee directory for "new number" claims), URL threat-intel lookups, Laya intent questions.
6. The bot replies with the risk band and top three reasons, for example: "Urgent. Sender is a plain mobile number, not a bank ID. Link domain is 2 days old. Asks you to update KYC today. Don't click. Reported to security."
7. The result is saved to the employee's history in the web app and joins any related campaign. If they reply "escalate", it is emailed to IT with the evidence.

**Bot commands:** `report` (start a new report), escalate (send the last result to IT), `status` (last result), `help`.

**Bot safety rules**

- Never open shared links; only look them up.
- Message text is data only and can never change what the bot does.
- Replies warn only; the bot takes no other action.
- Store only what the employee shared, plus their WhatsApp number.

## 7. Risk scoring and explanations

Each message gets a risk band, not a fake percentage, because none of our model scores are calibrated.

**Bands**

| Band | Meaning | What the employee sees |
| --- | --- | --- |
| Urgent | Hard evidence, or several strong signals together | Red badge, notification, "Don't click, don't reply", one-tap Report to IT |
| Review | Some signals, or models disagree | Amber badge with reasons and "Verify with the sender another way" |
| Low | No meaningful signals | No badge |
| Insufficient data | Key checks failed or could not run | Grey "Couldn't fully check" badge and a suggestion to ask IT |

**Policy rules (written as code, versioned)**

- Urgent if any hard fact fires: SPF/DMARC fail with a known brand or executive name, a URL or hash on a threat list, or Laya says yes to both "claims to be an executive" and "asks for money or a bank change".
- Review if the text model score or SMS-Shield risk crosses our hand-set threshold, or two or more Laya cues are yes.
- Low only when every check ran and nothing fired.
- Insufficient data when a check that matters timed out or was skipped.

**Evidence ledger:** every finding is one row: `evidence_id, type, value, source, observed_at, status (found / not found / not checked)`.

**Reason codes** link evidence to plain words, for example `REPLY_TO_MISMATCH`, `SPF_FAIL`, `URL_ON_THREAT_LIST`, `NEW_DOMAIN`, `PAYMENT_CHANGE_REQUEST`, `CREDENTIAL_REQUEST`, `EXEC_IMPERSONATION`, `URGENCY_CUE`, `SECRECY_CUE`, `UNOFFICIAL_SENDER_ID`. The app and bot show the top reasons, each clickable to its evidence.

## 8. Campaign detection

A background job links messages that share indicators, across email, SMS and WhatsApp, and shows them as one candidate campaign.

**Link rules (each link stores why it was made)**

- Same URL or same registered domain.
- Same attachment hash.
- Same sender address, reply-to address or sender phone number.
- Same claimed identity (Laya says "claims to be the CEO" and the name matches) within 48 hours.
- Similar subject plus close timing, used only together with another link, never alone.

**Output:** the employee sees "This message was also sent to N colleagues", a strong sign of a campaign. When anyone escalates a campaign message, IT's email lists every linked message, channel and targeted employee.

This runs after each message is assessed, so it never slows the first alert. We present it as a prototype, since we have no labelled campaign data to measure it.

## 9. Employee web app

The React web app is for every employee and is installable on phones as a PWA; it has five screens. The security team only receives escalation emails, so there is no analyst console to build.

| Screen | What it shows | What the employee does |
| --- | --- | --- |
| Sign in | Google sign-in and Gmail consent, plus a link to save the WhatsApp bot number | Connect their work Gmail |
| Inbox check | Recent emails with a Low / Review / Urgent badge, riskiest first | Open a flagged email |
| Message detail | Message as safe text, risk band, plain-language reasons, what to do next, "also sent to N colleagues" | Tap Report to IT, or mark "This is fine" |
| Check a message | Paste an SMS or WhatsApp message with its sender, or upload a `.eml`; same result screen | Check anything before acting on it |
| My reports | History of messages they checked or escalated, with results | Re-open a result, see if IT replied |

Email HTML is never rendered; URLs are shown as plain text, not links.

## 10. Data model and API

Eight PostgreSQL tables cover the demo; one `messages` table holds every channel.

| Table | Key fields |
| --- | --- |
| `users` | id, name, title, email, phone, gmail\_token\_ref (encrypted), whatsapp\_number |
| `messages` | id, user\_id, channel (email / sms / whatsapp), external\_id (unique), sender, reply\_to, subject, body\_text, urls\[\], attachments (json), received\_at |
| `evidence` | id, message\_id, type, value, source, observed\_at, status (found / not\_found / not\_checked) |
| `assessments` | id, message\_id, risk\_band, reasons (json: code + evidence\_ids + text), data\_completeness, model\_versions, created\_at |
| `escalations` | id, message\_id, user\_id, sent\_to (IT email), sent\_at, employee\_note, user\_feedback (escalated / marked fine) |
| `campaigns` | id, first\_seen, last\_seen, status (candidate / confirmed) |
| `campaign_links` | campaign\_id, message\_id, link\_type, shared\_value |
| `pending_reports` | whatsapp\_number, message\_text, stage, updated\_at |

**API endpoints (FastAPI)**

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/auth/google` and `/auth/google/callback` | Employee signs in and connects Gmail |
| POST | `/scan` | Poll the signed-in employee's Gmail now |
| POST | `/webhooks/twilio/whatsapp` | Receive bot messages (Twilio signature checked) |
| POST | `/check` | Check a pasted message or `.eml` upload |
| GET | `/me/messages?band=` | Employee's inbox check, riskiest first |
| GET | `/me/messages/{id}` | Message detail with reasons and evidence |
| POST | `/me/messages/{id}/escalate` | Email the result and evidence to IT |
| POST | `/me/messages/{id}/feedback` | "This is fine" |
| GET | `/me/reports` | Employee's report history |
| POST | `/admin/users/import` | Seed the employee directory from a CSV |

## 11. Coverage map

Every objective and outcome in the problem statement maps to a specific part of the build.

| Problem statement item | Where we cover it |
| --- | --- |
| Objective 1: classify text, headers, URLs, attachment metadata | DistilBERT + SMS-Shield (text), rule checks (headers), URL lookups, attachment metadata rules |
| Objective 2: impersonation and urgency cues | Laya yes/no questions, display-name and lookalike-domain rules, sender-ID and directory checks |
| Objective 3: threat intelligence | VirusTotal, PhishTank, URLhaus, WHOIS domain age |
| Objective 4: explain risk factors | Plain-language reasons tied to evidence, in the app and the bot reply |
| Objective 5: route for analyst review | One-tap Report to IT sends the message, band and evidence to the security team |
| Outcome 1: prioritized phishing alerts | Inbox check sorts riskiest first; Urgent sends a notification |
| Outcome 2: earlier campaign detection | Cross-channel linking; "also sent to N colleagues" warning |
| Outcome 3: explainable risk scores | Bands with clickable reasons |
| Outcome 4: reduced triage effort | IT only sees what employees escalate, with evidence already gathered |
| Outcome 5: faster user reporting and response | WhatsApp bot and Check a message give a verdict in seconds |

## 12. Build plan

Build email end to end first; add the WhatsApp channel only once email works.

**Phase 1: core email pipeline**

- [ ] Repo, Docker Compose with PostgreSQL, FastAPI skeleton, database tables
- [ ] `.eml` upload and parser (headers, text, URLs, attachment metadata)
- [ ] Rule checks with reason codes and evidence rows
- [ ] cybersectony DistilBERT wrapper; confirm which label means phishing email
- [ ] Laya wrapper with the four intent questions
- [ ] Threat-intel adapters (VirusTotal, PhishTank, URLhaus) and WHOIS, with "not checked" on failure
- [ ] Policy layer that outputs a band and reasons

**Phase 2: dashboard and Gmail**

- [ ] Employee web app: Google sign-in, inbox check, message detail, Report to IT
- [ ] Gmail OAuth and polling
- [ ] Seed employee directory from a CSV; escalation email to IT

**Phase 3: WhatsApp channel**

- [ ] SMS-Shield running in Ollama behind a small HTTP endpoint
- [ ] Twilio sandbox, webhook with signature check, ngrok
- [ ] Bot conversation: receive, ask sender, run message path, reply
- [ ] Check-a-message page in the web app

**Phase 4: campaigns and polish**

- [ ] Campaign linking job and campaign screen
- [ ] Tune thresholds on the test set
- [ ] Demo script rehearsal, slides, results table (rules only vs + models vs + Laya)

### Backend work split

Shyamanth builds the platform and integrations, finishing early with stub results so he can move to the frontend; Member B builds the analysis engine behind one function.

**Contract, agreed together on day 1:** a shared `schemas.py` with Pydantic models `NormalizedMessage`, `Evidence`, `Reason` and `Assessment`, and one function `analyze(msg: NormalizedMessage) -> Assessment`. Shyamanth codes against a stub `analyze()` that returns a fixed result until Member B's real one is ready.

**Shyamanth: platform and integrations (then frontend)**

- [ ] Repo layout, Docker Compose (PostgreSQL, Ollama), FastAPI skeleton, config and secrets
- [ ] Write `schemas.py` with Member B; add the stub `analyze()`
- [ ] Database tables and migrations (Alembic); a helper to look up employees for Member B
- [ ] Google sign-in, read-only Gmail OAuth, encrypted token storage
- [ ] Gmail polling job: fetch new message IDs, pass raw MIME to Member B's parser, call `analyze()`, save results
- [ ] `/me/messages`, `/me/messages/{id}`, `/check`, `/me/reports`, feedback endpoints
- [ ] Report to IT: escalation email (SMTP) with band, reasons and evidence
- [ ] Employee directory CSV import
- [ ] Twilio webhook with signature check, bot conversation states, reply formatting, `escalate` command
- [ ] Hand off: FastAPI `/docs` page shared with the team, then start the frontend

**Member B: analysis engine**

- [ ] Safe MIME parser: headers, plain text, HTML to text, URLs, attachment metadata, into `NormalizedMessage`
- [ ] Rule checks with reason codes: SPF/DKIM/DMARC, Reply-To mismatch, display-name tricks, lookalike domains, risky attachments
- [ ] Threat-intel adapters (VirusTotal, PhishTank, URLhaus) with a cache; WHOIS domain age; "not checked" on any failure
- [ ] cybersectony DistilBERT wrapper; confirm which label means phishing email
- [ ] Laya wrapper with the four intent questions
- [ ] SMS-Shield in Ollama with a small client; sender-ID and directory checks
- [ ] Policy layer: band, reasons, evidence ledger; swap out the stub `analyze()`
- [ ] Campaign linker job and the "also sent to N colleagues" count
- [ ] Build and run the 20-message test set, tune thresholds, fill the results table

**Handoff points**

1. Day 1: agree `schemas.py`; both work in parallel from then on.
2. Member B's real `analyze()` replaces the stub; run the test set end to end through the API.
3. Shyamanth's frontend works on stub results until that swap, so neither waits on the other.

## 13. Demo script and test set

The demo tells one attack story across two channels in about five minutes.

**Script**

1. **Normal day.** An employee opens the app; a genuinely urgent invoice from a known vendor shows no badge. Point: we don't scare people about every urgent email.
2. **Credential phish.** A "Microsoft password expires today" email gets a red badge: lookalike domain, 2-day-old domain, URL on a threat list. Tap a reason to see its evidence, then tap Report to IT and show the escalation email arriving.
3. **AI-written BEC.** A polished email "from the CEO" asks to change a vendor's bank account, with no links. The text model alone misses it; Reply-To mismatch and Laya's executive-impersonation + payment-change answers make it Urgent.
4. **WhatsApp follow-up.** On a phone, share a "Hi, it's \[CEO\], new number, need a quick favour" message to the bot. It asks for the sender, then replies Urgent: the number isn't the CEO's number in the directory.
5. **Campaign.** Sign in as a second demo employee who got the same BEC email; the app shows "also sent to 2 colleagues", linking the email and the WhatsApp message.
6. **Close.** Show the results table and the line: "Every employee gets a security expert in their pocket, and AI here has no power to act."

**Test set (write ourselves, about 20 messages)**

| Type | Count | Expected band |
| --- | --- | --- |
| Classic credential phish (fake login, account locked) | 4 | Urgent |
| AI-style BEC email, no links (CEO, vendor bank change, gift cards) | 4 | Urgent or Review |
| Malicious attachment email (invoice.pdf.exe) | 2 | Urgent |
| Indian scam SMS (KYC, delivery, UPI) | 4 | Urgent |
| "New number" WhatsApp impersonation | 2 | Urgent |
| Legitimate but urgent business email and real bank OTP SMS | 4 | Low |

Run it before the demo and record results for rules only, rules + models, and rules + models + Laya.

## 14. Risks, limitations and future scope

The biggest risk is untested off-the-shelf models; our own test set and the rule guardrails are the mitigation.

| Risk | Mitigation |
| --- | --- |
| Employees worry the app reads their mail for the company | Read-only Gmail scope, work account only; IT sees a message only when the employee escalates it |
| Stored Gmail tokens are sensitive | Encrypt tokens; let employees disconnect any time |
| cybersectony label names are unclear; reported 99.58% is same-dataset testing | Confirm labels on known samples; treat it as one signal, not the verdict |
| Laya typed-decisions checkpoint was not trained on phishing | Only simple yes/no questions; rules override it |
| SMS-Shield is trained on synthetic SMS and is slow (seconds) | Use only for shared messages; show its result as one signal |
| Prompt injection inside message text | No model has tools or actions; text is data only |
| Twilio sandbox needs a join code per phone | Join all demo phones before judging |
| Threat-intel API rate limits during the demo | Cache results; pre-run the demo messages |
| Scores are not calibrated | Show bands, not percentages |
| No labelled campaign data | Present campaign linking as a prototype |

**Future scope (for the last slide)**

- Fine-tune a classifier on AI-generated phishing datasets (E-PhishLLM, Toth et al. 2025).
- Microsoft 365 connector and real-time push notifications instead of polling.
- Android companion app for automatic SMS checks on the phone.
- Telugu, Tamil and other Indian languages for message checks.
- Analyst feedback used to retune thresholds.
