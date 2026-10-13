# Annotation guide

Applies to schema version `1.0` (`evaluation/schema.py`). Every example below is invented.
Domains use reserved names (`.example`) and people and companies are fictional.

## 0. Principles

1. **Labels describe the text, not the sender's honesty.** A message can have
   `payment_request=true` and be perfectly legitimate. The four content labels never decide
   whether a message is malicious; that is the separate `outcome`.
2. **Label what the text says, not what you suspect.** Judge only the subject and body you can
   see. Do not infer from names, domains or signatures that "this must be fake".
3. **A claim in the text is not a verified identity.** `authority_claim_in_content` records
   that the text asserts authority. Nothing here authenticates a sender. Headers, SPF/DKIM/DMARC
   and directory checks are other parts of the system and are out of scope for labelling.
4. **When two careful readers could disagree, say so.** Use `null` plus `outcome=ambiguous`
   (or `label_status=needs_review`), rather than forcing a guess. Nulls are excluded from
   scoring, which is better than silently noisy labels.
5. **Annotate independently first.** Do not look at another annotator's labels or any model
   output before labelling.

## 1. Fields you set

| Field | Values | Notes |
|---|---|---|
| `labels.authority_claim_in_content` | true / false / null | section 2.1 |
| `labels.payment_request` | true / false / null | section 2.2 |
| `labels.credential_request` | true / false / null | section 2.3 |
| `labels.urgency_secrecy` | true / false / null | section 2.4 |
| `outcome` | legitimate / suspicious / malicious / ambiguous | section 3 |
| `scenario` | see `evaluation/schema.py` | broad category; a stratification aid, not a label |
| `evidence_spans` | per true label: `{field, start, end}` | character offsets into `subject` or `body` |
| `contains_embedded_instruction` | boolean | true if the text addresses a classifier or assistant |
| `language`, `has_url` | see spec | `has_url` is checked automatically against the text |
| `label_status`, `annotation` | see section 5 | who labelled it and how far it was verified |

**Evidence spans** point at the words that justify a `true`. They are required for
independently reviewed positives in strict mode and strongly encouraged otherwise: they let a
reviewer confirm the label from the text in seconds and expose labels given for the wrong reason.

## 2. The four content labels

### 2.1 `authority_claim_in_content`

> Does the message text claim to come from an executive, senior leader, or other authority?

**True** when the subject or body asserts, in the sender's voice, that the sender holds a
position of authority over the recipient's work, money or legal standing: an explicit title or
signature (CEO, CFO, Managing Director, VP, Head of Finance, "Director"), a first-person
statement ("this is Alex, your CEO"), or an institution speaking in an official capacity with
power over the recipient (government or tax authority, court, regulator, law enforcement,
"HR/Legal on behalf of the Board").

**False** when the sender gives only a name, a first name, a routine functional signature
("Accounts", "Operations", "IT Helpdesk"), or a brand voice ("Microsoft Support"), or when the
text merely *mentions* an executive.

| | Example | Label |
|---|---|---|
| Positive | "...Thank you all. Alex Morgan, CEO" | true |
| Positive | "This is a notice from the Income Tax Department regarding your filing." | true |
| Negative | "Hi, it's Sam from accounts. Quick question about the order." | false |
| Negative | "Please send the report to the CFO by Friday." (mentions, does not claim) | false |
| Boundary | "Sent on behalf of the Managing Director" | true: invokes the director's authority as the sender's mandate |
| Boundary | "The CEO asked me to arrange this" | false: a name-drop by a non-authority; note it in `notes` |
| Boundary | "IT Security: your mailbox will be locked" | false unless it asserts a mandate ("by order of the CISO") |
| Ambiguous | "Regards, Jordan (Finance)" with no title | false; if a reader could see "Finance lead", use null |

A legitimate executive announcement is **true** here. That is the point: the label records
the claim and the system must verify it elsewhere.

### 2.2 `payment_request`

> Does the message request payment, a wire transfer, invoice payment, or a bank-account change?

**True** when the text asks the recipient to pay or move value, settle an amount owed, buy
something on the sender's behalf (including gift cards), send cryptocurrency, or change or
supply bank, payee, card or payroll-deposit details that will be used to move money.
A request to pay a stated invoice is true even when routine and legitimate.

**False** when the text only reports a payment (receipt, confirmation), gives a price,
discusses budgets, or offers information with no ask.

| | Example | Label |
|---|---|---|
| Positive | "Please wire 480,000 to the account below today." | true |
| Positive | "Invoice 4471 for 1,250 is due on 5 November; pay through your portal." | true |
| Positive | "Please update my direct deposit to the new account details below." | true |
| Positive | "Buy five 100 gift cards and send me the codes." | true |
| Negative | "Thank you, we received your payment of 1,250. No action needed." | false |
| Negative | "The budget for next year is 2.4 million." | false |
| Boundary | "Could you confirm our bank details on file are still correct? Don't send anything." | null (or false with a note); this is verification, not a request to pay or change |
| Boundary | "Your subscription renews automatically on 1 December for 49." | false: a notice, not a request |
| Boundary | "Reply with your account number so we can refund you." | false here (money would move *to* the recipient); true for `credential_request` (2.3) |

### 2.3 `credential_request`

> Does the message ask the recipient to disclose credentials, authentication codes, or
> sensitive account information?

**True** when the text asks the recipient to supply, enter, read out, reply with, or "verify"
a secret or sensitive account detail: password, PIN, one-time or MFA code, recovery code,
security answers, full card number or CVV, government identity number, or full account
credentials. It is also true for the classic harvesting pattern: telling the recipient to sign
in or "confirm" their details *in order to keep, restore or verify access*.

**False** when the text mentions passwords or codes but asks the recipient to disclose
nothing: security reminders, policy notices, "never share your code" warnings, or a plain
"log in to the portal to view your document".

| | Example | Label |
|---|---|---|
| Positive | "Enter your current password to keep your mailbox active." | true |
| Positive | "Reply with the 6-digit code we just sent to your phone." | true |
| Positive | "Verify your account by confirming your card number and CVV." | true |
| Negative | "Reminder: never share your password or MFA codes. IT will never ask for them." | false |
| Negative | "Our password policy requires a change every 90 days." | false |
| Boundary | "Sign in to the portal to download your statement." | false: directs to authenticate, does not ask to disclose to the sender; URL legitimacy is not a text label |
| Boundary | "Sign in now to avoid suspension of your account." | true: access-retention pressure is the harvesting pattern |
| Ambiguous | "Please confirm your identity with the usual details." | null |

### 2.4 `urgency_secrecy`

> Does the message create urgency, secrecy, or pressure to bypass normal procedures?

**True** when the text contains any of: (a) explicit time pressure ("immediately", "today",
"within 24 hours", "ASAP", "before close of business") or a threatened consequence for delay;
(b) an instruction to keep it secret or confidential from others, or not to verify it by
phone or with colleagues; (c) an instruction to skip or work around the normal approval,
process or review.

**False** for an ordinary deadline or date with no pressure language ("due on 5 November",
"see you Thursday").

| | Example | Label |
|---|---|---|
| Positive | "Keep this confidential until it is done." | true |
| Positive | "Your account will be suspended within 24 hours." | true |
| Positive | "Please skip the usual approval, there is no time." | true |
| Positive (legitimate) | "The conveyor is down; reroute all orders immediately." | true |
| Negative | "Invoice 4471 is due on 5 November." | false |
| Negative | "Let's meet Thursday at 3pm." | false |
| Boundary | "Please reply when you can; ideally this week." | false |
| Boundary | "Urgent: lunch menu updated." | true: urgency language is present even if trivial; the label is about the wording |

## 3. `outcome` (separate from the four labels)

Annotate the outcome *after* the four labels, from the message design as visible in the text
(and, for synthetic data, the author's documented intent).

| Value | Use when |
|---|---|
| `legitimate` | The message reads as ordinary, non-deceptive correspondence. It may still ask for payment or contain urgency. |
| `malicious` | The message is built to deceive the recipient into a harmful action (credential theft, payment fraud, gift-card or payroll diversion). For synthetic data this is the documented intent; for real data it is an established phishing or fraud example from the source. |
| `suspicious` | It contains features that warrant caution but the text alone cannot establish intent. Typical case: an unverified request to change bank details. |
| `ambiguous` | Annotators cannot decide, the content is empty or too short to judge, or the evidence conflicts. Content labels that are clear may still be set. |

Rules:

1. A message with `payment_request=true` and `authority_claim_in_content=true` is **not**
   automatically malicious. Do not derive the outcome from the labels.
2. Do not use `malicious` merely because a message is urgent, short, or poorly written.
3. Empty or content-free messages are `ambiguous` with all content labels `false`.
4. A message containing instructions aimed at a classifier is judged on its other content;
   set `contains_embedded_instruction=true` and use scenario `adversarial_instruction` only
   when that is its main feature.

## 4. Worked boundary cases

| Text | authority | payment | credential | urgency | outcome |
|---|---|---|---|---|---|
| "...we opened our new office. Alex Morgan, CEO" | true | false | false | false | legitimate |
| "Wire 480,000 today. Keep it confidential. Alex Morgan, CEO" | true | true | false | true | malicious |
| "Our bank has changed; use these details for future payments. Northwind Accounts" | false | true | false | false | suspicious |
| "Reminder: IT will never ask for your password." | false | false | false | false | legitimate |
| "Enter your password to avoid suspension." | false | false | true | true | malicious |
| "Thanks, received your payment." | false | false | false | false | legitimate |
| (empty) | false | false | false | false | ambiguous |
| "Hi Sam, could you confirm our bank details are right?" | false | null | false | false | ambiguous |

## 5. Recording who labelled it

`annotation.authored_by` is the person or generator that wrote the text. `annotation.annotators`
lists everyone who assigned labels. `label_status` says how far the labels were verified:

| Status | Meaning | Requirements enforced by the validator |
|---|---|---|
| `provisional` | Labelled by its author or one annotator. **Not independently verified.** | no adjudicator |
| `reviewed` | A second annotator, who is not the author, independently agreed on every label. | at least 2 distinct annotators, one not the author; no disagreement flag |
| `adjudicated` | Annotators disagreed and an adjudicator resolved it. | 2+ annotators, an adjudicator, `initial_disagreement=true` |
| `needs_review` | Unresolved. May contain `null`. Excluded from scoring. | none |

Never mark a record `reviewed` without a real second pass. Do not promote a label by editing
the status alone; the validator can only check consistency, not honesty.

## 6. Disagreement resolution

1. Both annotators label independently, without model output.
2. Compare label by label. If they agree on all four labels and the outcome, status is `reviewed`.
3. If they differ, discuss against this guide. If the guide decides it, the annotators amend
   and the record is `reviewed` only if both then independently confirm.
4. If the guide does not decide it, an adjudicator who did not take part in the discussion
   decides, sets `initial_disagreement=true` and status `adjudicated`, and the case is added to
   section 4 (or the guide is clarified) so the next annotator gets the same rule.
5. If the adjudicator cannot decide: `null` for that label, `outcome=ambiguous`,
   status `needs_review`. Do not coerce.
