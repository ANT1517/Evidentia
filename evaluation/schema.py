"""Record schema constants for the labelled evaluation corpus.

This package is evaluation tooling only. It is deliberately independent of `engine/`: it
imports nothing from the production engine and nothing here is used by `analyze()`.

One record per line in a JSON Lines file. See docs/evaluation_dataset_spec.md for the
meaning of every field and docs/annotation_guide.md for how to label.
"""
from __future__ import annotations

SCHEMA_VERSION = "1.0"

# ---- the four content labels. They describe the TEXT, not whether it is malicious. ----------
INTENT_LABELS = (
    "authority_claim_in_content",   # text claims to come from an executive / senior leader / authority
    "payment_request",             # text asks for a payment, transfer, invoice payment, bank-detail change
    "credential_request",          # text asks the recipient to disclose credentials, codes, sensitive account data
    "urgency_secrecy",             # text creates urgency, secrecy, or pressure to bypass procedure
)

# ---- message-level outcome: separate from the labels above ----------------------------------
OUTCOMES = ("legitimate", "suspicious", "malicious", "ambiguous")

# ---- how trustworthy a record's labels are -------------------------------------------------
LABEL_STATUSES = (
    "provisional",    # labelled by its author/one annotator only; NOT independently verified
    "reviewed",       # a second annotator independently agreed on every label
    "adjudicated",    # annotators disagreed and an adjudicator resolved it
    "needs_review",   # unresolved; labels may be null; excluded from scoring
)
INDEPENDENT_STATUSES = ("reviewed", "adjudicated")

SPLITS = ("dev", "calibration", "test", "unassigned")
SCORED_SPLITS = ("dev", "calibration", "test")

SCENARIOS = (
    "transactional_legit",         # receipts, invoices, shipping, statements
    "internal_business_legit",     # ordinary colleague / vendor correspondence
    "executive_announcement_legit",
    "security_notice_legit",       # password-policy reminders, phishing-awareness notes
    "urgent_ops_legit",            # genuine operational urgency
    "credential_phish",            # credential or code harvesting
    "bec_executive_payment",       # executive impersonation asking for payment/wire
    "bec_giftcard",
    "bec_payroll_change",
    "vendor_bank_change",
    "malicious_link",              # link-led attack not covered above
    "no_url_attack",               # attack with no URL or attachment
    "short_or_empty",
    "ambiguous",
    "adversarial_instruction",     # embeds instructions aimed at the classifier
    "other",
)

LANGUAGES = ("en", "hi", "hi-Latn", "mixed", "other")   # hi-Latn = Hindi in Latin script (Hinglish)
PRIMARY_LANGUAGES = ("en",)                              # the only language scored in v1
CHANNELS = ("email",)

SOURCE_TYPES = ("synthetic", "public_dataset", "licensed_corpus", "contributed")
GENERATORS = ("human", "template", "llm", "dataset")
LICENSES = ("project-synthetic", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0", "MIT", "Apache-2.0",
            "ODC-By-1.0")

# ---- limits ---------------------------------------------------------------------------------
MAX_SUBJECT_CHARS = 300
MAX_BODY_CHARS = 20_000
ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{2,63}$"
GROUP_PATTERN = r"^[a-z0-9][a-z0-9_-]{2,63}$"
ANNOTATOR_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"

REQUIRED_FIELDS = (
    "schema_version", "id", "subject", "body", "language", "channel", "has_url", "scenario",
    "labels", "outcome", "label_status", "annotation", "provenance", "group_id", "split",
)
OPTIONAL_FIELDS = ("evidence_spans", "contains_embedded_instruction", "notes")
ALL_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS


def json_schema() -> dict:
    """JSON Schema (draft 2020-12) generated from the constants above, for external tooling.

    It captures structure, enums and limits only. Cross-field rules (null labels, status vs
    annotators, has_url vs text, provenance conditions, splits and groups) are enforced by
    evaluation/validate.py, which is the source of truth.
    """
    enum = lambda vals: {"enum": list(vals)}
    span = {"type": "object", "additionalProperties": False,
            "required": ["field", "start", "end"],
            "properties": {"field": enum(("subject", "body")),
                           "start": {"type": "integer", "minimum": 0},
                           "end": {"type": "integer", "minimum": 1}}}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Phishing / intent evaluation record",
        "description": "One JSON Lines record. Structural schema only; see evaluation/validate.py "
                       "for cross-field rules.",
        "type": "object",
        "additionalProperties": False,
        "required": list(REQUIRED_FIELDS),
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "id": {"type": "string", "pattern": ID_PATTERN},
            "subject": {"type": "string", "maxLength": MAX_SUBJECT_CHARS},
            "body": {"type": "string", "maxLength": MAX_BODY_CHARS},
            "language": enum(LANGUAGES),
            "channel": enum(CHANNELS),
            "has_url": {"type": "boolean"},
            "scenario": enum(SCENARIOS),
            "labels": {
                "type": "object", "additionalProperties": False,
                "required": list(INTENT_LABELS),
                "properties": {k: {"type": ["boolean", "null"]} for k in INTENT_LABELS},
            },
            "outcome": enum(OUTCOMES),
            "label_status": enum(LABEL_STATUSES),
            "annotation": {
                "type": "object", "additionalProperties": False,
                "required": ["authored_by", "annotators"],
                "properties": {
                    "authored_by": {"type": "string", "pattern": ANNOTATOR_PATTERN},
                    "annotators": {"type": "array", "minItems": 1, "uniqueItems": True,
                                   "items": {"type": "string", "pattern": ANNOTATOR_PATTERN}},
                    "adjudicator": {"type": ["string", "null"], "pattern": ANNOTATOR_PATTERN},
                    "initial_disagreement": {"type": "boolean"},
                },
            },
            "provenance": {
                "type": "object",
                "required": ["source_type", "license", "generator"],
                "properties": {
                    "source_type": enum(SOURCE_TYPES),
                    "license": enum(LICENSES),
                    "generator": enum(GENERATORS),
                    "generator_model": {"type": "string"},
                    "author": {"type": "string"},
                    "source_id": {"type": "string"},
                    "retrieved_on": {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"},
                    "redaction_applied": {"type": "boolean"},
                },
            },
            "group_id": {"type": "string", "pattern": GROUP_PATTERN},
            "split": enum(SPLITS),
            "evidence_spans": {
                "type": "object", "additionalProperties": False,
                "properties": {k: {"type": "array", "minItems": 1, "items": span}
                               for k in INTENT_LABELS},
            },
            "contains_embedded_instruction": {"type": "boolean"},
            "notes": {"type": "string", "maxLength": 500},
        },
    }
