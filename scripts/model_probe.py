#!/usr/bin/env python
"""Opt-in probe: what does the email DistilBERT actually output on a few labelled examples?

NOT part of the test suite and never imported by it. It exists to settle the label-mapping
question (the model card and the dataset card disagree) with observed behaviour, and to
confirm output shape. Its output is a set of raw score vectors. It is NOT an accuracy
measurement: about 20 hand-written examples cannot support one, and nothing here should be
quoted as a detection rate.

Safety
  * Dry run by default: prints the plan (repository, pinned revision, files, size). No
    network, no model load.
  * Running needs BOTH --run AND the environment variable MODEL_PROBE=1.
  * Download needs a further explicit --allow-download. Without it, only an already-cached
    copy of the pinned revision is used (--allow-download is never implied).
  * Only the pinned revision is fetched, only the listed files, and weights are loaded from
    `model.safetensors` with use_safetensors=True (no pickle), trust_remote_code=False.
  * Inputs are short synthetic strings. Nothing is fetched from any URL inside them.

Usage
  python scripts/model_probe.py                                   # dry run
  MODEL_PROBE=1 python scripts/model_probe.py --run --allow-download --out probe.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from pathlib import Path
from typing import Callable, Optional

REPO_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
REVISION = "6724dec17360ab1f6450553f1d950404f66a5dde"
FILES = ("config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
         "special_tokens_map.json", "vocab.txt")
APPROX_DOWNLOAD_MB = 269          # 66,956,548 float32 parameters + tokenizer files
MAX_LENGTH = 512                  # model.config.max_position_embeddings

# The two documented, mutually inconsistent readings of the four outputs.
MODEL_CARD_NAMES = ("legitimate_email", "phishing_url", "legitimate_url", "phishing_url_alt")
DATASET_CARD_NAMES = ("legitimate_email", "phishing_email", "legitimate_url", "phishing_url")

# (id, group, human-assigned intent, text). Synthetic and non-sensitive. Domains are made up and
# are never contacted. "expected" is only what a person would call the text; it is not a
# claim about the model.
EXAMPLES = [
    ("legit_business", "email", "legitimate",
     "Hi team, attached is the agenda for Thursday's quarterly planning meeting. Please review "
     "the budget summary beforehand and send any questions to me before the call. Thanks, Maria"),
    ("legit_urgent", "email", "legitimate",
     "URGENT: the production database backup failed last night. Please check the dashboard and "
     "confirm the restore test passes before 10am. I'm on call if you need me. - Dev Ops"),
    ("legit_invoice", "email", "legitimate",
     "Dear customer, invoice 4471 for October is due this Friday. You can review it any time in "
     "your account portal. Thank you for your business. Acme Supplies Billing"),
    ("phish_credential", "email", "phishing",
     "Your Microsoft 365 password expires today. To avoid losing access to your mailbox, verify "
     "your account immediately at http://micros0ft-secure-login.com/verify and enter your "
     "current password. Failure to act will result in account suspension."),
    ("phish_bank", "email", "phishing",
     "Dear customer, we noticed unusual sign-in activity on your account. Your account has been "
     "limited. Click here to confirm your identity and restore access: "
     "http://secure-bankofficial-update.net/login"),
    ("bec_no_url", "email", "phishing",
     "Hi, are you at your desk? I need you to handle something confidential. Our vendor Northwind "
     "has changed their bank account. Please update the payment details and process today's "
     "payment of 480,000 to the new account. Keep this between us until it is done. - Alex"),
    ("giftcard_bec", "email", "phishing",
     "I'm in a meeting and can't talk. I need you to buy 5 gift cards of $100 each for a client "
     "gift. Send me the codes by reply as soon as possible. I will reimburse you. Thanks."),
    ("email_with_susp_url", "email", "phishing",
     "Please review the shared document here: http://docs-share-view.xyz/a8f3k2/open and sign in "
     "with your email password to access it."),
    ("edge_empty", "edge", "n/a", ""),
    ("edge_whitespace", "edge", "n/a", "   \n\t  "),
    ("edge_ok", "edge", "n/a", "ok"),
    ("edge_literal_empty_word", "edge", "n/a", "empty"),
    ("edge_non_english", "edge", "n/a",
     "आपका खाता निलंबित कर दिया गया है। कृपया तुरंत अपना पासवर्ड सत्यापित करें।"),
    ("edge_long", "edge", "n/a",
     "Quarterly update for the team. " * 120 + "Please verify your password at the link below."),
    ("url_legit", "url_only", "legitimate", "https://www.python.org/downloads/"),
    ("url_suspicious", "url_only", "phishing", "http://secure-paypa1-login.verify-account-update.com/signin"),
]

# Follow-up controls added after the first run: padding position, benign transactional wording,
# short BEC variants and degenerate input. Still anecdotal; still not an evaluation.
_FILL = "Quarterly update for the team. " * 120
_PHISH = "Please verify your password at http://micros0ft-secure-login.com/verify now."
EXAMPLES += [
    ("diag_long_phish_first", "diagnostic", "phishing", _PHISH + " " + _FILL),
    ("diag_long_phish_last", "diagnostic", "phishing", _FILL + _PHISH),
    ("diag_phish_sentence_alone", "diagnostic", "phishing", _PHISH),
    ("diag_benign_reschedule", "diagnostic", "legitimate",
     "Hi Sam, can we move tomorrow's 1:1 to 3pm? I have a conflict in the morning. Thanks, Priya"),
    ("diag_benign_internal_invoice", "diagnostic", "legitimate",
     "Reminder: the vendor invoice for October is due Friday. Finance has already approved it, "
     "no action needed from you."),
    ("diag_benign_password_policy", "diagnostic", "legitimate",
     "Reminder from IT: our password policy requires a change every 90 days. You can change "
     "yours in the usual settings page when convenient."),
    ("diag_benign_shipping", "diagnostic", "legitimate",
     "Your order has shipped and will arrive on Thursday. You can track it in your account. "
     "Thank you for shopping with us."),
    ("diag_benign_dear_customer", "diagnostic", "legitimate",
     "Dear customer, your invoice for October is attached. Payment is due within 30 days. "
     "Thank you."),
    ("diag_phish_verify_short", "diagnostic", "phishing",
     "Verify your account now or it will be closed."),
    ("diag_phish_ceo_wire", "diagnostic", "phishing",
     "Please wire 25,000 to the account below today. I'm travelling and unreachable. This is "
     "confidential. - CEO"),
    ("diag_phish_payroll", "diagnostic", "phishing",
     "Hi HR, I changed banks. Please update my direct deposit to the new account before "
     "Friday's payroll. Thanks."),
    ("diag_degenerate_punct", "diagnostic", "n/a", "..."),
    ("diag_degenerate_hello", "diagnostic", "n/a", "hello"),
    ("diag_degenerate_lorem", "diagnostic", "n/a", "lorem ipsum dolor sit amet"),
]


def softmax(logits):
    m = max(logits)
    exps = [math.exp(x - m) for x in logits]
    s = sum(exps)
    return [e / s for e in exps]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_real_model(allow_download: bool, say: Callable[[str], None]):
    """-> (predict(text) -> dict, info dict). Imports heavy libraries lazily."""
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    import torch
    import transformers
    from huggingface_hub import snapshot_download
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    transformers.logging.set_verbosity_error()
    try:
        path = snapshot_download(REPO_ID, revision=REVISION, allow_patterns=list(FILES),
                                 local_files_only=True)
    except Exception:
        if not allow_download:
            raise SystemExit("model is not cached and --allow-download was not given; refusing "
                             "to download")
        say(f"downloading {REPO_ID}@{REVISION[:12]} (about {APPROX_DOWNLOAD_MB} MB) ...")
        path = snapshot_download(REPO_ID, revision=REVISION, allow_patterns=list(FILES))
    root = Path(path)
    if root.name != REVISION:                     # snapshot dir is named by commit hash
        raise SystemExit(f"unexpected snapshot revision {root.name}")

    tok = AutoTokenizer.from_pretrained(root, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        root, local_files_only=True, use_safetensors=True, trust_remote_code=False)
    model.eval()
    info = {
        "repo_id": REPO_ID, "revision": root.name,
        "model_safetensors_sha256": _sha256(root / "model.safetensors"),
        "transformers": transformers.__version__, "torch": torch.__version__,
        "num_labels": model.config.num_labels, "id2label": dict(model.config.id2label),
        "max_position_embeddings": model.config.max_position_embeddings,
        "problem_type": model.config.problem_type,
        "tokenizer_model_max_length": tok.model_max_length,
    }

    def predict(text: str) -> dict:
        full_len = len(tok(text, truncation=False, add_special_tokens=True)["input_ids"])
        enc = tok(text, truncation=True, max_length=MAX_LENGTH, return_tensors="pt")
        with torch.inference_mode():
            logits = model(**enc).logits[0].tolist()
        return {"logits": logits, "tokens": int(enc["input_ids"].shape[1]),
                "tokens_untruncated": full_len, "truncated": full_len > MAX_LENGTH}

    return predict, info


def main(argv=None, *, env=None, out=None, loader=None) -> int:
    env = os.environ if env is None else env
    out = out or sys.stdout
    say = lambda s="": out.write(s + "\n")

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", action="store_true", help="load the model and run inference")
    ap.add_argument("--allow-download", action="store_true",
                    help="permit fetching the pinned revision if it is not cached")
    ap.add_argument("--out", type=Path, help="write the full results as JSON")
    args = ap.parse_args(argv)

    say("PLAN: " + ("RUN" if args.run else "DRY RUN (no network, no model load)"))
    say(f"repository : {REPO_ID}")
    say(f"revision   : {REVISION}  (pinned commit; never 'main')")
    say(f"files      : {', '.join(FILES)}")
    say(f"size       : about {APPROX_DOWNLOAD_MB} MB if not already cached")
    say("weights    : model.safetensors only (no pickle); trust_remote_code=False")
    say(f"examples   : {len(EXAMPLES)} synthetic strings (nothing is fetched from them)")
    if not args.run:
        say("Dry run only. To execute: set MODEL_PROBE=1 and pass --run "
            "(plus --allow-download if the model is not cached).")
        return 0
    if env.get("MODEL_PROBE") != "1":
        say("REFUSED: --run also requires the environment variable MODEL_PROBE=1")
        return 3

    try:
        predict, info = (loader or (lambda: load_real_model(args.allow_download, say)))()
    except SystemExit as e:
        say(f"REFUSED: {e}")
        return 4
    except Exception as e:                         # missing deps, corrupt files, ...
        say(f"ERROR: could not load the model ({type(e).__name__})")
        return 5

    say("")
    say("MODEL INFO")
    for k, v in info.items():
        say(f"  {k}: {v}")

    rows = []
    for ex_id, group, intent, text in EXAMPLES:
        try:
            r = predict(text)
            probs = softmax(r["logits"])
            top = max(range(len(probs)), key=probs.__getitem__)
            rows.append({"id": ex_id, "group": group, "human_label": intent,
                         "chars": len(text), **r, "scores": probs, "argmax": top})
        except Exception as e:
            rows.append({"id": ex_id, "group": group, "human_label": intent,
                         "error": type(e).__name__})

    say("")
    say("RESULTS (softmax over the 4 raw outputs; index = output position)")
    say(f"{'id':<30}{'human':<12}{'tok':>5}  {'out0':>7}{'out1':>7}{'out2':>7}{'out3':>7}  top")
    for r in rows:
        if "error" in r:
            say(f"{r['id']:<30}{r['human_label']:<12}  ERROR {r['error']}")
            continue
        s = r["scores"]
        trunc = "*" if r["truncated"] else " "
        say(f"{r['id']:<30}{r['human_label']:<12}{r['tokens']:>4}{trunc} "
            f"{s[0]:>7.3f}{s[1]:>7.3f}{s[2]:>7.3f}{s[3]:>7.3f}  out{r['argmax']}")
    say("(* = input exceeded the 512-token limit and was truncated)")
    say("")
    say("Readings of each output index under the two documented mappings:")
    for i in range(4):
        say(f"  out{i}: model card = {MODEL_CARD_NAMES[i]:<17} | dataset card = {DATASET_CARD_NAMES[i]}")
    say("")
    say(f"These are raw model outputs on {len(EXAMPLES)} hand-written strings. This is NOT an accuracy")
    say("measurement and the scores are not calibrated probabilities.")

    if args.out:
        args.out.write_text(json.dumps({"info": info, "results": rows,
                                        "note": "raw outputs; not an accuracy measurement"},
                                       indent=2, default=str), encoding="utf-8")
        say(f"full results written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
