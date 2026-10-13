#!/usr/bin/env python
"""Opt-in demo: run DistilBERT and Laya together on synthetic text. EXPERIMENTAL.

Dry run by default: prints the plan and loads nothing. Real inference needs BOTH `--run` and
TWO_MODEL_DEMO=1. Weights come only from the local cache (pinned revisions, hash-checked);
nothing is ever downloaded. Only built-in synthetic examples are used and their text is never
printed. Results are raw model outputs, not verdicts and not accuracy evidence.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.models.email import MODEL_REVISION as EMAIL_REV, EmailClassifierAdapter  # noqa: E402
from engine.models.intent import MODEL_REVISION as INTENT_REV, LayaIntentAdapter  # noqa: E402
from engine.models.runner import TwoModelRunner  # noqa: E402

EXAMPLES = [
    ("ceo_wire_request",
     "Urgent: wire needed today",
     "I am in a meeting and cannot take calls. Please wire 480,000 to the account below today "
     "and keep this confidential until it is done. Alex Morgan, CEO"),
    ("routine_invoice",
     "Invoice 4471",
     "Dear customer, invoice 4471 for 1,250 is due on 5 November. You can pay through your "
     "usual portal. Thank you. Acme Supplies Billing"),
    ("credential_lure",
     "Your mailbox password expires today",
     "Your password expires today. Sign in and enter your current password to keep access to "
     "your mailbox, or it will be suspended within 24 hours."),
    ("benign_meeting_note",
     "Planning meeting",
     "Hi team, the planning meeting moves to Thursday at 3pm. The agenda is attached. "
     "Thanks, Priya"),
    ("empty_message", "", ""),
]


def main(argv=None, *, env=None, out=None, runner=None) -> int:
    env = os.environ if env is None else env
    out = out or sys.stdout
    say = lambda s="": out.write(s + "\n")
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", action="store_true", help="run real local inference")
    args = ap.parse_args(argv)

    say("PLAN: " + ("RUN" if args.run else "DRY RUN (no weights loaded, no network)"))
    say(f"email model : DistilBERT @ {EMAIL_REV[:12]} (class mapping UNRESOLVED)")
    say(f"intent model: Laya typed-decisions @ {INTENT_REV[:12]} (uncalibrated)")
    say(f"examples    : {len(EXAMPLES)} synthetic, text never printed")
    if not args.run:
        say("Dry run only. To execute: TWO_MODEL_DEMO=1 python scripts/two_model_demo.py --run")
        return 0
    if env.get("TWO_MODEL_DEMO") != "1":
        say("REFUSED: --run also requires TWO_MODEL_DEMO=1")
        return 3

    runner = runner or TwoModelRunner(EmailClassifierAdapter(enabled=True, timeout_s=120),
                                      LayaIntentAdapter(enabled=True, timeout_s=120))
    say("")
    say("EXPERIMENTAL RAW OUTPUTS: not verdicts, not accuracy evidence")
    total = time.monotonic()
    for name, subject, body in EXAMPLES:
        r = runner.run(f"{subject}\n\n{body}".strip())
        e, i = r.email, r.intent
        ep = "-" if e.probabilities is None else " ".join(f"{p:.3f}" for p in e.probabilities)
        say(f"{name}")
        say(f"  distilbert: status={e.status.value:<12} out0..3=[{ep}] winner={e.winning_index} "
            f"mapping={e.label_mapping} ({r.email_seconds}s)")
        ip = "-" if i.probabilities is None else " ".join(
            f"{k.split('_')[0]}={v:.3f}" for k, v in i.probabilities.items())
        say(f"  laya      : status={i.status.value:<12} {ip} ({r.intent_seconds}s)")
    say(f"total wall time: {time.monotonic() - total:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
