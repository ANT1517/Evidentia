"""Deterministic email rule checks.

Every check is a pure function of a NormalizedMessage and an EngineConfig. Nothing here does
I/O: no DNS, no HTTP, no file access. Attachments are judged by file name and declared type
only, which are metadata and not proof of what a file contains.

Each check returns a CheckResult:
  completed  False means the check could not run, or its input could not be trusted.
             The policy layer never treats an incomplete check as clean.
  evidence   ledger rows (FOUND = indicator present, NOT_FOUND = ran and found nothing,
             NOT_CHECKED = could not be completed).
  reasons    plain-language reasons; each cites evidence ids that exist in `evidence`.
  facts      short machine-readable tokens the policy combines (e.g. "attachment.executable").
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime

from .config import EngineConfig
from .domains import (
    domain_label,
    edit_distance,
    email_domain,
    host_of,
    is_ip,
    registered_domain,
    skeleton,
)
from .schemas import (
    Evidence,
    EvidenceStatus as S,
    NormalizedMessage,
    Reason,
    ReasonCode as RC,
)

RULES_VERSION = "0.1.0"

_BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


@dataclass
class CheckResult:
    check: str
    completed: bool
    evidence: list[Evidence] = field(default_factory=list)
    reasons: list[Reason] = field(default_factory=list)
    facts: set[str] = field(default_factory=set)


class _Ledger:
    """Builds evidence rows with deterministic ids ('<check>-<n>')."""

    def __init__(self, check: str, now: datetime) -> None:
        self.check, self.now, self.n = check, now, 0
        self.rows: list[Evidence] = []

    def add(self, type_: str, value: str, source: str, status: S, detail: str = "") -> str:
        self.n += 1
        eid = f"{self.check}-{self.n}"
        self.rows.append(Evidence(
            evidence_id=eid, type=type_, value=_safe(value), source=source,
            status=status, observed_at=self.now, detail=_safe(detail, 300) or None,
        ))
        return eid


def _safe(text: str, limit: int = 120) -> str:
    """Make message-derived text safe to show: escape control and bidi characters, truncate."""
    out = []
    for ch in text or "":
        if ch in _BIDI or unicodedata.category(ch).startswith("C"):
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _tokens(text: str) -> list[str]:
    s = unicodedata.normalize("NFKD", text)
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    return re.sub(r"[^a-z0-9\u0080-￿]+", " ", s).split()


# --------------------------------------------------------------------------- auth

def auth_trust(msg: NormalizedMessage, cfg: EngineConfig) -> tuple[bool, str]:
    """Can the Authentication-Results values on this message be believed?

    Both must hold: the platform fetched it through a trusted path, and the header names
    one of our own authserv-ids. An uploaded .eml fails the first test by default, so a
    forged `Authentication-Results: ...; spf=pass` can never produce a verified result.
    """
    if msg.ingest_source not in cfg.trusted_ingest_sources:
        return False, f"ingest source '{msg.ingest_source.value}' is not a trusted path"
    sid = (msg.auth.authserv_id or "").lower()
    if not sid:
        return False, "header has no authserv-id from a trusted server"
    if sid not in cfg.trusted_authserv_ids:
        return False, f"authserv-id '{_safe(sid, 60)}' is not one of our servers"
    return True, "result added by a trusted receiving server"


_AUTH_CODES = {"spf": RC.SPF_FAIL, "dkim": RC.DKIM_FAIL, "dmarc": RC.DMARC_FAIL}
_AUTH_WHAT = {
    "spf": "the sending server is not authorised to send for this domain (SPF)",
    "dkim": "the message signature does not verify (DKIM)",
    "dmarc": "the message failed the domain's anti-spoofing policy (DMARC)",
}


def check_auth(msg: NormalizedMessage, cfg: EngineConfig, now: datetime, mech: str) -> CheckResult:
    check = f"auth_{mech}"
    led = _Ledger(check, now)
    res = CheckResult(check, completed=False)
    value = getattr(msg.auth, mech)
    trusted, why = auth_trust(msg, cfg)

    if value is None:
        led.add(check, "absent", "authentication-results:absent", S.NOT_CHECKED,
                f"No {mech.upper()} result is present in the headers.")
    elif not trusted:
        led.add(check, value, "authentication-results:untrusted", S.NOT_CHECKED,
                f"Header claims {mech}={_safe(value, 20)} but it is unverified: {why}.")
    elif value == "pass":
        res.completed = True
        led.add(check, value, "authentication-results:trusted", S.NOT_FOUND,
                f"{mech.upper()} passed ({why}).")
    elif value == "fail":
        res.completed = True
        eid = led.add(check, value, "authentication-results:trusted", S.FOUND,
                      f"{mech.upper()} failed ({why}).")
        res.facts |= {"auth.trusted_fail", f"auth.{mech}_fail"}
        dom = registered_domain(email_domain(msg.sender)) if msg.sender else ""
        protected = {registered_domain(d) for d in cfg.protected_domains}
        scope = " This is a domain you rely on." if dom in protected else ""
        res.reasons.append(Reason(
            code=_AUTH_CODES[mech], evidence_ids=[eid],
            text=f"Verified check failed: {_AUTH_WHAT[mech]}.{scope}",
        ))
    elif value == "softfail":
        res.completed = True
        eid = led.add(check, value, "authentication-results:trusted", S.FOUND,
                      f"{mech.upper()} soft-failed ({why}).")
        res.facts |= {"auth.trusted_softfail"}
        res.reasons.append(Reason(
            code=_AUTH_CODES[mech], evidence_ids=[eid],
            text=f"A verified check was only weakly satisfied: {_AUTH_WHAT[mech]} soft-failed.",
        ))
    else:
        led.add(check, value, "authentication-results:trusted", S.NOT_CHECKED,
                f"{mech.upper()} result '{_safe(value, 20)}' is inconclusive.")

    res.evidence = led.rows
    return res


# --------------------------------------------------------------------------- reply-to

def check_reply_to(msg: NormalizedMessage, cfg: EngineConfig, now: datetime) -> CheckResult:
    led = _Ledger("reply_to", now)
    res = CheckResult("reply_to", completed=True)
    if not msg.sender:
        res.completed = False
        led.add("reply_to", "", "rules.reply_to", S.NOT_CHECKED, "Sender address is missing.")
    elif not msg.reply_to:
        led.add("reply_to", "", "rules.reply_to", S.NOT_FOUND, "No Reply-To header.")
    else:
        sd = registered_domain(email_domain(msg.sender))
        rd = registered_domain(email_domain(msg.reply_to))
        if sd and rd and sd != rd:
            eid = led.add("reply_to_mismatch", f"{msg.sender} -> {msg.reply_to}", "rules.reply_to",
                          S.FOUND, f"Sender domain {sd} differs from Reply-To domain {rd}.")
            res.facts.add("reply_to.mismatch")
            res.reasons.append(Reason(
                code=RC.REPLY_TO_MISMATCH, evidence_ids=[eid],
                text=f"Replies would go to {_safe(rd, 60)}, not to the sender's own domain "
                     f"{_safe(sd, 60)}.",
            ))
        else:
            led.add("reply_to", msg.reply_to, "rules.reply_to", S.NOT_FOUND,
                    "Reply-To is in the same domain as the sender.")
    res.evidence = led.rows
    return res


# --------------------------------------------------------------------------- identity

def _has_phrase(tokens: list[str], phrase: str) -> bool:
    p = phrase.split()
    return any(tokens[i:i + len(p)] == p for i in range(len(tokens) - len(p) + 1))


def check_identity(msg: NormalizedMessage, cfg: EngineConfig, now: datetime) -> CheckResult:
    """Display-name impersonation of configured executives, employees and brands."""
    led = _Ledger("identity", now)
    res = CheckResult("identity", completed=True)
    if not msg.sender:
        res.completed = False
        led.add("identity", "", "rules.identity", S.NOT_CHECKED, "Sender address is missing.")
        res.evidence = led.rows
        return res

    sender = msg.sender.lower()
    sdom = registered_domain(email_domain(sender))
    name = msg.sender_display_name
    toks = _tokens(name)
    tokset = set(toks)
    exec_emails = {p.email.lower() for p in cfg.directory if p.executive}
    protected_regs = {registered_domain(d) for d in cfg.protected_domains}

    if sdom and sdom in protected_regs:
        led.add("protected_domain_sender", sdom, "rules.identity", S.FOUND,
                "The sender address is in a protected domain (company or brand).")
        res.facts.add("identity.protected_domain_sender")

    matched_person = False
    for p in cfg.directory:
        ptoks = _tokens(p.name)
        if len(ptoks) >= 2 and set(ptoks) <= tokset and sender != p.email.lower():
            matched_person = True
            fact = "identity.exec_mismatch" if p.executive else "identity.person_mismatch"
            code = RC.EXEC_IMPERSONATION if p.executive else RC.DISPLAY_NAME_SPOOF
            eid = led.add("display_name_identity", name, "rules.identity", S.FOUND,
                          f"Display name matches directory entry '{p.name}' ({p.role}) but the "
                          f"address {sender} is not theirs.")
            res.facts.add(fact)
            res.reasons.append(Reason(
                code=code, evidence_ids=[eid],
                text=f"The name matches {p.name} ({p.role}) but the email address is not "
                     f"{p.name}'s known address.",
            ))

    for b in cfg.brands:
        bsk = skeleton(b.name)
        if bsk and bsk in {skeleton(t) for t in toks}:
            if sdom not in {registered_domain(d) for d in b.domains}:
                eid = led.add("display_name_brand", name, "rules.identity", S.FOUND,
                              f"Display name uses the brand '{b.name}' but the sender domain "
                              f"{sdom} is not one of its domains.")
                res.facts.add("identity.brand_mismatch")
                res.reasons.append(Reason(
                    code=RC.DISPLAY_NAME_SPOOF, evidence_ids=[eid],
                    text=f"The sender presents as {b.name} but the address is from "
                         f"{_safe(sdom, 60)}, which is not a {b.name} domain.",
                ))

    if not matched_person and sender not in exec_emails:
        for t in cfg.executive_titles:
            if _has_phrase(toks, t):
                eid = led.add("display_name_title", name, "rules.identity", S.FOUND,
                              f"Display name claims the title '{t}' but the sender is not a "
                              f"known executive address.")
                res.facts.add("identity.title_claim")
                res.reasons.append(Reason(
                    code=RC.DISPLAY_NAME_SPOOF, evidence_ids=[eid],
                    text="The sender's name claims an executive title, but the address does "
                         "not belong to a known executive.",
                ))
                break

    for addr in _EMAIL_IN_TEXT.findall(name):
        adom = registered_domain(email_domain(addr))
        if adom and sdom and adom != sdom:
            eid = led.add("display_name_address", name, "rules.identity", S.FOUND,
                          f"Display name contains {addr} but the real sender domain is {sdom}.")
            res.facts.add("identity.display_address_mismatch")
            res.reasons.append(Reason(
                code=RC.DISPLAY_NAME_SPOOF, evidence_ids=[eid],
                text="The displayed name contains an email address that is not the real "
                     "sender's address.",
            ))
            break

    if not any(r.status == S.FOUND and r.type.startswith("display_name") for r in led.rows):
        led.add("identity", name, "rules.identity", S.NOT_FOUND,
                "Display name does not impersonate a configured executive, employee or brand.")
    res.evidence = led.rows
    return res


# --------------------------------------------------------------------------- lookalike

_LURE_WORDS = (
    "secure", "security", "login", "signin", "support", "verify", "account", "update",
    "service", "helpdesk", "portal", "billing", "alert", "online", "team", "mail",
)


def _lookalike_method(cand: str, prot: str) -> str:
    """Why `cand` (a domain label) resembles `prot` (a protected label); '' if it doesn't."""
    sc, sp = skeleton(cand), skeleton(prot)
    if not sc or not sp:
        return ""
    if cand == prot:
        return "same name with a different domain ending"
    if sc == sp:
        return "look-alike characters"
    if len(sp) >= 5 and 0 < edit_distance(sc, sp) <= (1 if len(sp) < 9 else 2):
        return "one or two characters different"
    if len(sp) >= 3 and sp in sc.split("-"):
        return "contains the protected name inside a longer domain"
    if len(sp) >= 5 and any(sc in (sp + w, w + sp) for w in _LURE_WORDS):
        return "protected name plus a lure word"
    return ""


def check_lookalike(msg: NormalizedMessage, cfg: EngineConfig, now: datetime) -> CheckResult:
    led = _Ledger("lookalike", now)
    res = CheckResult("lookalike", completed=True)
    if not msg.sender:
        res.completed = False
        led.add("lookalike", "", "rules.lookalike", S.NOT_CHECKED, "Sender address is missing.")
        res.evidence = led.rows
        return res

    candidates: dict[str, str] = {}   # registered domain -> where it was seen
    def add(host: str, where: str) -> None:
        if host and not is_ip(host):
            candidates.setdefault(registered_domain(host), where)
    add(email_domain(msg.sender), "sender address")
    if msg.reply_to:
        add(email_domain(msg.reply_to), "Reply-To address")
    for u in msg.urls:
        h = host_of(u)
        if h:
            add(h, "link")

    protected = {registered_domain(d) for d in cfg.protected_domains}
    found = 0
    for dom, where in candidates.items():
        if dom in protected:
            continue
        label = domain_label(dom)
        for prot in sorted(set(registered_domain(d) for d in cfg.lookalike_targets)):
            method = _lookalike_method(label, domain_label(prot))
            if method:
                if found < cfg.max_items_per_check:
                    eid = led.add("lookalike_domain", dom, "rules.lookalike", S.FOUND,
                                  f"{where}: resembles {prot} ({method}).")
                    res.reasons.append(Reason(
                        code=RC.LOOKALIKE_DOMAIN, evidence_ids=[eid],
                        text=f"The {where} domain {_safe(dom, 60)} imitates {prot}.",
                    ))
                found += 1
                res.facts.add("lookalike.domain")
                if where == "sender address":
                    res.facts.add("lookalike.sender")
                break
    if not found:
        led.add("lookalike", ", ".join(sorted(candidates)) or "-", "rules.lookalike",
                S.NOT_FOUND, "No domain resembles a protected company or brand domain.")
    res.evidence = led.rows
    return res


# --------------------------------------------------------------------------- links

def check_link_mismatch(msg: NormalizedMessage, cfg: EngineConfig, now: datetime) -> CheckResult:
    led = _Ledger("link_mismatch", now)
    res = CheckResult("link_mismatch", completed=True)
    for lm in msg.link_mismatches[: cfg.max_items_per_check]:
        eid = led.add("link_text_mismatch", f"{lm.shown_domain} -> {lm.href_domain}",
                      "rules.links", S.FOUND,
                      f"Link text shows {lm.shown_domain} but the destination is {lm.href_domain}.")
        res.reasons.append(Reason(
            code=RC.LINK_TEXT_MISMATCH, evidence_ids=[eid],
            text=f"A link appears to go to {_safe(lm.shown_domain, 60)} but really goes to "
                 f"{_safe(lm.href_domain, 60)}.",
        ))
        res.facts.add("link.mismatch")
    if not res.reasons:
        led.add("link_mismatch", "", "rules.links", S.NOT_FOUND,
                "No link text disagrees with its destination.")
    res.evidence = led.rows
    return res


# --------------------------------------------------------------------------- attachments

def _classify_attachment(name: str, ctype: str, cfg: EngineConfig) -> tuple[str, str]:
    """-> (fact, human explanation) or ('', '') if nothing suspicious. Name/type only."""
    logical = name.replace("\\", "/").rsplit("/", 1)[-1].rstrip(" .").casefold()
    parts = logical.split(".")
    exts = parts[1:] if len(parts) > 1 else []
    final = exts[-1] if exts else ""
    bidi = any(ch in _BIDI for ch in name)
    double = len(exts) >= 2 and exts[-2] in cfg.decoy_exts

    if final in cfg.executable_exts:
        how = f" disguised with a .{exts[-2]} extension" if double else ""
        return "attachment.executable", f"file name ends in .{final}, an executable type{how}"
    if final in cfg.macro_exts:
        return "attachment.macro", f"file name ends in .{final}, a macro-capable Office type"
    if final in cfg.risky_other_exts:
        return "attachment.risky_other", f".{final} files are a common phishing carrier"
    if any(e in cfg.executable_exts for e in exts[:-1]):
        return "attachment.risky_other", "an executable extension appears inside the name"
    if ctype.lower() in cfg.executable_mime_types:
        return "attachment.risky_other", f"declared type {ctype} is an executable type"
    if bidi:
        return "attachment.risky_other", "file name contains text-direction override characters"
    return "", ""


def check_attachments(msg: NormalizedMessage, cfg: EngineConfig, now: datetime) -> CheckResult:
    led = _Ledger("attachments", now)
    res = CheckResult("attachments", completed=True)
    for att in msg.attachments:
        fact, why = _classify_attachment(att.filename, att.content_type, cfg)
        if not fact:
            continue
        eid = led.add("risky_attachment", att.filename, "rules.attachments", S.FOUND,
                      f"{why}. Judged from the file name and declared type only; the file was "
                      f"not opened and its real contents are unknown.")
        res.facts.add(fact)
        res.reasons.append(Reason(
            code=RC.RISKY_ATTACHMENT, evidence_ids=[eid],
            text=f"Attachment '{_safe(att.filename, 60)}': {why}. Do not open it.",
        ))
    if not res.reasons:
        n = len(msg.attachments)
        led.add("attachments", str(n), "rules.attachments", S.NOT_FOUND,
                "No attachment has a risky file name." if n else "No attachments.")
    res.evidence = led.rows
    return res


# --------------------------------------------------------------------------- runner

def run_rules(msg: NormalizedMessage, cfg: EngineConfig, now: datetime) -> list[CheckResult]:
    """All email rule checks in a fixed order."""
    return [
        check_auth(msg, cfg, now, "spf"),
        check_auth(msg, cfg, now, "dkim"),
        check_auth(msg, cfg, now, "dmarc"),
        check_reply_to(msg, cfg, now),
        check_identity(msg, cfg, now),
        check_lookalike(msg, cfg, now),
        check_link_mismatch(msg, cfg, now),
        check_attachments(msg, cfg, now),
    ]
