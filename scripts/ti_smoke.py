#!/usr/bin/env python
"""Opt-in LIVE smoke test for the threat-intelligence adapters.

This is the only place in the project that can contact VirusTotal, URLhaus, PhishTank or an
RDAP server. It is NOT part of the test suite and is never imported by it (a mocked test
drives `main()` with a fake transport).

Safety properties
  * Dry run by default: prints exactly what WOULD be sent and where. No network.
  * Going live needs BOTH the --confirm-live flag AND environment variable TI_LIVE_SMOKE=1.
  * Only indicators listed in the operator's JSON file are used, and each is approved
    verbatim. Query strings, fragments, credentials and token-like paths are rejected.
  * Keys come from the environment (VIRUSTOTAL_API_KEY, URLHAUS_AUTH_KEY, PHISHTANK_APP_KEY).
    Their values are never printed, not even a prefix or length.
  * Providers must be named explicitly with --providers; nothing is on by default.
  * Output shows redacted indicator references and, with --show-shapes, only the TYPES and key
    names of responses (never values), to help diagnose API format changes.

Usage
  python scripts/ti_smoke.py --indicators scripts/smoke_indicators.example.json \\
         --providers domain_age,urlhaus                       # dry run
  TI_LIVE_SMOKE=1 python scripts/ti_smoke.py --indicators FILE \\
         --providers domain_age,urlhaus --confirm-live --show-shapes
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.threat_intel import (  # noqa: E402
    HttpRequest,
    SharingPolicy,
    StdlibTransport,
    ThreatIntelConfig,
    ThreatIntelService,
)
from engine.threat_intel.config import RATE_LIMIT_BASIS  # noqa: E402
from engine.threat_intel.privacy import (  # noqa: E402
    audit_policy,
    normalize_domain,
    normalize_sha256,
    normalize_url,
)
from engine.threat_intel.providers import default_providers  # noqa: E402
from engine.threat_intel.types import ErrorCategory as E  # noqa: E402

PROVIDER_NAMES = ("urlhaus", "phishtank", "virustotal", "domain_age")
KEY_ENV = {"urlhaus": "URLHAUS_AUTH_KEY", "phishtank": "PHISHTANK_APP_KEY",
           "virustotal": "VIRUSTOTAL_API_KEY", "domain_age": None}
KEY_REQUIRED = {"urlhaus": True, "phishtank": False, "virustotal": True, "domain_age": False}
COMPAT_ERRORS = {E.UNKNOWN_FORMAT, E.MALFORMED_RESPONSE, E.AUTH_FAILED}


# ---------------------------------------------------------------- helpers

def shape_of(obj, depth: int = 0):
    """Structure of a JSON value: key names and type names only, never values."""
    if depth >= 4:
        return "..."
    if isinstance(obj, dict):
        return {str(k)[:40]: shape_of(v, depth + 1) for k, v in list(obj.items())[:25]}
    if isinstance(obj, list):
        return [shape_of(obj[0], depth + 1)] if obj else []
    return type(obj).__name__


class ShapeRecorder:
    """Transport wrapper that remembers response structure (types only) for diagnostics."""

    def __init__(self, inner) -> None:
        self.inner, self.shapes = inner, []

    def request(self, req: HttpRequest, *, timeout: float, max_bytes: int):
        resp = self.inner.request(req, timeout=timeout, max_bytes=max_bytes)
        host = urlsplit(req.url).netloc
        try:
            shape = shape_of(json.loads(resp.body.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            shape = "<not JSON>"
        self.shapes.append((host, resp.status, shape))
        return resp


def _mask(req: HttpRequest) -> str:
    p = urlsplit(req.url)
    segs = p.path.split("/")
    if segs and len(segs[-1]) > 40:
        segs[-1] = "<id>"
    return f"{req.method} {p.netloc}{'/'.join(segs)}"


def _load(path: Path):
    """-> (indicators, policy, problems). Every entry is approved exactly as written."""
    problems: list = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [], SharingPolicy(), [f"cannot read indicators file: {type(e).__name__}"]
    if not isinstance(doc, dict):
        return [], SharingPolicy(), ["indicators file must be a JSON object"]

    inds, urls, domains, hashes = [], set(), set(), set()
    for n, raw in enumerate(doc.get("urls") or [], 1):
        i = normalize_url(str(raw))
        if i is None:
            problems.append(f"urls[{n}]: not a valid http(s) URL")
        elif i.flags:
            problems.append(f"urls[{n}]: has a query string, fragment or credentials; list the bare URL")
        elif i.value != str(raw):
            problems.append(f"urls[{n}]: not in normalised form (expected exactly what is sent)")
        else:
            inds.append(i)
            urls.add(i.value)
    for n, raw in enumerate(doc.get("domains") or [], 1):
        i = normalize_domain(str(raw))
        if i is None or i.value != str(raw):
            problems.append(f"domains[{n}]: must be a lower-case registered domain")
        else:
            inds.append(i)
            domains.add(i.value)
    for n, raw in enumerate(doc.get("sha256") or [], 1):
        i = normalize_sha256(str(raw))
        if i is None or i.value != str(raw):
            problems.append(f"sha256[{n}]: must be 64 lower-case hex characters")
        else:
            inds.append(i)
            hashes.add(i.value)
    policy = SharingPolicy(approved_urls=frozenset(urls), approved_domains=frozenset(domains),
                           approved_sha256=frozenset(hashes))
    problems.extend(audit_policy(policy))
    return inds, policy, problems


# ---------------------------------------------------------------- main

def main(argv=None, *, env=None, transport=None, out=None) -> int:
    env = os.environ if env is None else env
    out = out or sys.stdout
    say = lambda s="": out.write(s + "\n")

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--indicators", required=True, type=Path,
                    help="JSON file: {urls: [], domains: [], sha256: []} of public test indicators")
    ap.add_argument("--providers", required=True,
                    help="comma-separated subset of: " + ", ".join(PROVIDER_NAMES))
    ap.add_argument("--confirm-live", action="store_true",
                    help="actually contact providers (also needs TI_LIVE_SMOKE=1)")
    ap.add_argument("--show-shapes", action="store_true",
                    help="print response key/type structure (no values)")
    args = ap.parse_args(argv)

    chosen = [p.strip() for p in args.providers.split(",") if p.strip()]
    bad = [p for p in chosen if p not in PROVIDER_NAMES]
    if not chosen or bad:
        say(f"error: --providers must be a non-empty subset of {', '.join(PROVIDER_NAMES)}")
        return 1

    inds, policy, problems = _load(args.indicators)
    if problems:
        say("REFUSED: the indicators file is not safe to use:")
        for p in problems:
            say(f"  - {p}")
        return 1
    if not inds:
        say("error: no indicators listed")
        return 1

    cfg = ThreatIntelConfig(
        enabled=True, enabled_providers=frozenset(chosen),
        virustotal_live_enabled="virustotal" in chosen, sharing=policy,
    )
    if len(inds) > cfg.max_indicators_per_message:
        say(f"error: {len(inds)} indicators; the per-message cap is {cfg.max_indicators_per_message}")
        return 1

    live = bool(args.confirm_live and env.get("TI_LIVE_SMOKE") == "1")
    if args.confirm_live and not live:
        say("REFUSED: --confirm-live also requires the environment variable TI_LIVE_SMOKE=1")
        return 3

    # ---- plan (always printed) ----
    say("PLAN: " + ("LIVE run" if live else "DRY RUN (no network)"))
    say("providers: " + ", ".join(chosen))
    for name in chosen:
        var = KEY_ENV[name]
        if var:
            state = "set" if (env.get(var) or "").strip() else "MISSING"
            need = "required" if KEY_REQUIRED[name] else "optional"
            say(f"  key {var}: {state} ({need})")
        say(f"  budget {name}: {RATE_LIMIT_BASIS[name]}")
    providers = [p for p in default_providers() if p.name in chosen]
    n_req = 0
    say("requests that would be sent (lookup only; nothing is uploaded or scanned):")
    for ind in inds:
        for prov in providers:
            if ind.type not in prov.supported:
                continue
            try:
                req = prov.build_request(ind, "x", cfg)
            except Exception as e:                   # e.g. no RDAP server for this TLD
                say(f"  {prov.name:<10} {ind.ref}: not requested ({getattr(e, 'detail', 'n/a')})")
                continue
            n_req += 1
            say(f"  {prov.name:<10} {ind.ref}: {_mask(req)}")
    say(f"total requests: {n_req}")
    if not live:
        say("Dry run only. To go live: set TI_LIVE_SMOKE=1 and add --confirm-live.")
        return 0

    # ---- live ----
    if transport is None:
        if "pytest" in sys.modules:
            say("REFUSED: will not build a real network transport under pytest")
            return 4
        transport = StdlibTransport()
    rec = ShapeRecorder(transport) if args.show_shapes else transport
    key_provider = lambda name: env.get(name)
    svc = ThreatIntelService(cfg, transport=rec, key_provider=key_provider)
    report = svc.lookup_indicators(inds)

    say("")
    say("RESULTS (indicator references are redacted):")
    counts: dict = {}
    compat = False
    for r in report.results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1
        det = ", ".join(f"{k}={v}" for k, v in sorted(r.details.items())
                        if isinstance(v, (int, bool)) or (isinstance(v, str) and len(v) <= 40))
        err = f" error={r.error.value}" if r.error else ""
        if r.error in COMPAT_ERRORS:
            compat = True
        say(f"  [{r.status.value:<11}] {r.provider:<10} {r.indicator_type.value:<6} "
            f"{r.indicator_ref}  {r.category.value}{err}  {det}")
    for name, why in sorted(report.disabled.items()):
        say(f"  [disabled   ] {name}: {why}")
    say("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    say("NOT_FOUND means the provider has no listing. It is not a safety verdict.")

    if args.show_shapes and isinstance(rec, ShapeRecorder):
        say("")
        say("RESPONSE SHAPES (types only, no values):")
        seen = set()
        for host, status, shape in rec.shapes:
            line = f"  {host} HTTP {status}: {json.dumps(shape, sort_keys=True)}"
            if line not in seen:
                seen.add(line)
                say(line)
    if compat:
        say("")
        say("COMPATIBILITY PROBLEM: a provider answered in a format or with a status this "
            "adapter did not expect. Re-run with --show-shapes and compare with the docs.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
