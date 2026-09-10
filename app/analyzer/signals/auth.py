"""Detector: did the mail cryptographically prove where it came from?

This is the Security+ material, applied. Three protocols work together:

  SPF   -- the domain publishes a DNS record listing which servers may
           send for it. Checks the *envelope* sender.
  DKIM  -- the sending server signs the message with a private key; the
           public key lives in DNS. Proves the body wasn't altered and
           that the signing domain approved it.
  DMARC -- ties the two to the visible From header ("alignment") and
           tells receivers what to do on failure: none / quarantine /
           reject.

The receiving mail server runs these checks and writes the outcome into
an `Authentication-Results` header. We read that header rather than
re-running the checks ourselves, because by the time you have the message
the original connection is long gone and SPF is no longer verifiable.
"""

from __future__ import annotations

import re

from ..domains import registrable_domain
from ..types import Category, Finding, ParsedEmail, Severity

RESULT_RE = {
    "spf": re.compile(r"(?i)\bspf\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)"),
    "dkim": re.compile(r"(?i)\bdkim\s*=\s*(pass|fail|none|policy|neutral|permerror|temperror)"),
    "dmarc": re.compile(r"(?i)\bdmarc\s*=\s*(pass|fail|bestguesspass|none|permerror|temperror)"),
}

EXPLAIN = {
    "spf": (
        "SPF checks whether the server that delivered this mail is on the list the "
        "domain published in DNS. A fail means an unauthorised server sent it."
    ),
    "dkim": (
        "DKIM is a cryptographic signature over the message. A fail means either the "
        "signature doesn't verify or the content was modified in transit."
    ),
    "dmarc": (
        "DMARC is the one that matters most for spoofing: it requires the "
        "authenticated domain to match the From address you actually see. A DMARC "
        "fail on a message claiming to be a major brand means the From header is forged."
    ),
}


def analyze(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    # Only meaningful when the user pasted real headers.
    if not email.headers:
        return findings

    auth_header = " ".join(
        value for key, value in email.headers.items()
        if key in {"authentication-results", "arc-authentication-results", "received-spf"}
    )

    if not auth_header:
        findings.append(Finding(
            code="AUTH_NO_RESULTS",
            category=Category.AUTHENTICATION,
            severity=Severity.INFO,
            title="No email-authentication results present",
            detail="The headers contain no Authentication-Results line, so SPF/DKIM/DMARC can't be read.",
            why=(
                "Most major providers add this header. Its absence usually means the mail "
                "was forwarded, came from an internal relay, or the headers were pasted "
                "incompletely — not that anything is wrong."
            ),
        ))
        return findings

    results: dict[str, str] = {}
    for mechanism, pattern in RESULT_RE.items():
        match = pattern.search(auth_header)
        if match:
            results[mechanism] = match.group(1).lower()

    hard_failures = [m for m, r in results.items() if r == "fail"]
    soft_failures = [m for m, r in results.items() if r in {"softfail", "permerror", "temperror", "neutral"}]

    if "dmarc" in hard_failures:
        findings.append(Finding(
            code="AUTH_DMARC_FAIL",
            category=Category.AUTHENTICATION,
            severity=Severity.CRITICAL,
            title="DMARC failed — the From address is not authenticated",
            detail=f"Authentication results report dmarc=fail (spf={results.get('spf', 'n/a')}, dkim={results.get('dkim', 'n/a')}).",
            why=EXPLAIN["dmarc"],
            evidence=auth_header[:200],
            meta={"results": results},
        ))
    else:
        for mechanism in hard_failures:
            findings.append(Finding(
                code=f"AUTH_{mechanism.upper()}_FAIL",
                category=Category.AUTHENTICATION,
                severity=Severity.HIGH,
                title=f"{mechanism.upper()} check failed",
                detail=f"Authentication results report {mechanism}=fail.",
                why=EXPLAIN[mechanism],
                evidence=auth_header[:200],
                meta={"results": results},
            ))

    for mechanism in soft_failures:
        findings.append(Finding(
            code=f"AUTH_{mechanism.upper()}_SOFT",
            category=Category.AUTHENTICATION,
            severity=Severity.LOW,
            title=f"{mechanism.upper()} did not pass cleanly ({results[mechanism]})",
            detail=f"Authentication results report {mechanism}={results[mechanism]}.",
            why=(
                EXPLAIN[mechanism]
                + " A soft or error result is inconclusive — often caused by forwarding, "
                "which breaks SPF legitimately."
            ),
            evidence=auth_header[:200],
            meta={"results": results},
        ))

    # DKIM signing domain that doesn't align with the visible From is the
    # textbook DMARC-alignment failure, worth surfacing even when DMARC
    # itself reported pass (some relays report loosely).
    dkim_sig = email.headers.get("dkim-signature", "")
    signing_domain = ""
    match = re.search(r"(?i)\bd\s*=\s*([a-z0-9.\-]+)", dkim_sig)
    if match:
        signing_domain = registrable_domain(match.group(1))
    from_domain = registrable_domain(email.from_address.split("@")[-1]) if "@" in email.from_address else ""
    if signing_domain and from_domain and signing_domain != from_domain and results.get("dmarc") != "pass":
        findings.append(Finding(
            code="AUTH_DKIM_MISALIGNED",
            category=Category.AUTHENTICATION,
            severity=Severity.MEDIUM,
            title="DKIM signature belongs to a different domain than the From address",
            detail=f"Signed by {signing_domain}, but the message claims to be from {from_domain}.",
            why=(
                "DMARC alignment requires the signing domain to match the visible From "
                "domain. Bulk-mail providers legitimately sign with their own domain, so "
                "check whether the signer is a known sending platform before concluding "
                "anything."
            ),
            evidence=signing_domain,
        ))

    # Positive signal: everything passed. Reported as INFO (zero weight) so
    # it shows in the UI without moving the score.
    if results.get("dmarc") == "pass" and not hard_failures:
        findings.append(Finding(
            code="AUTH_ALL_PASS",
            category=Category.AUTHENTICATION,
            severity=Severity.INFO,
            title="SPF/DKIM/DMARC all passed",
            detail=f"Results: {', '.join(f'{k}={v}' for k, v in sorted(results.items()))}.",
            why=(
                "The sending domain is authenticated — the From address really does belong "
                "to whoever controls that domain. Note what this does NOT prove: an "
                "attacker who registers paypal-secure.info can pass DMARC perfectly for "
                "their own domain. Authentication proves origin, not trustworthiness."
            ),
            meta={"results": results},
        ))

    return findings
