"""Detector: who is this actually from?

The From header is *unauthenticated by design* -- SMTP lets anyone write
anything there. Almost every consumer phishing email loses right here, if
you know where to look.
"""

from __future__ import annotations

import re

from ..domains import (
    BRAND_DOMAINS,
    FREEMAIL_DOMAINS,
    lookalike_of,
    registrable_domain,
)
from ..types import Category, Finding, ParsedEmail, Severity


def _domain_of(address: str) -> str:
    return address.split("@")[-1].strip().lower() if "@" in (address or "") else ""


def analyze(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    from_domain = _domain_of(email.from_address)
    from_reg = registrable_domain(from_domain)
    display = (email.from_display or "").strip()

    # --- 1. Display name claims a brand the sending domain doesn't own ----
    # "PayPal Service <billing@account-verify.info>". This is the single
    # highest-yield check in the whole engine, because the display name is
    # what mail clients show and the address is what they hide.
    display_lower = display.lower()
    for brand, legit_domains in BRAND_DOMAINS.items():
        # Word-boundary match, not substring: a plain `in` test finds "irs"
        # inside "First National Bank" and "ups" inside "Groups".
        brand_present = re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", display_lower)
        if brand_present and from_reg:
            if from_reg not in legit_domains and not any(
                from_reg.endswith("." + d) for d in legit_domains
            ):
                findings.append(Finding(
                    code="SENDER_BRAND_MISMATCH",
                    category=Category.SENDER,
                    severity=Severity.CRITICAL,
                    title=f"Display name says \"{brand.title()}\" but the address isn't theirs",
                    detail=(
                        f"The sender shows as \"{display}\" but the actual address is "
                        f"{email.from_address}, whose domain is {from_reg}. "
                        f"{brand.title()} sends from: {', '.join(sorted(legit_domains))}."
                    ),
                    why=(
                        "The display name is free text -- the sender types whatever they "
                        "want and your mail app shows it in bold. The address after the @ "
                        "is the part that has to be real. When they disagree, trust the "
                        "address."
                    ),
                    evidence=email.from_address,
                    meta={"brand": brand, "actual_domain": from_reg},
                ))
                break

    # --- 2. Sending domain is a lookalike of a real one -------------------
    if from_reg:
        match = lookalike_of(from_reg)
        if match:
            impersonated, technique = match
            technique_text = {
                "character_substitution": "characters swapped for lookalikes (0 for o, 1 for l, rn for m)",
                "typosquat": "one character different from the real domain",
                "brand_in_hostname": "the brand name glued into a domain they don't own",
            }[technique]
            findings.append(Finding(
                code="SENDER_LOOKALIKE_DOMAIN",
                category=Category.SENDER,
                severity=Severity.CRITICAL,
                title=f"Sending domain imitates {impersonated}",
                detail=(
                    f"{from_reg} is not {impersonated}, but it's built to look like it: "
                    f"{technique_text}."
                ),
                why=(
                    "Registering a near-identical domain costs a few dollars and defeats "
                    "skim-reading. Read domains right-to-left from the final dot: the last "
                    "two labels are the only part that identifies the owner."
                ),
                evidence=from_reg,
                meta={"impersonates": impersonated, "technique": technique},
            ))

    # --- 3. Reply-To points somewhere else --------------------------------
    # Classic in business-email-compromise: the mail looks like it's from
    # your CFO, but your reply goes to the attacker's inbox.
    reply_domain = registrable_domain(_domain_of(email.reply_to))
    if reply_domain and from_reg and reply_domain != from_reg:
        findings.append(Finding(
            code="SENDER_REPLY_TO_MISMATCH",
            category=Category.SENDER,
            severity=Severity.HIGH,
            title="Your reply would go to a different domain",
            detail=(
                f"The mail is from {email.from_address} ({from_reg}) but Reply-To is set "
                f"to {email.reply_to} ({reply_domain}). Hitting Reply sends your answer "
                f"to {reply_domain}, not to the sender you see."
            ),
            why=(
                "Reply-To is a separate header from From. Attackers spoof a trusted From "
                "address and set Reply-To to a mailbox they control, so the conversation "
                "silently moves to them. Legitimate mail rarely crosses domains this way."
            ),
            evidence=email.reply_to,
        ))

    # --- 4. Return-Path (envelope sender) disagrees with From -------------
    return_domain = registrable_domain(_domain_of(email.return_path))
    if return_domain and from_reg and return_domain != from_reg:
        findings.append(Finding(
            code="SENDER_RETURN_PATH_MISMATCH",
            category=Category.SENDER,
            severity=Severity.MEDIUM,
            title="Envelope sender doesn't match the From address",
            detail=(
                f"Return-Path is {email.return_path} ({return_domain}) while From claims "
                f"{from_reg}."
            ),
            why=(
                "Return-Path is the address the sending server actually authenticated as. "
                "A mismatch is normal for mailing lists and some marketing platforms, but "
                "on a message claiming to be your bank it's a strong tell."
            ),
            evidence=email.return_path,
        ))

    # --- 5. Corporate-sounding mail sent from a free mailbox --------------
    if from_domain in FREEMAIL_DOMAINS and display:
        corporate_words = re.search(
            r"(?i)\b(support|security|service|billing|account|admin|helpdesk|"
            r"no-?reply|team|department|payroll|hr|it desk|verification)\b",
            display,
        )
        if corporate_words:
            findings.append(Finding(
                code="SENDER_FREEMAIL_CORPORATE",
                category=Category.SENDER,
                severity=Severity.HIGH,
                title="A 'department' writing from a free email account",
                detail=(
                    f"\"{display}\" was sent from {email.from_address}, a personal "
                    f"{from_domain} address."
                ),
                why=(
                    "Real support, billing and IT departments send from their own company "
                    "domain. Nobody's payroll department runs on Gmail."
                ),
                evidence=email.from_address,
            ))

    # --- 6. Address unreadable or absent ----------------------------------
    if email.from_address and not re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", email.from_address, re.I):
        findings.append(Finding(
            code="SENDER_MALFORMED_ADDRESS",
            category=Category.SENDER,
            severity=Severity.MEDIUM,
            title="Sender address is malformed",
            detail=f"'{email.from_address}' is not a well-formed email address.",
            why=(
                "Malformed addresses often come from bulk sending tools that skip "
                "validation, or are an attempt to confuse filters that parse addresses "
                "differently than your mail client does."
            ),
            evidence=email.from_address,
        ))

    return findings
