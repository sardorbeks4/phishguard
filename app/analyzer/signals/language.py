"""Detector: social engineering in the text itself.

Phishing is a psychology exploit wrapped in a technical one. The text is
engineered to push you past the moment where you'd normally think, using
a small, stable set of levers: urgency, fear, authority, reward, secrecy.

Calibration note: language signals are the *weakest* class of evidence
here, because legitimate mail is also sometimes urgent. They are scored
low on their own and mostly serve to push an already-suspicious message
over the line. The exceptions are the payment-fraud and credential-request
patterns, which have essentially no legitimate counterpart.
"""

from __future__ import annotations

import re

from ..types import Category, Finding, ParsedEmail, Severity

# Each family: (regex, human label). Written as word-boundary regexes so
# "account" doesn't match inside "accountant".
PRESSURE_FAMILIES: dict[str, list[tuple[str, str]]] = {
    "urgency": [
        (r"\b(within|in)\s+(24|48|12|72)\s*(hours?|hrs?)\b", "a countdown deadline"),
        (r"\b(immediately|urgent(ly)?|right away|as soon as possible|asap)\b", "urgency wording"),
        (r"\b(act|respond|reply|confirm|verify|update)\s+now\b", "a demand to act now"),
        (r"\b(expir(es?|ing|ed)|deadline|last (chance|warning)|final notice)\b", "an expiry threat"),
        (r"\btime[- ]sensitive\b", "time-pressure framing"),
    ],
    "fear": [
        (r"\b(suspend(ed|ing)?|deactivat(ed?|ion)|disabl(ed?|ing)|terminat(ed?|ion))\b",
         "a threat to close your account"),
        (r"\b(unauthorized|suspicious|unusual)\s+(access|activity|login|sign[- ]?in|transaction)\b",
         "a claimed security incident"),
        (r"\b(locked|restricted|on hold|limited)\s+(your\s+)?(account|access)\b", "an account-lock claim"),
        (r"\b(legal action|prosecut(e|ion)|lawsuit|penalt(y|ies)|fine)\b", "a legal threat"),
        (r"\b(virus|malware|infected|compromised)\b", "an infection claim"),
    ],
    "reward": [
        (r"\b(you('ve| have)?\s+won|winner|congratulations|prize|jackpot|lottery)\b", "a prize claim"),
        (r"\b(refund|reimbursement|rebate|cash ?back|compensation)\s+(of|is|due|pending|awaiting)\b",
         "an unexpected refund"),
        (r"\b(free|complimentary)\s+(gift|voucher|reward|iphone|gift ?card)\b", "a free-gift offer"),
        (r"\b(inheritance|beneficiary|unclaimed funds|next of kin)\b", "an inheritance story"),
    ],
    "authority": [
        (r"\b(ceo|cfo|president|director|manager)\b.{0,40}\b(request(ed|ing)?|need|asked)\b",
         "an appeal to a senior person"),
        (r"\b(irs|internal revenue|tax (office|authority)|hmrc|social security administration)\b",
         "a government-agency claim"),
        (r"\bit (department|desk|support|helpdesk)\b.{0,60}\b(requires?|must|need)\b",
         "an IT-department demand"),
    ],
    "secrecy": [
        (r"\b(do not|don't|please don't)\s+(tell|share|discuss|inform|forward)\b", "a request for secrecy"),
        (r"\b(keep this|this must remain)\s+(confidential|between us|private|discreet)\b",
         "a confidentiality demand"),
        (r"\bi(')?m (currently )?in a meeting\b", "an excuse to avoid verification"),
        (r"\b(can'?t|cannot|unable to)\s+(talk|call|speak|be reached)\b", "a reason you can't call back"),
    ],
}

# These have no benign twin. A real company never asks for these by email.
CREDENTIAL_REQUESTS = [
    (r"\b(confirm|verify|update|re-?enter|provide|submit)\s+(your\s+)?"
     r"(password|passcode|pin|credentials|login details|account details)\b",
     "asks you to supply your password or PIN"),
    (r"\b(one[- ]?time|verification|security|authentication)\s+(code|passcode|pin)\b.{0,80}"
     r"\b(send|share|reply|provide|forward|text|give)\b",
     "asks for a one-time / MFA code"),
    (r"\b(send|share|reply with|forward)\b.{0,40}\b(otp|2fa|mfa|verification code)\b",
     "asks you to forward a two-factor code"),
    (r"\b(social security|ssn|national insurance)\s*(number|#)\b", "asks for a government ID number"),
    (r"\b(full\s+)?(card|credit card|debit card)\s*(number|details)\b.{0,60}\b(confirm|verify|provide|update|enter)\b",
     "asks for full card details"),
]

PAYMENT_FRAUD = [
    (r"\b(gift ?cards?|itunes card|google play card|steam card|apple card)\b.{0,80}"
     r"\b(buy|purchase|send|scratch|code|redeem)\b",
     "gift-card purchase"),
    (r"\b(buy|purchase|get)\b.{0,40}\b(gift ?cards?)\b", "gift-card purchase"),
    (r"\b(wire|bank)\s+transfer\b.{0,80}\b(urgent|today|immediately|asap|new account)\b",
     "an urgent wire transfer"),
    (r"\b(updated?|new|changed)\s+(bank(ing)?|account|payment|wire)\s+(details|information|instructions)\b",
     "changed payment instructions"),
    (r"\b(bitcoin|btc|ethereum|crypto(currency)?|usdt)\b.{0,60}\b(send|transfer|pay(ment)?|wallet)\b",
     "a cryptocurrency payment"),
]

GENERIC_GREETINGS = re.compile(
    r"(?im)^\s*(dear\s+(customer|user|client|member|sir/?\s*madam|account holder|valued\s+\w+)|"
    r"hello\s+(user|customer|member)|attention\s+(customer|user))\b"
)


def analyze(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    text = email.searchable_text
    if not text.strip():
        return findings

    # --- 1. Payment fraud: highest-confidence language signal ------------
    for pattern, label in PAYMENT_FRAUD:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            findings.append(Finding(
                code="LANG_PAYMENT_FRAUD",
                category=Category.LANGUAGE,
                severity=Severity.CRITICAL,
                title="The message steers you toward an irreversible payment",
                detail=f"It references {label}: \"{_snippet(match.group(0))}\"",
                why=(
                    "Gift cards, wire transfers and crypto are the payment rails attackers "
                    "choose precisely because the money cannot be recalled once sent. No "
                    "employer, agency or utility settles a debt in gift cards -- that "
                    "request is fraud 100% of the time."
                ),
                evidence=_snippet(match.group(0)),
            ))
            break

    # --- 2. Credential / MFA harvesting ----------------------------------
    for pattern, label in CREDENTIAL_REQUESTS:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            findings.append(Finding(
                code="LANG_CREDENTIAL_REQUEST",
                category=Category.LANGUAGE,
                severity=Severity.HIGH,
                title="The message asks for secrets directly",
                detail=f"It {label}: \"{_snippet(match.group(0))}\"",
                why=(
                    "Your provider already knows your password and never needs it back. A "
                    "one-time code is the last thing standing between an attacker who "
                    "already has your password and your account -- which is exactly why "
                    "they ask for it."
                ),
                evidence=_snippet(match.group(0)),
            ))
            break

    # --- 3. Pressure families --------------------------------------------
    # Scored by how many *distinct* levers are pulled. One urgent phrase is
    # nothing; urgency plus fear plus secrecy in one short email is a
    # manipulation pattern.
    hits: dict[str, list[str]] = {}
    for family, patterns in PRESSURE_FAMILIES.items():
        for pattern, label in patterns:
            match = re.search(pattern, text, re.I | re.S)
            if match:
                hits.setdefault(family, []).append(f"{label} (\"{_snippet(match.group(0), 60)}\")")
                break

    if hits:
        families = sorted(hits)
        severity = (
            Severity.HIGH if len(families) >= 3
            else Severity.MEDIUM if len(families) == 2
            else Severity.LOW
        )
        bullets = "; ".join(item for items in hits.values() for item in items)
        findings.append(Finding(
            code="LANG_PRESSURE_TACTICS",
            category=Category.LANGUAGE,
            severity=severity,
            title=(
                f"Uses {len(families)} manipulation lever{'s' if len(families) > 1 else ''}: "
                f"{', '.join(families)}"
            ),
            detail=f"Detected {bullets}.",
            why=(
                "Urgency, fear and secrecy exist in the message to stop you doing the one "
                "thing that defeats the attack: pausing to check through a channel the "
                "sender doesn't control. The more levers stacked in a short message, the "
                "more deliberate the engineering."
            ),
            evidence=None,
            meta={"families": families},
        ))

    # --- 4. Generic greeting ---------------------------------------------
    greeting = GENERIC_GREETINGS.search(text)
    if greeting:
        findings.append(Finding(
            code="LANG_GENERIC_GREETING",
            category=Category.LANGUAGE,
            severity=Severity.LOW,
            title="Greets you generically instead of by name",
            detail=f"Opens with \"{_snippet(greeting.group(0), 50)}\".",
            why=(
                "A company that holds an account for you knows your name and normally uses "
                "it. Bulk phishing goes to thousands of addresses at once, so it can't. "
                "Weak on its own -- plenty of real newsletters do this too."
            ),
            evidence=_snippet(greeting.group(0), 50),
        ))

    return findings


def _snippet(text: str, limit: int = 90) -> str:
    cleaned = re.sub(r"\s+", " ", (text or "")).strip()
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"
