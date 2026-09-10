"""The orchestrator: run every detector, combine, explain.

Kept deliberately thin. All the knowledge lives in the signal modules;
this file only decides *how* to run them and how to present the result.
Adding a new detector is one import and one line in DETECTORS -- that is
the whole extension point.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from .parser import looks_like_raw_email, parse_fields, parse_raw_email
from .signals import attachments, auth, language, links, sender
from .types import Category, Finding, ParsedEmail, score_findings

Detector = Callable[[ParsedEmail], list[Finding]]

DETECTORS: list[tuple[str, Detector]] = [
    ("sender", sender.analyze),
    ("links", links.analyze),
    ("language", language.analyze),
    ("attachments", attachments.analyze),
    ("authentication", auth.analyze),
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# What to tell the user to *do*, keyed by verdict.
ADVICE = {
    "high_risk": [
        "Do not click any link and do not open any attachment.",
        "If you already entered a password, change it now on the real site and everywhere you reused it.",
        "If you entered a one-time code, contact the provider immediately — assume the account is being accessed.",
        "Report it (Gmail: ⋮ → Report phishing) and delete it.",
    ],
    "likely_phishing": [
        "Treat every link and attachment as hostile.",
        "Verify through a channel you control: type the company's address yourself, or call the number on your card.",
        "Report it to your mail provider and, if it's a school account, to Baruch IT.",
    ],
    "suspicious": [
        "Don't act on it yet — the pressure to hurry is itself part of the pattern.",
        "Confirm with the sender through a known-good channel before doing anything.",
        "Check the sender's domain letter by letter against one you know is real.",
    ],
    "low_risk": [
        "Nothing here matched a known phishing pattern, but absence of evidence isn't proof.",
        "A well-crafted, targeted email can look completely clean. Verify independently before any money moves or credentials are entered.",
    ],
}


def analyze_email(
    *,
    raw: str | None = None,
    sender_address: str = "",
    subject: str = "",
    body: str = "",
    reply_to: str = "",
    attachment_names: list[str] | None = None,
) -> dict[str, Any]:
    """Analyze one email and return a fully explained result.

    Accepts either `raw` (a full pasted message) or the loose fields. If
    `raw` is supplied and looks like real headers, it wins; otherwise we
    fall back to treating it as a body, because users paste all sorts of
    things and refusing to answer is a worse product than degrading."""
    started = time.perf_counter()

    if raw and looks_like_raw_email(raw):
        email = parse_raw_email(raw)
        input_mode = "raw_message"
    elif raw:
        email = parse_fields(sender=sender_address, subject=subject, body=raw, reply_to=reply_to,
                             attachments=attachment_names)
        input_mode = "body_only"
    else:
        email = parse_fields(sender=sender_address, subject=subject, body=body, reply_to=reply_to,
                             attachments=attachment_names)
        input_mode = "fields"

    findings: list[Finding] = []
    detector_errors: list[str] = []
    for name, detector in DETECTORS:
        try:
            findings.extend(detector(email))
        except Exception as exc:  # one broken detector must not kill the report
            detector_errors.append(f"{name}: {exc.__class__.__name__}")

    findings = _dedupe(findings)
    score, verdict, label = score_findings(findings)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity.value], f.code))

    return {
        "score": score,
        "verdict": verdict,
        "verdict_label": label,
        "summary": _summarize(findings, score, label),
        "findings": [f.to_dict() for f in findings],
        "by_category": _group(findings),
        "advice": ADVICE[verdict],
        "parsed": {
            "from_display": email.from_display,
            "from_address": email.from_address,
            "reply_to": email.reply_to,
            "subject": email.subject,
            "attachments": email.attachments,
            "link_count": len(links.extract_links(email)),
            "input_mode": input_mode,
        },
        "meta": {
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "detector_errors": detector_errors,
            "engine_version": "0.1.0",
        },
    }


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse repeats of the same code+evidence.

    Phishing mail repeats the same malicious link ten times; reporting it
    ten times would both spam the UI and inflate the score."""
    seen: set[tuple[str, str | None]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.code, f.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _group(findings: list[Finding]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {c.value: [] for c in Category}
    for f in findings:
        grouped[f.category.value].append(f.to_dict())
    return grouped


def _summarize(findings: list[Finding], score: int, label: str) -> str:
    scoring = [f for f in findings if f.severity.value != "info"]
    if not scoring:
        return (
            "No phishing indicators were found. That is not the same as safe — a "
            "targeted message written by a careful attacker can pass every automated "
            "check."
        )
    worst = min(scoring, key=lambda f: SEVERITY_ORDER[f.severity.value])
    return (
        f"{label} ({score}/100). {len(scoring)} indicator"
        f"{'s' if len(scoring) != 1 else ''} found; the strongest is: {worst.title}."
    )
