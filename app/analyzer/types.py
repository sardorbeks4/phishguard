"""Core data structures shared by every detector.

Design note
-----------
A detector never returns a bare number. It returns *Findings* -- each one
carries the evidence that triggered it and a plain-English explanation.
The score is derived from the findings, not the other way around. That
ordering is what makes the product teachable instead of a black box.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """How much a single finding moves the needle.

    The numeric weight is the probability (0-1) that this signal alone
    indicates phishing. See `score_findings` for how they combine.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return {
            "info": 0.00,
            "low": 0.12,
            "medium": 0.30,
            "high": 0.55,
            "critical": 0.80,
        }[self.value]


class Category(str, Enum):
    """Which family a finding belongs to. Drives UI grouping and the
    'what should I learn from this' section."""

    SENDER = "sender"
    LINKS = "links"
    LANGUAGE = "language"
    ATTACHMENTS = "attachments"
    AUTHENTICATION = "authentication"


@dataclass(frozen=True)
class Finding:
    """One piece of evidence.

    Attributes
    ----------
    code:        stable machine ID, e.g. "SENDER_BRAND_MISMATCH". Never
                 change these once shipped -- the frontend, the training
                 module and any future analytics key off them.
    title:       short human label for the UI.
    detail:      what we actually observed, quoting the evidence.
    why:         the teaching moment -- why this pattern is a red flag.
    evidence:    the exact substring/value, so the UI can highlight it.
    """

    code: str
    category: Category
    severity: Severity
    title: str
    detail: str
    why: str
    evidence: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "why": self.why,
            "evidence": self.evidence,
            "meta": self.meta,
        }


@dataclass
class ParsedEmail:
    """Normalised view of an email, whatever format it arrived in.

    We accept two shapes of input: a full RFC-822 message (headers +
    body, what you get from 'Show original' in Gmail) or just the loose
    fields a user can copy off the screen. Both are funnelled into this
    one struct so detectors never care which happened.
    """

    from_display: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    attachments: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    @property
    def searchable_text(self) -> str:
        """Subject + body, for language detectors.

        Most real phishing is HTML-only, so a language detector that read
        `body_text` alone would see nothing at all. We strip tags off the
        HTML part and append it. Tag-stripping is done with a regex and the
        result is only ever pattern-matched, never rendered.
        """
        import re
        from html import unescape

        parts = [self.subject, self.body_text]
        if self.body_html:
            # Drop script/style bodies entirely, then remove remaining tags.
            cleaned = re.sub(
                r"(?is)<(script|style)\b.*?</\1>", " ", self.body_html
            )
            cleaned = re.sub(r"<[^>]+>", " ", cleaned)
            parts.append(unescape(cleaned))
        return "\n".join(p for p in parts if p)


VERDICT_BANDS = [
    (75, "high_risk", "Almost certainly phishing"),
    (50, "likely_phishing", "Likely phishing"),
    (25, "suspicious", "Suspicious - verify before acting"),
    (0, "low_risk", "No strong phishing signals found"),
]


def score_findings(findings: list[Finding]) -> tuple[int, str, str]:
    """Combine findings into a 0-100 risk score.

    Why not just add the weights up? Because three medium signals would
    then outrank one critical signal, and you'd blow past 100 on a
    long email. Instead we treat each finding as an independent
    probability that the mail is malicious and combine them with the
    complement rule:

        P(phish) = 1 - product of (1 - p_i)

    Properties this gives us for free:
      * the score is monotonic  -- more evidence never lowers the score
      * it saturates gracefully -- it approaches 100 but never exceeds it
      * one strong signal outweighs a pile of weak ones, which matches
        how a real analyst triages

    Returns (score, verdict_code, verdict_label).
    """
    survival = 1.0
    for f in findings:
        survival *= 1.0 - f.severity.weight
    score = int(round((1.0 - survival) * 100))

    for threshold, code, label in VERDICT_BANDS:
        if score >= threshold:
            return score, code, label
    return score, "low_risk", "No strong phishing signals found"
