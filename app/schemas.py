"""Request/response contracts.

Pydantic models are not paperwork -- they are the security boundary. Every
byte from the internet is validated here before it reaches any of our
logic. Length caps, type checks and field whitelisting all happen at this
layer, so the analyzer can assume its input is sane.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

MAX_TEXT = 200_000
MAX_FIELD = 2_000


class AnalyzeRequest(BaseModel):
    """Either paste the whole message in `raw`, or fill the fields."""

    raw: str | None = Field(
        default=None,
        max_length=MAX_TEXT,
        description="Full pasted email (headers + body), or just the body.",
    )
    sender: str = Field(default="", max_length=MAX_FIELD)
    subject: str = Field(default="", max_length=MAX_FIELD)
    body: str = Field(default="", max_length=MAX_TEXT)
    reply_to: str = Field(default="", max_length=MAX_FIELD)
    attachments: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("attachments")
    @classmethod
    def cap_filename_length(cls, value: list[str]) -> list[str]:
        return [name[:255] for name in value if name and name.strip()]

    @model_validator(mode="after")
    def require_something_to_analyze(self) -> "AnalyzeRequest":
        if not any([
            (self.raw or "").strip(),
            self.body.strip(),
            self.sender.strip(),
            self.subject.strip(),
        ]):
            raise ValueError(
                "Provide at least one of: raw, body, sender or subject."
            )
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "sender": "PayPal Service <security@paypa1-alerts.info>",
                "subject": "Urgent: verify your account within 24 hours",
                "body": "Dear Customer, click here to restore access.",
                "attachments": ["statement.pdf.exe"],
            }
        }
    }


class FindingOut(BaseModel):
    code: str
    category: Literal["sender", "links", "language", "attachments", "authentication"]
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    detail: str
    why: str
    evidence: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ParsedOut(BaseModel):
    from_display: str
    from_address: str
    reply_to: str
    subject: str
    attachments: list[str]
    link_count: int
    input_mode: str


class AnalyzeResponse(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Literal["low_risk", "suspicious", "likely_phishing", "high_risk"]
    verdict_label: str
    summary: str
    findings: list[FindingOut]
    by_category: dict[str, list[FindingOut]]
    advice: list[str]
    parsed: ParsedOut
    meta: dict[str, Any]


class SampleOut(BaseModel):
    """A training sample. Every one of these is FICTIONAL and clearly
    labelled -- see app/samples.py for why that matters."""

    id: str
    name: str
    difficulty: Literal["easy", "medium", "hard"]
    is_phishing: bool
    teaching_point: str
    sender: str
    subject: str
    body: str
    attachments: list[str] = Field(default_factory=list)
