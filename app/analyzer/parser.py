"""Turn whatever the user pasted into a ParsedEmail.

Two input shapes, one output shape:

  * Raw RFC-822 -- what "Show original" (Gmail) or "View source" (Outlook)
    gives you. Full headers, MIME parts, the works. We use Python's
    stdlib `email` package, which is battle-tested; writing our own MIME
    parser would be a security bug factory.

  * Loose fields -- someone screenshots-and-retypes the sender, subject
    and body. Fewer signals available, but the language and link
    detectors still work.

SECURITY: we never render the HTML, never fetch a URL, never execute
anything. The parser only reads. Everything downstream treats the email
as hostile data.
"""

from __future__ import annotations

import re
from email import message_from_string, policy
from email.utils import parseaddr

from .types import ParsedEmail

# A body over this size is almost certainly a mail loop or an attack on
# our own regex engine. Truncate rather than reject so the user still
# gets an answer.
MAX_BODY_CHARS = 200_000


def _decode_part(part) -> str:
    try:
        payload = part.get_content()
        return payload if isinstance(payload, str) else ""
    except Exception:
        # Broken encodings are common in real phishing -- degrade, don't crash.
        try:
            raw = part.get_payload(decode=True) or b""
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""


def parse_raw_email(raw: str) -> ParsedEmail:
    """Parse a full RFC-822 message."""
    msg = message_from_string(raw[:MAX_BODY_CHARS], policy=policy.default)

    display, address = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            filename = part.get_filename()
            disposition = (part.get_content_disposition() or "").lower()
            if filename or disposition == "attachment":
                attachments.append(filename or "unnamed-attachment")
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain":
                text_parts.append(_decode_part(part))
            elif ctype == "text/html":
                html_parts.append(_decode_part(part))
    else:
        content = _decode_part(msg)
        if msg.get_content_type() == "text/html":
            html_parts.append(content)
        else:
            text_parts.append(content)

    headers = {k.lower(): v for k, v in msg.items()}

    return ParsedEmail(
        from_display=display or "",
        from_address=(address or "").lower(),
        reply_to=(reply_to or "").lower(),
        return_path=(return_path or "").lower(),
        to=msg.get("To", "") or "",
        subject=msg.get("Subject", "") or "",
        body_text="\n".join(text_parts)[:MAX_BODY_CHARS],
        body_html="\n".join(html_parts)[:MAX_BODY_CHARS],
        attachments=attachments,
        headers=headers,
        raw=raw[:MAX_BODY_CHARS],
    )


def parse_fields(
    sender: str = "",
    subject: str = "",
    body: str = "",
    reply_to: str = "",
    attachments: list[str] | None = None,
) -> ParsedEmail:
    """Parse the loose-field input shape.

    `sender` may be 'Name <addr@example.com>' or a bare address; parseaddr
    handles both."""
    display, address = parseaddr(sender or "")
    if not address and "@" in (sender or ""):
        address = sender.strip()

    body = (body or "")[:MAX_BODY_CHARS]
    looks_like_html = bool(re.search(r"<\s*(a|div|table|html|body|p)\b", body, re.I))

    return ParsedEmail(
        from_display=display or "",
        from_address=(address or "").lower(),
        reply_to=(parseaddr(reply_to or "")[1] or "").lower(),
        subject=subject or "",
        body_text="" if looks_like_html else body,
        body_html=body if looks_like_html else "",
        attachments=attachments or [],
        raw=body,
    )


def looks_like_raw_email(text: str) -> bool:
    """Heuristic: did the user paste full headers?

    We look for two or more header-shaped lines near the top of the input.
    Cheap, and wrong only in ways that degrade gracefully."""
    head = "\n".join((text or "").splitlines()[:40])
    hits = len(re.findall(
        r"(?im)^(received|from|to|subject|date|message-id|return-path|"
        r"authentication-results|dkim-signature|mime-version|content-type):\s",
        head,
    ))
    return hits >= 3
