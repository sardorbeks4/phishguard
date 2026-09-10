"""Detector: is the attachment a payload?

We only ever look at the *filename*. PhishGuard never opens, extracts or
executes an attachment -- that would move the malware into our own
infrastructure. Filename analysis is cheap, safe, and catches most of
what consumer-grade phishing sends.
"""

from __future__ import annotations

import re

from ..types import Category, Finding, ParsedEmail, Severity

# Executable or script content: opening one runs code.
EXECUTABLE_EXTS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "cpl", "jar",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "hta", "reg",
    "lnk", "inf", "app", "dmg", "deb", "apk", "sh", "run",
}

# Macro-enabled Office formats: the 'm' suffix literally means macros.
MACRO_EXTS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "xla"}

# Containers that hide the real extension from mail scanners.
ARCHIVE_EXTS = {"zip", "rar", "7z", "iso", "img", "vhd", "cab", "ace", "gz", "tgz"}

# An HTML attachment is a login page delivered as a file: it opens in your
# browser from a local path, so there's no suspicious domain to notice.
HTML_EXTS = {"html", "htm", "shtml", "mht", "mhtml", "svg"}

# Right-to-left override and friends. A filename containing U+202E renders
# reversed from the point it appears, so a name stored as
# "invoice" + U+202E + "fdp.exe" is DISPLAYED to the user as "invoiceexe.pdf".
# Pure deception -- there is no legitimate reason for these in a filename.
#
# Built from integer codepoints rather than written as literal characters:
# these are invisible, so pasting them into source gives you a file that
# reads one way in a diff and behaves another. Never put an invisible
# character in code when you can name it instead.
BIDI_CODEPOINTS = (
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # LRE, RLE, PDF, LRO, RLO
    0x2066, 0x2067, 0x2068, 0x2069,          # LRI, RLI, FSI, PDI
    0x200E, 0x200F,                          # LRM, RLM
)
BIDI_CHARS = re.compile("[" + "".join(chr(cp) for cp in BIDI_CODEPOINTS) + "]")


def _ext(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def analyze(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    for name in email.attachments:
        name = (name or "").strip()
        if not name:
            continue
        ext = _ext(name)

        if BIDI_CHARS.search(name):
            findings.append(Finding(
                code="ATTACH_RTL_OVERRIDE",
                category=Category.ATTACHMENTS,
                severity=Severity.CRITICAL,
                title="Filename contains hidden text-direction characters",
                detail=f"'{BIDI_CHARS.sub('<hidden>', name)}' embeds Unicode direction-override characters.",
                why=(
                    "These invisible characters reverse how the rest of the name is drawn, "
                    "so an .exe can display as a .pdf. There is no legitimate reason for "
                    "them in a filename."
                ),
                evidence=name,
            ))
            continue

        # Double extension is checked *before* the plain executable test:
        # "invoice.pdf.exe" is both, but the double-extension explanation is
        # the one that teaches the reader something they can reuse.
        parts = name.lower().split(".")
        if len(parts) >= 3 and parts[-2] in {
            "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "csv", "ppt", "pptx"
        }:
            findings.append(Finding(
                code="ATTACH_DOUBLE_EXTENSION",
                category=Category.ATTACHMENTS,
                severity=Severity.CRITICAL,
                title="Double file extension",
                detail=f"'{name}' looks like a .{parts[-2]} but its real type is .{parts[-1]}.",
                why=(
                    "Windows hides known extensions by default, so this shows up in your "
                    "downloads folder as a harmless document. The last extension is the "
                    "one that decides what happens when you double-click."
                ),
                evidence=name,
            ))
            continue

        if ext in EXECUTABLE_EXTS:
            findings.append(Finding(
                code="ATTACH_EXECUTABLE",
                category=Category.ATTACHMENTS,
                severity=Severity.CRITICAL,
                title=f"Executable attachment (.{ext})",
                detail=f"'{name}' is a program or script, not a document.",
                why=(
                    "Opening it runs code with your privileges. Invoices, receipts and "
                    "shipping notices are never delivered as executables."
                ),
                evidence=name,
            ))
            continue

        if ext in MACRO_EXTS:
            findings.append(Finding(
                code="ATTACH_MACRO_ENABLED",
                category=Category.ATTACHMENTS,
                severity=Severity.HIGH,
                title=f"Macro-enabled Office file (.{ext})",
                detail=f"'{name}' can contain executable macros.",
                why=(
                    "The 'm' in .docm/.xlsm means macros are enabled. The whole attack is "
                    "the yellow 'Enable Content' banner -- clicking it runs the attacker's "
                    "code. Ordinary documents don't need it."
                ),
                evidence=name,
            ))
            continue

        if ext in HTML_EXTS:
            findings.append(Finding(
                code="ATTACH_HTML_PAGE",
                category=Category.ATTACHMENTS,
                severity=Severity.HIGH,
                title=f"Web page delivered as an attachment (.{ext})",
                detail=f"'{name}' opens in your browser from your own disk.",
                why=(
                    "This is a login page shipped as a file. Because it opens from a local "
                    "path there is no suspicious domain in the address bar to notice, and "
                    "mail scanners that check links never saw a link."
                ),
                evidence=name,
            ))
            continue

        if ext in ARCHIVE_EXTS:
            findings.append(Finding(
                code="ATTACH_ARCHIVE",
                category=Category.ATTACHMENTS,
                severity=Severity.MEDIUM,
                title=f"Archive attachment (.{ext})",
                detail=f"'{name}' is a container whose contents can't be inspected from the filename.",
                why=(
                    "Archives — especially password-protected ones, and disk images like "
                    ".iso — exist here to get the real payload past the scanner. Legitimate "
                    "senders rarely need to zip a single document."
                ),
                evidence=name,
            ))

    return findings
