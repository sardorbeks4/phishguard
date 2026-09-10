"""Detector: where do the links actually go?

A link has two halves: what you *see* and where it *goes*. In HTML mail
those are completely independent, and the gap between them is where most
credential theft lives.
"""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import unquote, urlparse

from ..domains import (
    BRAND_DOMAINS,
    HIGH_ABUSE_TLDS,
    URL_SHORTENERS,
    is_ip_literal,
    lookalike_of,
    registrable_domain,
    tld_of,
)
from ..types import Category, Finding, ParsedEmail, Severity

# Matches <a ...href="URL"...>VISIBLE TEXT</a>. We use a regex rather than
# a full HTML parser on purpose: we are not rendering this HTML, we only
# need the href/text pairs, and a regex can't be tricked into fetching a
# remote resource the way a real parser's entity resolution can.
ANCHOR_RE = re.compile(
    r"""<a\b[^>]*?href\s*=\s*(["'])(?P<href>.*?)\1[^>]*>(?P<text>.*?)</a>""",
    re.I | re.S,
)
TAG_RE = re.compile(r"<[^>]+>")
BARE_URL_RE = re.compile(r"""(?i)\bhttps?://[^\s<>"'\)\]]+""")
# Domain-shaped text, for detecting when link text *pretends* to be a URL.
DOMAINISH_RE = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")

CREDENTIAL_PATH_RE = re.compile(
    r"(?i)(login|signin|sign-in|verify|verification|secure|account|update|"
    r"confirm|auth|password|reset|billing|unlock|validate|recover)"
)


def _visible_text(html_fragment: str) -> str:
    return unescape(TAG_RE.sub("", html_fragment or "")).strip()


def extract_links(email: ParsedEmail) -> list[tuple[str, str]]:
    """Return (href, visible_text) pairs from both HTML and plain-text bodies."""
    links: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for match in ANCHOR_RE.finditer(email.body_html or ""):
        href = unescape(match.group("href")).strip()
        text = _visible_text(match.group("text"))
        if href.lower().startswith(("http://", "https://")):
            key = (href, text)
            if key not in seen:
                seen.add(key)
                links.append(key)

    # Plain-text URLs (and any URL sitting in HTML outside an anchor).
    html_without_anchors = ANCHOR_RE.sub(" ", email.body_html or "")
    for blob in (email.body_text or "", html_without_anchors):
        for match in BARE_URL_RE.finditer(blob):
            href = unescape(match.group(0)).rstrip(".,;:!?")
            key = (href, href)
            if key not in seen:
                seen.add(key)
                links.append(key)

    return links[:100]  # bound the work; no real email needs more


def analyze(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    links = extract_links(email)
    if not links:
        return findings

    flagged_domains: set[str] = set()

    for href, text in links:
        try:
            parsed = urlparse(href)
        except ValueError:
            continue

        host = (parsed.hostname or "").lower()
        reg = registrable_domain(host)
        decoded_url = unquote(href)

        # --- 1. Link text shows one domain, href goes to another ---------
        text_domains = DOMAINISH_RE.findall(text or "")
        if text_domains and reg:
            shown = registrable_domain(text_domains[0])
            if shown and shown != reg and "." in shown:
                findings.append(Finding(
                    code="LINK_TEXT_HREF_MISMATCH",
                    category=Category.LINKS,
                    severity=Severity.CRITICAL,
                    title="Link says one site, goes to another",
                    detail=(
                        f"The link reads \"{text[:80]}\" (suggesting {shown}) but it "
                        f"actually points to {reg}."
                    ),
                    why=(
                        "In HTML email the clickable text and the destination are separate "
                        "fields. Hover a link (or long-press on mobile) and read the real "
                        "destination in the status bar before you click."
                    ),
                    evidence=href[:200],
                    meta={"shown": shown, "actual": reg},
                ))

        # --- 2. userinfo trick: https://paypal.com@evil.ru/ --------------
        # Checked before the IP test below, which bails out early: the two
        # are routinely combined ("https://www.paypal.com@203.0.113.9/").
        if "@" in (parsed.netloc or ""):
            findings.append(Finding(
                code="LINK_USERINFO_TRICK",
                category=Category.LINKS,
                severity=Severity.CRITICAL,
                title="Everything before the @ in this URL is ignored",
                detail=(
                    f"The URL contains '@' in the host portion. Your browser will go to "
                    f"{host}, not to whatever is printed before the @."
                ),
                why=(
                    "URLs support a user:password@host form left over from FTP. Attackers "
                    "put a trusted domain in the username slot so the URL reads correctly "
                    "while resolving somewhere else entirely."
                ),
                evidence=href[:200],
            ))

        # --- 3. Raw IP address instead of a hostname ---------------------
        if is_ip_literal(host):
            findings.append(Finding(
                code="LINK_IP_ADDRESS",
                category=Category.LINKS,
                severity=Severity.HIGH,
                title="Link points at a bare IP address",
                detail=f"The link goes to {host} instead of a domain name.",
                why=(
                    "Real services own domain names and use them. IP-literal links usually "
                    "mean a compromised box or a throwaway server that never had a "
                    "certificate or a registration to lose."
                ),
                evidence=href[:200],
            ))
            continue

        if not reg:
            continue

        # --- 4. Credential-harvest URL on a lookalike domain -------------
        if reg not in flagged_domains:
            match = lookalike_of(reg)
            if match:
                impersonated, technique = match
                flagged_domains.add(reg)
                findings.append(Finding(
                    code="LINK_LOOKALIKE_DOMAIN",
                    category=Category.LINKS,
                    severity=Severity.CRITICAL,
                    title=f"Link destination imitates {impersonated}",
                    detail=f"The link goes to {reg}, which is built to be mistaken for {impersonated}.",
                    why=(
                        "The landing page will be a pixel-perfect copy of the real login "
                        "screen. The only difference you can see is the domain in the "
                        "address bar -- which is why attackers spend money making it look right."
                    ),
                    evidence=href[:200],
                    meta={"impersonates": impersonated, "technique": technique},
                ))

        # --- 5. Brand hidden in the subdomain or path --------------------
        # 'paypal.com.security-check.ru/login' -- everything before the
        # last two labels is attacker-controlled decoration.
        host_prefix = host[: -len(reg)].rstrip(".") if host.endswith(reg) else host
        # Match whole labels, never substrings. A plain `in` test here
        # matched "irs" inside "home.cunyfirst.cuny.edu" and accused a real
        # university of impersonating the tax authority. Tokenise first.
        prefix_tokens = {t for t in re.split(r"[.\-_]+", host_prefix) if t}
        for brand, legit in BRAND_DOMAINS.items():
            brand_token = brand.replace(" ", "")
            if len(brand_token) < 4:
                continue  # "ups", "irs" are too short to match safely
            in_subdomain = brand_token in prefix_tokens
            if in_subdomain and reg not in legit and reg not in flagged_domains:
                flagged_domains.add(reg)
                findings.append(Finding(
                    code="LINK_BRAND_IN_SUBDOMAIN",
                    category=Category.LINKS,
                    severity=Severity.CRITICAL,
                    title=f"\"{brand.title()}\" appears in the subdomain, not the real domain",
                    detail=(
                        f"The link host is {host}. The part that identifies the owner is "
                        f"{reg} -- everything to the left of it is chosen freely by whoever "
                        f"controls {reg}."
                    ),
                    why=(
                        "Anyone who owns evil.com can create paypal.com.login.evil.com in "
                        "seconds. Read the hostname backwards from the slash: the last two "
                        "labels before the first single slash are the real site."
                    ),
                    evidence=href[:200],
                    meta={"brand": brand, "actual": reg},
                ))
                break

        # --- 6. Punycode / internationalised domain ----------------------
        if "xn--" in host:
            findings.append(Finding(
                code="LINK_PUNYCODE",
                category=Category.LINKS,
                severity=Severity.HIGH,
                title="Link uses an internationalised (punycode) domain",
                detail=f"The host {host} is punycode-encoded, so it displays as non-Latin characters.",
                why=(
                    "Cyrillic 'а' and Latin 'a' are different characters that render "
                    "identically. Punycode domains are legitimate for non-English sites but "
                    "are a known homograph-attack vector on English-language brand names."
                ),
                evidence=href[:200],
            ))

        # --- 7. URL shortener hiding the destination ---------------------
        if reg in URL_SHORTENERS:
            findings.append(Finding(
                code="LINK_SHORTENER",
                category=Category.LINKS,
                severity=Severity.MEDIUM,
                title="Destination hidden behind a URL shortener",
                detail=f"The link uses {reg}, which conceals where it actually leads.",
                why=(
                    "Shorteners are normal on social media and abnormal in transactional "
                    "email -- your bank has no reason to hide its own domain. Expand the "
                    "link with a preview service before clicking."
                ),
                evidence=href[:200],
            ))

        # --- 8. Unencrypted link asking for credentials ------------------
        if parsed.scheme == "http" and CREDENTIAL_PATH_RE.search(decoded_url):
            findings.append(Finding(
                code="LINK_INSECURE_CREDENTIAL_PAGE",
                category=Category.LINKS,
                severity=Severity.MEDIUM,
                title="Login-style link over plain HTTP",
                detail=f"{href[:120]} uses http:// and its path looks like a sign-in page.",
                why=(
                    "Any real login page has used HTTPS for a decade. Plain HTTP means the "
                    "credentials would also travel in cleartext -- sloppy even by attacker "
                    "standards, and conclusive that this isn't a major brand."
                ),
                evidence=href[:200],
            ))

        # --- 9. Cheap, heavily abused TLD --------------------------------
        tld = tld_of(reg)
        if tld in HIGH_ABUSE_TLDS and reg not in flagged_domains:
            findings.append(Finding(
                code="LINK_HIGH_ABUSE_TLD",
                category=Category.LINKS,
                severity=Severity.LOW,
                title=f"Link uses a .{tld} domain",
                detail=f"{reg} sits on .{tld}, a top-level domain with high abuse rates.",
                why=(
                    "Some TLDs are free or near-free and have little registration checking, "
                    "so they attract bulk disposable domains. Weak evidence on its own -- "
                    "legitimate sites use these too -- but it adds up with other signals."
                ),
                evidence=reg,
            ))

    return findings
