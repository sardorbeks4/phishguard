"""Domain intelligence: the part attackers work hardest to fool you on.

Everything in here answers one of three questions:
  1. What is the *registrable* domain of this host? (eTLD+1)
  2. Is this domain pretending to be a well-known one?
  3. Is this host obviously hostile on its face? (raw IP, punycode, ...)
"""

from __future__ import annotations

import ipaddress
import re

# ---------------------------------------------------------------------------
# Public suffix handling
# ---------------------------------------------------------------------------
# The "real" answer is Mozilla's Public Suffix List (~9000 entries), which
# the `tldextract` package ships. We hand-roll a small version instead so
# the analyzer has zero network dependency and stays deterministic in
# tests. Trade-off documented here on purpose: if PhishGuard ever goes to
# production, swap this set for tldextract and keep the same interface.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "co.za", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.br", "com.mx", "com.ar", "com.cn", "net.cn", "org.cn",
    "co.in", "net.in", "org.in", "co.kr", "com.tr", "com.sg",
    "com.hk", "com.tw", "com.my", "com.ph", "com.vn",
    "edu.pk", "gov.in", "ac.in", "co.il", "com.es", "com.pl",
}

# TLDs that are cheap, bulk-registered and disproportionately abused.
# Not evidence on its own -- worth at most a low-severity nudge.
HIGH_ABUSE_TLDS = {
    "zip", "mov", "top", "xyz", "gq", "cf", "ml", "tk", "ga",
    "click", "link", "work", "rest", "fit", "country", "kim",
    "loan", "download", "racing", "win", "review", "cam", "surf",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "bl.ink", "lnkd.in", "s.id", "t.ly", "shrtco.de",
}

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "proton.me", "mail.com", "gmx.com", "yandex.com",
    "icloud.com", "live.com", "msn.com", "zoho.com", "inbox.lv",
}

# Brands attackers impersonate most, mapped to the domains they legitimately
# send from. Keep this list small and high-precision: a wrong entry here
# creates false accusations, which is the worst failure mode for this
# product. In production this becomes a database table you can update
# without a redeploy.
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypal-communication.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "azure.com"},
    "apple": {"apple.com", "icloud.com", "itunes.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonses.com", "aws.amazon.com"},
    "netflix": {"netflix.com", "mailer.netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "mail.instagram.com"},
    "linkedin": {"linkedin.com", "e.linkedin.com"},
    "chase": {"chase.com", "jpmorgan.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "wells fargo": {"wellsfargo.com"},
    "citibank": {"citi.com", "citibank.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com", "usps.gov"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "adobe": {"adobe.com", "adobesign.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "irs": {"irs.gov"},
    "zoom": {"zoom.us", "zoom.com"},
    "slack": {"slack.com", "slack-mail.com"},
    "github": {"github.com", "githubusercontent.com"},
    "steam": {"steampowered.com", "valvesoftware.com"},
    "walmart": {"walmart.com"},
    "target": {"target.com"},
}

# Flat set of every legitimate brand domain, used for typosquat comparison.
KNOWN_GOOD_DOMAINS: set[str] = {d for domains in BRAND_DOMAINS.values() for d in domains}


def registrable_domain(host: str) -> str:
    """Return the eTLD+1 for a hostname.

    'login.secure.paypal.com.evil.ru' -> 'evil.ru'

    This is *the* function that defeats the single most common phishing
    trick: burying a trusted brand in the subdomain. Browsers only care
    about the registrable domain, and so should we.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def is_ip_literal(host: str) -> bool:
    """True if the host is a bare IP address rather than a name.

    Legitimate companies put a domain name in their links. A raw IP in a
    link that claims to be your bank is close to conclusive."""
    candidate = (host or "").strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def tld_of(host: str) -> str:
    return host.rsplit(".", 1)[-1].lower() if "." in (host or "") else ""


# ---------------------------------------------------------------------------
# Lookalike detection
# ---------------------------------------------------------------------------

# Characters that render nearly identically in most UI fonts. Attackers
# register 'paypa1.com' or 'rnicrosoft.com' and count on you skimming.
_CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a", "!": "i", "|": "l",
}
_CONFUSABLE_PAIRS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]


def skeleton(domain: str) -> str:
    """Collapse a domain to its visual 'skeleton'.

    paypa1.com  -> paypal
    rnicrosoft  -> microsoft
    micros0ft   -> microsoft

    Two different strings with the same skeleton look the same to a human
    at a glance -- which is exactly the attack."""
    name = (domain or "").lower()
    name = name.rsplit(".", 1)[0] if "." in name else name  # drop the TLD
    for pair, repl in _CONFUSABLE_PAIRS:
        name = name.replace(pair, repl)
    name = "".join(_CONFUSABLES.get(ch, ch) for ch in name)
    return re.sub(r"[^a-z0-9]", "", name)


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Classic edit distance, with early exit once we pass `cap`.

    Used to catch 'arnazon.com' / 'micosoft.com' style typosquats that the
    skeleton test misses. The cap keeps it cheap: we only ever care
    whether the distance is small."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        if min(current) > cap:
            return cap + 1
        previous = current
    return previous[-1]


def lookalike_of(domain: str) -> tuple[str, str] | None:
    """Is `domain` impersonating a domain we know to be legitimate?

    Returns (impersonated_domain, technique) or None. Order matters: we
    check the cheap exact-match escape first so real mail never gets
    flagged."""
    domain = registrable_domain(domain)
    if not domain or domain in KNOWN_GOOD_DOMAINS:
        return None

    target_skeleton = skeleton(domain)
    domain_name = domain.rsplit(".", 1)[0]

    for good in KNOWN_GOOD_DOMAINS:
        good_name = good.rsplit(".", 1)[0]

        # 1. Visual confusables: paypa1.com vs paypal.com
        if target_skeleton and target_skeleton == skeleton(good):
            return good, "character_substitution"

        # 2. Typo distance: only meaningful for names long enough that a
        #    1-2 char difference isn't just a different word. 'ups.com' vs
        #    'usps.com' would false-positive without this length guard.
        if len(good_name) >= 6 and levenshtein(domain_name, good_name, cap=2) <= 1:
            return good, "typosquat"

        # 3. Brand embedded with a separator: 'paypal-secure.com',
        #    'secure-paypal-login.net'. The brand is in the name but the
        #    domain isn't theirs.
        if len(good_name) >= 5 and good_name in re.split(r"[-_.]", domain_name):
            return good, "brand_in_hostname"

    return None
