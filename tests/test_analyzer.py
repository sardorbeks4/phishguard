"""Tests for the detection engine.

Two things are being tested here, and the second one matters more:

  1. Does each detector fire on the thing it's supposed to catch?
  2. Does it stay quiet on legitimate mail?

A security tool that cries wolf gets ignored, and an ignored tool is worse
than no tool -- it provides false assurance while training users to click
past warnings. So the false-positive tests are the ones to protect.
"""

from __future__ import annotations

import pytest

from app.analyzer import analyze_email
from app.analyzer.domains import (
    levenshtein,
    lookalike_of,
    registrable_domain,
    skeleton,
)
from app.analyzer.types import Finding, Severity, Category, score_findings


def codes(result: dict) -> set[str]:
    return {f["code"] for f in result["findings"]}


# ---------------------------------------------------------------------------
# Domain utilities -- the foundation everything else stands on
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host,expected", [
    ("paypal.com", "paypal.com"),
    ("www.paypal.com", "paypal.com"),
    ("login.secure.paypal.com.evil.ru", "evil.ru"),      # the whole point
    ("mail.google.co.uk", "google.co.uk"),               # multi-part suffix
    ("home.cunyfirst.cuny.edu", "cuny.edu"),
    ("localhost", "localhost"),
    ("", ""),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize("domain,expected", [
    ("paypa1.com", "paypal"),
    ("rnicrosoft.com", "microsoft"),
    ("micros0ft.net", "microsoft"),
    ("app1e.com", "apple"),
])
def test_skeleton_collapses_confusables(domain, expected):
    assert skeleton(domain) == expected


def test_levenshtein_caps_early():
    assert levenshtein("amazon", "arnazon") == 2
    assert levenshtein("abc", "xyzxyzxyz", cap=3) == 4  # cap+1, bailed out


@pytest.mark.parametrize("domain,impersonates", [
    ("paypa1.com", "paypal.com"),
    ("paypal-secure.com", "paypal.com"),
    ("secure-netflix-billing.net", "netflix.com"),
    # Regression: combines character substitution AND brand-gluing. Each
    # trick alone was caught; together they fell through both checks and
    # the sending domain went unflagged entirely.
    ("paypa1-secure.info", "paypal.com"),
    ("rnicrosoft-login.net", "microsoft.com"),
    # Short brand names, which only became matchable once a lure word was
    # required alongside them. Delivery and tax scams live here.
    ("ups-delivery-notice.com", "ups.com"),
    ("irs-refund-verify.com", "irs.gov"),
    ("zoom-security-alert.net", "zoom.com"),
])
def test_lookalike_detected(domain, impersonates):
    match = lookalike_of(domain)
    assert match is not None, f"{domain} should be flagged"
    assert match[0] == impersonates


@pytest.mark.parametrize("domain", [
    "paypal.com",        # the real thing
    "baruch.cuny.edu",
    "cuny.edu",
    "morningbrew.com",
    "stackoverflow.com",
    "ups.com",           # short name that must not match 'usps.com'
    # Brand names that are also ordinary English words. Without the
    # lure-word requirement these were accused of impersonation.
    "my-target-notes.com",
    "chase-the-sun.org",
    "apple-orchard-farm.com",
    "group-chat-online.com",   # lure word, but no brand
    "id-card-service.org",     # two lure words, still no brand
])
def test_lookalike_not_triggered_on_real_domains(domain):
    assert lookalike_of(domain) is None, f"{domain} was wrongly flagged"


# ---------------------------------------------------------------------------
# Scoring math
# ---------------------------------------------------------------------------

def _finding(sev: Severity) -> Finding:
    return Finding(code="X", category=Category.SENDER, severity=sev,
                   title="t", detail="d", why="w")


def test_score_is_monotonic_and_bounded():
    """More evidence never lowers the score, and it never exceeds 100."""
    previous = -1
    findings: list[Finding] = []
    for _ in range(12):
        findings.append(_finding(Severity.MEDIUM))
        score, _, _ = score_findings(findings)
        assert score >= previous
        assert 0 <= score <= 100
        previous = score


def test_one_critical_outweighs_several_lows():
    """The property that makes triage match how an analyst thinks."""
    critical, _, _ = score_findings([_finding(Severity.CRITICAL)])
    four_lows, _, _ = score_findings([_finding(Severity.LOW)] * 4)
    assert critical > four_lows


def test_info_findings_do_not_move_the_score():
    assert score_findings([_finding(Severity.INFO)] * 5)[0] == 0


def test_empty_findings_is_low_risk():
    score, verdict, _ = score_findings([])
    assert score == 0
    assert verdict == "low_risk"


# ---------------------------------------------------------------------------
# Sender detectors
# ---------------------------------------------------------------------------

def test_display_name_brand_mismatch():
    result = analyze_email(
        sender_address="PayPal Support <billing@account-services.info>",
        subject="Account notice",
        body="Please review your account.",
    )
    assert "SENDER_BRAND_MISMATCH" in codes(result)


def test_reply_to_mismatch():
    result = analyze_email(
        sender_address="Finance <ap@company.com>",
        reply_to="attacker@totally-different.xyz",
        subject="Invoice",
        body="See attached invoice.",
    )
    assert "SENDER_REPLY_TO_MISMATCH" in codes(result)


def test_freemail_pretending_to_be_a_department():
    result = analyze_email(
        sender_address="HR Payroll Department <hr.payroll.dept@gmail.com>",
        subject="Payroll update",
        body="Please update your details.",
    )
    assert "SENDER_FREEMAIL_CORPORATE" in codes(result)


def test_personal_gmail_is_not_flagged():
    """A friend emailing you from Gmail must stay clean."""
    result = analyze_email(
        sender_address="Aziz Karimov <aziz.karimov@gmail.com>",
        subject="notes from class",
        body="hey, here are my notes from discrete math today. see you thursday",
    )
    assert "SENDER_FREEMAIL_CORPORATE" not in codes(result)
    assert result["score"] == 0


# ---------------------------------------------------------------------------
# Link detectors
# ---------------------------------------------------------------------------

def test_link_text_href_mismatch():
    result = analyze_email(
        subject="Verify",
        body='<a href="https://evil-collector.xyz/login">https://www.paypal.com/signin</a>',
    )
    assert "LINK_TEXT_HREF_MISMATCH" in codes(result)


def test_brand_in_subdomain():
    result = analyze_email(
        subject="Notice",
        body='<a href="https://paypal.com.secure-login.tk/verify">Click here</a>',
    )
    assert "LINK_BRAND_IN_SUBDOMAIN" in codes(result)


def test_ip_address_link():
    result = analyze_email(subject="x", body="Visit http://192.0.2.44/account/login now")
    assert "LINK_IP_ADDRESS" in codes(result)


def test_userinfo_trick():
    result = analyze_email(
        subject="x",
        body='<a href="https://www.paypal.com@203.0.113.9/signin">Sign in</a>',
    )
    assert "LINK_USERINFO_TRICK" in codes(result)


def test_punycode_link():
    result = analyze_email(subject="x", body="Go to https://xn--pypal-4ve.com/login")
    assert "LINK_PUNYCODE" in codes(result)


def test_shortener_link():
    result = analyze_email(subject="x", body="Details here: https://bit.ly/3xAbCdE")
    assert "LINK_SHORTENER" in codes(result)


def test_legitimate_links_are_clean():
    """The regression test for the 'cunyfirst contains irs' bug."""
    result = analyze_email(
        sender_address="Registrar <registrar@baruch.cuny.edu>",
        subject="Spring registration opens Monday",
        body='Log in at <a href="https://home.cunyfirst.cuny.edu">'
             'https://home.cunyfirst.cuny.edu</a> to check your appointment time.',
    )
    assert result["findings"] == []
    assert result["score"] == 0


# ---------------------------------------------------------------------------
# Language detectors
# ---------------------------------------------------------------------------

def test_gift_card_request_is_critical():
    result = analyze_email(
        sender_address="Prof Reyes <d.reyes.work@gmail.com>",
        subject="Quick favor",
        body="I'm in a meeting and can't talk. Please purchase four Apple gift cards "
             "and send me the codes. Do not tell anyone yet.",
    )
    assert "LANG_PAYMENT_FRAUD" in codes(result)
    assert result["score"] >= 75


def test_mfa_code_request():
    result = analyze_email(
        subject="Verification required",
        body="You will receive a six-digit verification code by SMS. Please reply "
             "to this email with that code so we can complete the migration.",
    )
    assert "LANG_CREDENTIAL_REQUEST" in codes(result)


def test_pressure_severity_scales_with_lever_count():
    one_lever = analyze_email(subject="Please respond immediately", body="Thanks.")
    three_levers = analyze_email(
        subject="Urgent: account suspended",
        body="We detected unauthorized access. Confirm within 24 hours or your "
             "account will be suspended. Please do not share this email with anyone.",
    )
    def pressure_sev(result):
        return next(f["severity"] for f in result["findings"] if f["code"] == "LANG_PRESSURE_TACTICS")
    assert pressure_sev(one_lever) == "low"
    assert pressure_sev(three_levers) == "high"


def test_ordinary_urgent_email_does_not_score_as_phishing():
    """Real life is sometimes urgent. One lever must not be enough."""
    result = analyze_email(
        sender_address="Study Group <aziz.karimov@gmail.com>",
        subject="Need the slides asap",
        body="Hey, can you send the lecture slides right away? Meeting starts in an hour.",
    )
    assert result["verdict"] == "low_risk"


# ---------------------------------------------------------------------------
# Attachment detectors
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename,expected_code", [
    ("invoice.pdf.exe", "ATTACH_DOUBLE_EXTENSION"),
    ("setup.exe", "ATTACH_EXECUTABLE"),
    ("Statement.xlsm", "ATTACH_MACRO_ENABLED"),
    ("Delivery_Form.html", "ATTACH_HTML_PAGE"),
    ("documents.iso", "ATTACH_ARCHIVE"),
])
def test_attachment_types(filename, expected_code):
    result = analyze_email(subject="x", body="see attached", attachment_names=[filename])
    assert expected_code in codes(result)


def test_ordinary_attachments_are_clean():
    result = analyze_email(
        sender_address="Aziz <aziz.karimov@gmail.com>",
        subject="notes",
        body="here are the notes",
        attachment_names=["lecture_notes.pdf", "problem_set_3.docx", "data.csv"],
    )
    assert result["score"] == 0


def test_rtl_override_filename():
    result = analyze_email(
        subject="x", body="see attached",
        # U+202E built explicitly -- never paste an invisible char into a test.
        attachment_names=["invoice" + chr(0x202E) + "fdp.exe"],
    )
    assert "ATTACH_RTL_OVERRIDE" in codes(result)


# ---------------------------------------------------------------------------
# Header authentication
# ---------------------------------------------------------------------------

RAW_DMARC_FAIL = """Received: from mail.attacker.tk (mail.attacker.tk [198.51.100.7])
	by mx.example.com with ESMTP id abc123
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=attacker.tk; dkim=none; dmarc=fail header.from=paypal.com
From: PayPal <service@paypal.com>
To: student@example.edu
Subject: Your account has been limited
Date: Mon, 7 Sep 2026 09:12:00 +0000
Content-Type: text/plain

Please confirm your password to restore access.
"""

RAW_ALL_PASS = """Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com
From: GitHub <noreply@github.com>
To: student@example.edu
Subject: New sign-in from Chrome
Date: Mon, 7 Sep 2026 09:12:00 +0000
Content-Type: text/plain

Your account was signed in to from a new device.
"""


def test_dmarc_failure_is_critical():
    result = analyze_email(raw=RAW_DMARC_FAIL)
    assert "AUTH_DMARC_FAIL" in codes(result)
    assert result["parsed"]["input_mode"] == "raw_message"
    assert result["score"] >= 75


def test_all_pass_is_informational_only():
    result = analyze_email(raw=RAW_ALL_PASS)
    assert "AUTH_ALL_PASS" in codes(result)
    assert result["score"] == 0, "a passing auth result must not raise the score"


def test_missing_auth_headers_is_info_not_a_penalty():
    raw = "From: Someone <a@b.com>\nTo: c@d.com\nSubject: Hi\nDate: x\n\nHello."
    result = analyze_email(raw=raw)
    assert "AUTH_NO_RESULTS" in codes(result)
    assert result["score"] == 0


# ---------------------------------------------------------------------------
# Robustness -- hostile and malformed input must never crash the engine
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "",
    "a" * 300_000,                      # over the truncation cap
    "<a href=",                          # truncated HTML
    "<a href='http://\x00evil.com'>x</a>",  # embedded null
    "https://" + "a." * 500 + "com",    # pathological hostname
    "😀 emoji only",
    "<script>alert(1)</script>",
])
def test_engine_never_crashes(body):
    result = analyze_email(subject="test", body=body)
    assert 0 <= result["score"] <= 100
    assert result["meta"]["detector_errors"] == []


def test_duplicate_links_are_deduplicated():
    """Phishing repeats the same link a dozen times; the score must not
    inflate because of it."""
    once = analyze_email(subject="x", body='<a href="http://192.0.2.44/login">a</a>')
    ten_times = analyze_email(
        subject="x",
        body='<a href="http://192.0.2.44/login">a</a>' * 10,
    )
    assert once["score"] == ten_times["score"]


def test_full_phishing_email_scores_high():
    result = analyze_email(
        sender_address="PayPal Security <service@paypa1-secure.info>",
        subject="Urgent: Your account will be suspended in 24 hours",
        body='<p>Dear Customer,</p><p>We detected unusual activity. Verify your '
             'password immediately or your account will be suspended within 24 hours.'
             '</p><a href="http://paypal.com.login-verify.tk/secure">'
             'https://www.paypal.com/signin</a>',
        attachment_names=["invoice.pdf.exe"],
    )
    assert result["verdict"] == "high_risk"
    assert result["score"] >= 90
    assert len(result["advice"]) >= 3
    # Every finding must explain itself -- this is the product promise.
    for finding in result["findings"]:
        assert finding["why"].strip(), f"{finding['code']} has no explanation"
        assert finding["detail"].strip()
