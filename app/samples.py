"""The training corpus.

SCOPE DECISION -- read this before adding to the file.

PhishGuard is a *defensive* tool. It analyzes mail you already received
and it teaches you to read mail yourself. It deliberately does not:

  * generate phishing emails on demand,
  * send anything to anyone,
  * take a target list, or
  * host a fake login page.

Those features are what turn an awareness tool into an attack platform,
and the line is worth holding even though it costs a feature or two.

So the training mode uses this fixed, hand-written corpus. Every entry is
fictional, uses non-routable example domains where possible, is labelled
with the answer, and exists to make one specific teaching point. A mix of
real and fake is essential: a trainer that only shows phishing teaches
paranoia, not judgement, and users who flag everything are as useless to
a security team as users who flag nothing.
"""

from __future__ import annotations

from typing import Any

SAMPLES: list[dict[str, Any]] = [
    {
        "id": "campus-portal-reset",
        "name": "Student portal password reset",
        "difficulty": "easy",
        "is_phishing": True,
        "teaching_point": (
            "The sender's domain is a lookalike of the school's. Read the domain "
            "right-to-left: the last two labels before the first slash are the only "
            "part that identifies the owner."
        ),
        "sender": "IT Help Desk <helpdesk@student-portal-verify.info>",
        "subject": "Action required: your student account expires in 24 hours",
        "body": (
            "<p>Dear Student,</p>"
            "<p>Our records show your student account password expires within 24 hours. "
            "Failure to confirm your password will result in your account being "
            "suspended and loss of access to course materials.</p>"
            "<p><a href=\"http://university.edu.account-verify.tk/login\">"
            "https://portal.university.edu/reset</a></p>"
            "<p>IT Help Desk</p>"
        ),
        "attachments": [],
    },
    {
        "id": "scholarship-award",
        "name": "Surprise scholarship award",
        "difficulty": "easy",
        "is_phishing": True,
        "teaching_point": (
            "Unexpected money is the reward lever. Notice it also asks for a bank "
            "account 'to deposit the funds' — the actual goal."
        ),
        "sender": "Scholarship Committee <awards@grantfoundation-intl.top>",
        "subject": "Congratulations! You have won a $5,000 scholarship",
        "body": (
            "<p>Dear Student,</p>"
            "<p>Congratulations! You have been selected as a winner of our merit "
            "scholarship prize. To release your award we need you to confirm your "
            "bank account details and provide your social security number for tax "
            "purposes.</p>"
            "<p>Please respond immediately as this offer expires in 48 hours.</p>"
        ),
        "attachments": [],
    },
    {
        "id": "campus-job-giftcard",
        "name": "Fake campus job offer",
        "difficulty": "medium",
        "is_phishing": True,
        "teaching_point": (
            "The 'personal assistant' scam that targets student job boards. The "
            "gift-card request is conclusive: no employer settles anything in gift "
            "cards, ever."
        ),
        "sender": "Prof. Daniel Reyes <d.reyes.assistant@gmail.com>",
        "subject": "Part-time personal assistant position - $450/week",
        "body": (
            "<p>Hello,</p>"
            "<p>I got your contact from the university directory. I need a reliable "
            "student assistant for simple errands. The pay is $450 per week for a few "
            "hours of work.</p>"
            "<p>Your first task: I am currently in a meeting and cannot talk, so please "
            "purchase four Apple gift cards of $100 each for a client, scratch off the "
            "back and send me the codes. You will be reimbursed with your first "
            "paycheck. Please do not discuss this with anyone in the department yet.</p>"
        ),
        "attachments": [],
    },
    {
        "id": "shipping-notice",
        "name": "Package delivery failure",
        "difficulty": "medium",
        "is_phishing": True,
        "teaching_point": (
            "Everyone is waiting on a package, so this works year-round. The tell is "
            "the .html attachment: it's a login page delivered as a file, so there's "
            "no suspicious domain in the address bar to notice."
        ),
        "sender": "DHL Express <tracking@dhl-parcel-notice.xyz>",
        "subject": "Delivery attempt failed - schedule redelivery",
        "body": (
            "<p>Your parcel could not be delivered because the address was incomplete. "
            "Open the attached form to reschedule delivery within 3 days or the parcel "
            "will be returned to sender.</p>"
        ),
        "attachments": ["Delivery_Form_84213.html"],
    },
    {
        "id": "mfa-code-request",
        "name": "MFA code interception",
        "difficulty": "hard",
        "is_phishing": True,
        "teaching_point": (
            "The hardest kind to catch: no links, no attachments, no lookalike domain "
            "if the account is genuinely compromised. The entire attack is the request "
            "for the one-time code. Nobody legitimate ever asks for it."
        ),
        "sender": "IT Security <security@it-servicedesk.help>",
        "subject": "Verification required for your account",
        "body": (
            "<p>Hello,</p>"
            "<p>We are migrating accounts to a new authentication system. You will "
            "shortly receive a six-digit verification code by SMS. Please reply to "
            "this email with that code so we can complete the migration on your "
            "behalf.</p>"
            "<p>If you do not respond today your access will be interrupted.</p>"
        ),
        "attachments": [],
    },
    {
        "id": "invoice-macro",
        "name": "Unpaid invoice with macro document",
        "difficulty": "medium",
        "is_phishing": True,
        "teaching_point": (
            "The 'm' in .xlsm means macro-enabled. The entire attack is convincing you "
            "to click the yellow 'Enable Content' banner."
        ),
        "sender": "Accounts Receivable <billing@invoice-settlement.work>",
        "subject": "OVERDUE: Invoice #INV-99231 - final notice before legal action",
        "body": (
            "<p>Dear Customer,</p>"
            "<p>Our records indicate invoice INV-99231 remains unpaid. This is a final "
            "notice. If payment is not received immediately we will begin legal "
            "proceedings.</p>"
            "<p>See the attached statement for details.</p>"
        ),
        "attachments": ["Statement_INV99231.xlsm"],
    },
    {
        "id": "legit-course-notice",
        "name": "Real course registration notice",
        "difficulty": "easy",
        "is_phishing": False,
        "teaching_point": (
            "Legitimate: the domain matches the institution, the link stays on that "
            "domain, and it asks you to log in yourself rather than handing you a "
            "form. Note it's still mildly time-bound — urgency alone proves nothing."
        ),
        "sender": "Registrar <registrar@baruch.cuny.edu>",
        "subject": "Spring registration opens Monday",
        "body": (
            "<p>Hi Sardor,</p>"
            "<p>Registration for the spring term opens Monday at 7:00 a.m. Your "
            "enrollment appointment time is visible in CUNYfirst. Please clear any "
            "holds on your account before then.</p>"
            "<p>Log in at <a href=\"https://home.cunyfirst.cuny.edu\">"
            "https://home.cunyfirst.cuny.edu</a> to check.</p>"
            "<p>Office of the Registrar</p>"
        ),
        "attachments": [],
    },
    {
        "id": "legit-security-alert",
        "name": "Real new-device sign-in alert",
        "difficulty": "hard",
        "is_phishing": False,
        "teaching_point": (
            "This one is designed to feel like phishing and isn't. It mentions "
            "suspicious activity and it's urgent — but it asks for nothing, links only "
            "to the provider's own domain, and tells you to act through the app rather "
            "than through the email. Real alerts inform; phishing extracts."
        ),
        "sender": "GitHub <noreply@github.com>",
        "subject": "New sign-in to your account from Chrome on Windows",
        "body": (
            "<p>Hey sardor,</p>"
            "<p>Your account was signed in to from a new device. If this was you, no "
            "action is needed.</p>"
            "<p>If this wasn't you, review your security log at "
            "<a href=\"https://github.com/settings/security-log\">"
            "https://github.com/settings/security-log</a> and reset your password from "
            "your account settings.</p>"
        ),
        "attachments": [],
    },
]


def list_samples() -> list[dict[str, Any]]:
    return SAMPLES


def get_sample(sample_id: str) -> dict[str, Any] | None:
    return next((s for s in SAMPLES if s["id"] == sample_id), None)
