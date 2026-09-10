# PhishGuard

Paste a suspicious email, get an explained risk assessment. Every finding
says what was detected **and why it matters**, so the tool teaches you to
read email yourself instead of making you dependent on it.

```
FastAPI + Pydantic  ·  React + TypeScript + Vite  ·  zero data storage
```

---

**Live deploy:** see [DEPLOY.md](DEPLOY.md).

## Run it

Two terminals.

**Backend** (port 8000):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

**Frontend** (port 5173):

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Interactive API docs are at
http://localhost:8000/docs — FastAPI generates them from the Pydantic
models, for free.

**Tests:**

```bash
python3 -m pytest -q                   # 69 tests
cd frontend && npm run typecheck
```

---

## How it fits together

```
Browser (React)
    │  POST /api/analyze  { sender, subject, body, attachments }
    ▼
FastAPI  ── schemas.py ──►  validates and size-caps every field
    │
    ▼
analyzer/engine.py  ── runs 5 independent detectors ──┐
    │                                                  │
    │   sender.py    who is this really from?          │
    │   links.py     where do the links actually go?   │
    │   language.py  what psychology is being used?    │
    │   attachments.py  is the file a payload?         │
    │   auth.py      did SPF/DKIM/DMARC pass?          │
    │                                                  │
    ▼◄─────────────── list[Finding] ───────────────────┘
score_findings()  ──►  0-100 risk score + verdict + advice
    │
    ▼
JSON back to the browser
```

### The one idea worth stealing

**Detectors return evidence, not numbers.** Each one produces `Finding`
objects carrying a `title`, a `detail` (what was observed), and a `why`
(the teaching note). The score is *derived* from the findings at the very
end. Flip that ordering — compute a score and then try to explain it —
and you get a black box that nobody trusts and nobody learns from.

### How the score combines

Not a sum. Each finding is treated as an independent probability that the
mail is malicious, combined with the complement rule:

```
P(phish) = 1 - Π (1 - pᵢ)
```

This gives three properties for free: the score is monotonic (more
evidence never lowers it), it saturates toward 100 without ever exceeding
it, and one critical signal outranks a pile of weak ones — which is how a
real analyst triages. See `types.py::score_findings`.

---

## What it detects

| Category | Examples |
|---|---|
| **Sender** | display name says "PayPal" but the domain isn't theirs; lookalike domains (`paypa1.com`, `rnicrosoft.com`); Reply-To pointing elsewhere; "Payroll Department" writing from Gmail |
| **Links** | link text says one site and the href goes to another; brand buried in a subdomain (`paypal.com.evil.tk`); the `user@host` URL trick; raw IP addresses; punycode homographs; shorteners |
| **Language** | gift-card / wire / crypto payment requests; requests for passwords or MFA codes; stacked pressure levers (urgency + fear + secrecy) |
| **Attachments** | double extensions (`invoice.pdf.exe`); macro-enabled Office files; `.html` credential pages; right-to-left override filenames |
| **Authentication** | SPF / DKIM / DMARC results parsed out of real headers, with DMARC alignment explained |

---

## Security decisions (and why)

These are the parts worth being able to defend in an interview.

**Nothing is stored.** No database, no logging of message content. An
email someone is worried about often contains their own name, address and
account numbers. The safest way to protect that data is to never hold it —
a breach of this service leaks nothing. That's a product decision, not
laziness.

**Nothing is fetched.** The analyzer never follows a URL in the email. If
it did, this service would become a free scanner-evasion oracle for
attackers (checking which of their domains are flagged) and would tip
them off that a target is inspecting the mail.

**Nothing is rendered.** The frontend never uses
`dangerouslySetInnerHTML`. Email bodies are hostile input shown as text.
React escapes it automatically; the one place XSS could enter is the one
place we refuse to open.

**Input is capped at the edge.** Pydantic enforces field lengths before
anything reaches the engine, and middleware rejects oversized bodies
before reading them into memory. Regexes only ever run on bounded input.

**CORS is an allowlist, never `*`.** With `*`, any site your browser
visits could call this API.

**Rate limited per IP** (30 req/min, sliding window). The in-memory
implementation is honest about its limits: it doesn't survive a restart
and doesn't work across processes. The moment this runs on more than one
instance, it moves to Redis. Documented rather than hidden.

**Defensive scope.** PhishGuard analyzes and teaches. It does not
generate phishing emails, send anything, accept target lists, or host
login pages. The training corpus is a fixed, hand-written, clearly-labelled
set of fictional samples (`app/samples.py`). That line is what separates
an awareness tool from an attack platform.

---

## Known limitations

Being able to name these is more valuable than pretending they don't exist.

- **The public suffix list is hand-rolled** (`domains.py`). It covers
  common cases only. Production should use `tldextract`.
- **The brand list is small and hardcoded.** It should be a database
  table you can update without a redeploy.
- **SPF/DKIM/DMARC are read, not verified.** By the time you have the
  message, the original SMTP connection is gone and SPF is no longer
  checkable. We parse what the receiving server already recorded.
- **Rule-based detection is evadable** by anyone who reads the rules.
  That's fine for the teaching goal and a real ceiling on the product
  goal; see the roadmap.
- **No auth, no persistence, no accounts.** Deliberate for v1.

---

## Roadmap — what turns this into a product

Ordered by value per unit of work, not by what's fun.

1. **Bulk / forwarding intake.** A `report@` address users forward mail
   to, which replies with the analysis. This is the single biggest
   usability jump: nobody wants to copy-paste.
2. **Browser extension.** Analyze in-place in Gmail. Same API, different
   client.
3. **Accounts + history** (Postgres, SQLAlchemy, Alembic migrations).
   Needed before any of the below. Also where you learn auth properly —
   password hashing with Argon2, sessions vs JWT, CSRF.
4. **A trained classifier alongside the rules.** Not replacing them: the
   rules are what produce explanations, the model catches what the rules
   miss. Ensemble the two and keep the rules for the UI.
5. **Org dashboards.** "43% of your users would have clicked this." This
   is where the money is — universities and small businesses buy this,
   individuals don't.
6. ~~**Deployment**~~ — done. One Vercel project, push-to-deploy, CI gate
   on every push. See [DEPLOY.md](DEPLOY.md).

---

## Layout

```
api/index.py           Vercel entrypoint (5-line ASGI shim)
vercel.json            Build config, /api rewrite, security headers
.github/workflows/     CI: pytest + typecheck on every push
app/
    main.py            FastAPI app, middleware, routes
    schemas.py         Pydantic contracts = the security boundary
    samples.py         Fictional training corpus + scope rules
    analyzer/
      engine.py        Orchestration; add a detector in one line
      types.py         Finding, Severity, the scoring math
      parser.py        RFC-822 and loose-field parsing
      domains.py       eTLD+1, lookalikes, confusables, edit distance
      signals/         The five detectors
tests/                 69 tests, incl. false-positive regressions
frontend/
  src/
    App.tsx            The page
    api.ts             Every network call, with timeout handling
    types.ts           The API contract in TypeScript
    components/        ScoreGauge, FindingCard
    styles.css         Plain CSS, custom properties for the palette
```
