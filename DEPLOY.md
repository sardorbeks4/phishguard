# Deploying PhishGuard

Target: **one Vercel project serving both halves on one domain.** The React
app is served as static files; `/api/*` is rewritten to a Python serverless
function running the same FastAPI app you run locally. Because they share
an origin, there is no CORS in production at all.

Free tier, no credit card.

---

## The five files that make this work

Everything platform-specific lives in these. The application code has no
idea it's on Vercel — which is the point, and why moving to Fly or Render
later is a config change, not a rewrite.

| File | Job |
|---|---|
| `api/index.py` | The entrypoint. Vercel looks for a module-level `app` that speaks ASGI; FastAPI *is* ASGI, so this is a 5-line shim that fixes `sys.path` and imports the real app. |
| `vercel.json` | Build commands, the `/api/*` rewrite, function limits, security headers. |
| `requirements.txt` | Production Python deps **only**. No uvicorn — Vercel supplies the ASGI host, and every extra package is cold-start time. |
| `.vercelignore` | Keeps tests, CI config and the README out of the function bundle. Smaller bundle, faster cold start. |
| `.github/workflows/ci.yml` | Runs the 69 tests + typecheck on every push and PR. |

---

## Step 1 — Get it on GitHub

From the project root:

```bash
git init
git add .
git commit -m "PhishGuard: defensive email analyzer"
```

Create an empty repo on github.com (no README, no .gitignore — you have
both), then:

```bash
git remote add origin https://github.com/<your-username>/phishguard.git
git branch -M main
git push -u origin main
```

The moment this lands, GitHub Actions runs `ci.yml`. Check the Actions tab —
you should see two green jobs. **Fix any red before continuing.** Deploying
a build you know is broken teaches you nothing except how to read Vercel's
error page.

## Step 2 — Connect Vercel

1. Go to vercel.com and sign in **with GitHub**.
2. **Add New → Project**, pick the `phishguard` repo.
3. Vercel reads `vercel.json`, so leave every build setting alone. Framework
   preset should say *Other*. If it guessed *Vite*, change it to Other —
   otherwise it tries to build from the repo root and won't find the app.
4. Click **Deploy**.

First build takes about a minute: it installs the Python deps, bundles the
function, then runs `npm install && npm run build` in `frontend/`.

> Heads up: a project named `phishguard` already exists in your Vercel
> account — I created it while testing this setup, and its builds failed
> because I couldn't upload the whole source tree from my sandbox in one
> shot. Either delete it first (Project → Settings → Advanced → Delete) or
> let the GitHub import create `phishguard-1`. Nothing is broken either way.

## Step 3 — Verify the deploy

Don't trust a green checkmark. Check the two things that actually break:

```bash
# 1. Is the API alive? (this proves the Python function bundled correctly)
curl https://<your-app>.vercel.app/api/health

# 2. Does the engine actually run in the serverless environment?
curl -s -X POST https://<your-app>.vercel.app/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"sender":"PayPal <a@paypa1-secure.info>","subject":"Urgent: verify in 24 hours","body":"<a href=\"http://paypal.com.verify.tk/login\">https://paypal.com</a>"}'
```

Expect `{"status":"ok",...}` and a score of 100. Then open the site in a
browser and run a training sample end to end.

**If `/api/health` 404s**, the rewrite isn't matching — check `vercel.json`
made it into the commit. **If it 500s**, the function bundled but crashed on
import; the Vercel dashboard's *Functions → Logs* tab shows the Python
traceback, and it's almost always a missing dependency in
`requirements.txt`.

---

## From here on: push to deploy

That's the whole loop.

```
push to main         → CI runs → production deploy
open a pull request  → CI runs → preview deploy on its own URL
```

Every PR gets a real, shareable URL with that branch's code on it. This is
the single best habit to build now: never test a change by deploying it to
production and hoping.

---

## What's different in production (and what to watch)

**The rate limiter is much weaker here.** It keeps counters in process
memory, and serverless gives each cold start a fresh process. It still
blunts a burst that hits one warm instance, but it is not a real control.
The comment in `app/main.py` says so, and the fix — when you need one — is
Upstash Redis, which has a free tier and a one-click Vercel integration.

**Cold starts are real.** The first request after a quiet period takes a
second or two while Python boots. That's why `requirements.txt` is kept
minimal.

**`maxDuration` is 10 seconds** (set in `vercel.json`). Analysis takes
milliseconds, so this is a safety net against a pathological input, not a
constraint.

**No environment variables are needed** for the current feature set. When
you add some — an API key, a database URL — they go in Vercel's
*Settings → Environment Variables*, never in the repo. `.gitignore` already
excludes `.env`. The day you paste a secret into a commit is the day you
rotate that secret; git history is forever.

---

## Custom domain (optional, ~$10/yr)

Buy a domain anywhere, then Vercel *Settings → Domains → Add*. Vercel
handles the TLS certificate automatically. `phishguard.app` is the kind of
thing worth owning if you put this on a resume — but the free
`.vercel.app` URL works perfectly and costs nothing.
