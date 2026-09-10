"""FastAPI application.

Security posture for this service, stated up front because it drives
every decision below:

  * We accept hostile input by definition. Every request body is an
    email someone believes is malicious.
  * We never render it, never fetch anything it references, never
    execute it. The analyzer is pure string processing.
  * We store nothing. No database, no logs of message content. An email
    someone is worried about often contains their own name, address and
    account numbers — the safest way to protect that data is to never
    hold it. This is a real product decision, not laziness: it means a
    breach of this service leaks nothing.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .analyzer import analyze_email
from .samples import get_sample, list_samples
from .schemas import AnalyzeRequest, AnalyzeResponse, SampleOut

# ---------------------------------------------------------------------------
# Configuration -- environment first, safe defaults second.
# Never hardcode origins or secrets. This pattern is what lets the same
# code run locally and in production without a change.
#
# On the deployed site the frontend and API share one origin, so the
# browser never sends a cross-origin request and this allowlist is simply
# unused. It exists for local dev (Vite on :5173 talking to uvicorn on
# :8000 -- though the Vite proxy means even that is same-origin) and for
# the day the frontend moves to its own domain. The default is localhost
# only: if you ever need to widen it, set the env var, never edit this.
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "PHISHGUARD_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
RATE_LIMIT_REQUESTS = int(os.getenv("PHISHGUARD_RATE_LIMIT", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("PHISHGUARD_RATE_WINDOW", "60"))
MAX_REQUEST_BYTES = int(os.getenv("PHISHGUARD_MAX_BYTES", str(1_000_000)))

app = FastAPI(
    title="PhishGuard API",
    version="0.1.0",
    description=(
        "Defensive email analysis. Paste a suspicious email, get an explained "
        "risk assessment. Nothing is stored, nothing is fetched, nothing is sent."
    ),
)

# CORS: an explicit allowlist, never "*". With "*" any website your
# browser visits could call this API using your session.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=600,
)


# ---------------------------------------------------------------------------
# Rate limiting -- a sliding window per client IP.
#
# READ THIS BEFORE TRUSTING IT IN PRODUCTION.
#
# The state lives in this process's memory. On a single long-running server
# (uvicorn locally, a container on Fly/Render) that works exactly as you'd
# expect. On serverless -- which is how this deploys to Vercel -- it does
# NOT: each cold start gets a fresh empty dict, and concurrent requests may
# land on different instances that can't see each other's counters. It
# still blunts a burst that hits one warm instance, and it costs nothing,
# so it stays. But it is a speed bump, not a control.
#
# The real fix is shared state: Upstash Redis (has a free tier and a
# Vercel integration) or Vercel's own rate-limiting primitives. That's the
# right next step if this ever gets real traffic. Shipping the honest
# version with the limitation written down beats pretending it scales.
# ---------------------------------------------------------------------------
_request_log: dict[str, deque[float]] = defaultdict(deque)


def _client_key(request: Request) -> str:
    # X-Forwarded-For is trivially spoofable unless a proxy you control
    # sets it. Only trust it when explicitly told to.
    if os.getenv("PHISHGUARD_TRUST_PROXY") == "1":
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def guard(request: Request, call_next):
    # 1. Reject oversized bodies before reading them into memory.
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_REQUEST_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Email too large to analyze."},
        )

    # 2. Rate limit mutating/expensive endpoints.
    if request.url.path.startswith("/api/") and request.method == "POST":
        key = _client_key(request)
        now = time.monotonic()
        window = _request_log[key]
        while window and now - window[0] > RATE_LIMIT_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= RATE_LIMIT_REQUESTS:
            retry_after = int(RATE_LIMIT_WINDOW_SECONDS - (now - window[0])) + 1
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Slow down."},
                headers={"Retry-After": str(retry_after)},
            )
        window.append(now)

    response = await call_next(request)

    # 3. Defensive response headers. Cheap, and they close whole bug
    #    classes even though this API returns JSON only.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "engine": "0.1.0"}


@app.post("/api/analyze", response_model=AnalyzeResponse, tags=["analysis"])
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze one email and return every finding with its explanation."""
    result = analyze_email(
        raw=payload.raw,
        sender_address=payload.sender,
        subject=payload.subject,
        body=payload.body,
        reply_to=payload.reply_to,
        attachment_names=payload.attachments,
    )
    return AnalyzeResponse(**result)


@app.get("/api/samples", response_model=list[SampleOut], tags=["training"])
def samples() -> list[SampleOut]:
    """The fictional training corpus. See app/samples.py for the scope rules."""
    return [SampleOut(**s) for s in list_samples()]


@app.get("/api/samples/{sample_id}", response_model=SampleOut, tags=["training"])
def sample(sample_id: str) -> SampleOut:
    found = get_sample(sample_id)
    if not found:
        raise HTTPException(status_code=404, detail="Sample not found")
    return SampleOut(**found)
