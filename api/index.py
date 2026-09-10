"""Vercel serverless entrypoint.

Vercel's Python runtime looks for a module-level object named `app` that
speaks ASGI, and FastAPI is an ASGI app -- so there is no adapter, no
handler function, no `if __name__ == "__main__"`. The same object that
uvicorn runs locally is the one Vercel invokes in production.

Why this file is a thin shim rather than the app itself: keeping the real
application in `app/` means the code doesn't know or care that it's on
Vercel. Local dev (`uvicorn app.main:app`), the test suite, and any future
move to Fly or Render all import the same module. The platform-specific
part is these nine lines, and nothing else in the codebase mentions Vercel.
"""

import sys
from pathlib import Path

# Vercel's working directory when it invokes a function is not guaranteed
# to be the project root, so make the import explicit rather than hoping
# the ambient sys.path is right.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app  # noqa: E402

__all__ = ["app"]
