"""PhishLens local API: POST /analyze and GET /health.

Run from the repo root, so `model` can be imported:

    uvicorn api.main:app --host 127.0.0.1 --port 8000

Security notes (see CLAUDE.md):
- No CORS middleware. The extension calls this API from its service worker, which
  host_permissions allow without CORS. Without CORS headers, browsers don't let other
  websites read the responses.
- TrustedHostMiddleware only answers requests addressed to 127.0.0.1 or localhost.
  This blocks "DNS rebinding": a website points its own domain at 127.0.0.1 so the
  browser treats the API as part of that website.
- POST bodies must be JSON and at most 100 KB.
- Email content is never logged, stored or echoed back: it only lives in memory for
  one request. Error responses and log lines never include it.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.schemas import AnalyzeRequest, AnalyzeResponse, HealthResponse
from model.src.predict import analyze, load_model

MAX_BODY_BYTES = 100 * 1024
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs once at startup, before any request is answered.

    Without a trained model the server refuses to start, and uvicorn shows
    load_model()'s message saying how to train one.
    """
    app.state.model = load_model()
    yield


app = FastAPI(title="PhishLens", lifespan=lifespan)


def _error(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status_code)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    """422 with where and what went wrong, but not the value that was sent.

    FastAPI's default 422 includes each invalid value ("input") and extra details
    ("ctx"), which can be email content. Keep only the location, message and type.
    """
    errors = [
        {"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in error.errors()
    ]
    return JSONResponse({"detail": errors}, status_code=422)


@app.middleware("http")
async def check_post_body(request: Request, call_next):
    """Reject a POST before its body is read unless it is JSON of at most 100 KB.

    The size comes from the Content-Length header. The server never reads past it,
    so a body can't be bigger than it says. A body sent in chunks has no
    Content-Length, so it's refused too.
    """
    if request.method == "POST":
        content_type = request.headers.get("content-type", "")
        # A webpage can send text/plain or form data without asking first (no CORS
        # preflight), but not application/json. So only JSON is accepted.
        if content_type.split(";")[0].strip().lower() != "application/json":
            return _error(415, "Content-Type must be application/json")
        length = request.headers.get("content-length")
        if length is None or "transfer-encoding" in request.headers:
            return _error(411, "Content-Length header required")
        if not length.isdigit() or int(length) > MAX_BODY_BYTES:
            return _error(413, f"Request body must be at most {MAX_BODY_BYTES} bytes")
    return await call_next(request)


# Added last, so it runs first: a request for the wrong host is refused before
# anything else looks at it.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)


@app.get("/health", response_model=HealthResponse)
def health() -> dict:
    return {"status": "ok"}


# A plain `def`, not `async def`: FastAPI runs it in a thread pool, so the model's
# CPU work doesn't block the server from answering other requests meanwhile.
@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(
    email: AnalyzeRequest, request: Request
) -> AnalyzeResponse | JSONResponse:
    try:
        result = analyze(email.model_dump(), model=request.app.state.model)
        # Checked here, inside the try: if analyze() ever returned something off-
        # contract, FastAPI's own error would include the result, i.e. email content.
        return AnalyzeResponse.model_validate(result)
    except Exception as error:
        # Only the type name: an exception's message or traceback can quote the email.
        logger.error("analyze() failed with %s", type(error).__name__)
        return _error(500, "Internal server error")
