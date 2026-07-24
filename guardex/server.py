# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Reference GuardEx server - the SDK's local ML pipeline behind HTTP.

Serves the ``/v1`` protocol that ``GuardExClient`` / ``AsyncGuardExClient``
speak, backed by the same ``LocalRunner`` used in in-process mode::

    guardex-server                          # 127.0.0.1:8001
    guardex-server --host 0.0.0.0 --port 9000

    # or with uvicorn directly:
    uvicorn guardex.server:app --port 8001

Then point any GuardEx SDK at it::

    guard = Guard(base_url="http://localhost:8001")

Models load at startup, so the server does not accept traffic until the
pipeline is warm.  There is no authentication: run it on a private network
or front it with your own auth proxy (the SDK sends ``api_key`` as a
standard ``Authorization: Bearer`` header for proxies to check).
"""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Literal, Optional

try:
    from fastapi import FastAPI, Response
    from pydantic import BaseModel, field_validator
except ImportError as e:
    raise ImportError("pip install 'guardex-ai[server]'") from e

from guardex._engine.runner import LocalRunner, _ensure_providers
from guardex._version import get_package_version

MAX_CUSTOM_REGEX_PATTERNS = 32
MAX_CUSTOM_REGEX_LENGTH = 512

_runner = LocalRunner()


def _validate_custom_regex(patterns: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    if not patterns:
        return patterns
    if len(patterns) > MAX_CUSTOM_REGEX_PATTERNS:
        raise ValueError(
            f"pii_custom_regex accepts at most {MAX_CUSTOM_REGEX_PATTERNS} patterns"
        )
    for label, pattern in patterns.items():
        if len(pattern) > MAX_CUSTOM_REGEX_LENGTH:
            raise ValueError(
                f"pii_custom_regex[{label!r}] exceeds {MAX_CUSTOM_REGEX_LENGTH} characters"
            )
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"pii_custom_regex[{label!r}] does not compile: {exc}") from exc
    return patterns


class ScreenRequest(BaseModel):
    text: str
    stage: str = "input"
    pii_action: Literal["mask", "block", "none"] = "mask"
    pii_threshold: float = 0.7
    cascade_mode: str = "safety"
    audit_log: bool = False
    # Sent by the SDK for the audit trail; injection screening is client-side.
    prompt_guard: bool = False
    categories: Optional[List[str]] = None
    pii_entities: Optional[List[str]] = None
    pii_custom_regex: Optional[Dict[str, str]] = None
    scope_topics: Optional[List[str]] = None
    scope_utterances: Optional[Dict[str, List[str]]] = None
    scope_examples: Optional[List[str]] = None
    scope_width: str = "moderate"
    scope_threshold: Optional[float] = None
    scope_alpha: float = 0.0

    @field_validator("pii_custom_regex")
    @classmethod
    def _check_custom_regex(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        return _validate_custom_regex(v)


class ScreenBatchRequest(BaseModel):
    requests: List[ScreenRequest]


class ClassifyRequest(BaseModel):
    text: str
    stage: str = "input"
    categories: Optional[List[str]] = None


class PIIRequest(BaseModel):
    text: str
    threshold: float = 0.7
    entities: Optional[List[str]] = None


class GroundingRequest(BaseModel):
    response_text: str
    sources: List[str]
    mode: Optional[str] = None
    threshold: Optional[float] = None


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    import asyncio

    await asyncio.to_thread(_ensure_providers)
    yield


app = FastAPI(
    title="GuardEx",
    version=get_package_version(),
    lifespan=_lifespan,
)


def _screen_one(req: ScreenRequest) -> tuple[Dict[str, Any], Optional[str]]:
    return _runner.screen(
        text=req.text,
        stage=req.stage,
        pii_action=req.pii_action,
        categories=req.categories,
        pii_entities=req.pii_entities,
        pii_threshold=req.pii_threshold,
        pii_custom_regex=req.pii_custom_regex,
        scope_topics=req.scope_topics,
        scope_utterances=req.scope_utterances,
        scope_examples=req.scope_examples,
        scope_width=req.scope_width,
        scope_threshold=req.scope_threshold,
        scope_alpha=req.scope_alpha,
        cascade_mode=req.cascade_mode,
        audit_log=req.audit_log,
    )


@app.post("/v1/screen")
def screen(req: ScreenRequest, response: Response) -> Dict[str, Any]:
    raw, request_id = _screen_one(req)
    if request_id:
        response.headers["X-GuardEx-Request-Id"] = request_id
    return raw


@app.post("/v1/screen/batch")
def screen_batch(req: ScreenBatchRequest) -> Dict[str, Any]:
    return {"results": [_screen_one(item)[0] for item in req.requests]}


@app.post("/v1/classify")
def classify(req: ClassifyRequest) -> Dict[str, Any]:
    return _runner.classify(req.text, stage=req.stage, categories=req.categories)


@app.post("/v1/pii/scan")
def pii_scan(req: PIIRequest) -> Dict[str, Any]:
    return _runner.pii_scan(req.text, entities=req.entities, threshold=req.threshold)


@app.post("/v1/pii/mask")
def pii_mask(req: PIIRequest) -> Dict[str, Any]:
    return _runner.pii_mask(req.text, entities=req.entities, threshold=req.threshold)


@app.post("/v1/grounding")
def grounding(req: GroundingRequest, response: Response) -> Dict[str, Any]:
    raw, request_id = _runner.check_grounding(
        response_text=req.response_text,
        sources=req.sources,
        mode=req.mode,
        threshold=req.threshold,
    )
    if request_id:
        response.headers["X-GuardEx-Request-Id"] = request_id
    return raw


@app.get("/v1/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "version": get_package_version(), "mode": "local"}


def main() -> None:
    """Entry point for the ``guardex-server`` CLI command."""
    try:
        import uvicorn
    except ImportError:
        raise SystemExit("pip install 'guardex-ai[server]'")

    import argparse

    parser = argparse.ArgumentParser(description="Reference GuardEx screening server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Port to serve on (default: 8001)")
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
