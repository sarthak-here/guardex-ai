# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""telemetry.py - Optional OpenTelemetry instrumentation for GuardEx SDK.

Provides zero-overhead no-ops when ``opentelemetry-api`` is not installed, and
real spans + attributes when it is.

Usage::

    # Install the extras:
    #   pip install opentelemetry-api opentelemetry-sdk

    from guardex import Guard

    guard = Guard()
    # All guard.screen() / guard.ascreen() calls are automatically instrumented
    # when an OpenTelemetry tracer provider is configured in your app.

Span attributes set on every screening call
-------------------------------------------
``guardex.gate``          – the gate string (e.g. ``"input"``)
``guardex.action``        – ``"pass"`` | ``"block"`` | ``"mask"``
``guardex.safe``          – bool
``guardex.category``      – safety category code if unsafe, else ``""``
``guardex.latency_ms``    – client-side round-trip in milliseconds
``guardex.request_id``    – server-assigned request ID (when present)
``guardex.pii.detected``  – bool
``guardex.pii.count``     – number of PII entities detected
"""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

# Optional OTel import

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import Span, StatusCode
    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False
    _otel_trace = None  # type: ignore
    Span = Any          # type: ignore
    StatusCode = None   # type: ignore


_TRACER_NAME = "guardex"


def _get_tracer():
    if _HAS_OTEL:
        return _otel_trace.get_tracer(_TRACER_NAME)
    return None


# Context manager used by Guard

@contextmanager
def screening_span(gate: str) -> Generator[Optional[Any], None, None]:
    """Context manager that wraps a screening call in an OTel span.

    Yields the span (or ``None`` when OTel is not installed).  The caller is
    responsible for setting attributes on the span after the call.

    Example::

        with screening_span("input") as span:
            result = client.screen(...)
            record_result(span, result)
    """
    tracer = _get_tracer()
    if tracer is None:
        yield None
        return

    with tracer.start_as_current_span(f"guardex.screen.{gate}") as span:
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(StatusCode.ERROR, str(exc))
            raise


def record_result(span: Optional[Any], result: Any) -> None:
    """Attach ScreenResult attributes to an OTel span.

    Safe to call with ``span=None`` (no-op).
    """
    if span is None or not _HAS_OTEL:
        return

    try:
        span.set_attribute("guardex.gate",          result.gate)
        span.set_attribute("guardex.action",         result.action)
        span.set_attribute("guardex.safe",           result.safe)
        span.set_attribute("guardex.category",       result.classify.category or "")
        span.set_attribute("guardex.latency_ms",     result.latency_ms)
        span.set_attribute("guardex.request_id",     result.request_id or "")
        span.set_attribute("guardex.pii.detected",   result.pii.has_pii)
        span.set_attribute("guardex.pii.count",      len(result.pii.entities))
        if result.scope is not None:
            span.set_attribute("guardex.scope.allowed",      result.scope.allowed)
            span.set_attribute("guardex.scope.matched_topic", result.scope.matched_topic or "")
        if result.blocked:
            span.set_status(StatusCode.ERROR, f"blocked: {result.classify.category or 'scope'}")
    except Exception:
        # Never let telemetry errors surface to the caller
        logger.debug("GuardEx telemetry attribute error", exc_info=True)


# Audit logging helpers

_AUDIT_LOGGER = logging.getLogger("guardex.audit")


def emit_audit_log(
    gate: str,
    action: str,
    safe: bool,
    category: Optional[str],
    request_id: Optional[str],
    latency_ms: float,
    pii_detected: bool,
    pii_count: int,
    detailed: bool = False,
    text_preview: Optional[str] = None,
) -> None:
    """Emit a structured audit log entry.

    Uses the ``guardex.audit`` logger at INFO level.  Wire a handler to this
    logger to ship audit events to your SIEM, S3, or audit table.

    Parameters
    ----------
    detailed:
        When True (``policy.detailed_logging=True``), include a truncated
        preview of the screened text.
    """
    record: dict[str, Any] = {
        "event":      "guardex.screen",
        "gate":        gate,
        "action":      action,
        "safe":        safe,
        "category":    category,
        "request_id":  request_id,
        "latency_ms":  round(latency_ms, 2),
        "pii_detected": pii_detected,
        "pii_count":   pii_count,
    }
    if detailed and text_preview is not None:
        record["text_preview"] = text_preview[:200]

    # Emit as a single JSON object so SIEM ingestion (Splunk, ES, Datadog)
    # can parse the line without custom Python-repr handling.
    _AUDIT_LOGGER.info("GUARDEX_AUDIT %s", json.dumps(record, default=str))


def otel_available() -> bool:
    """Return True if opentelemetry-api is installed."""
    return _HAS_OTEL
