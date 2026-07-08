# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Prometheus-compatible metrics with no external dependency.

Implements the Prometheus text exposition format directly. Metrics:

- ``guardex_request_duration_seconds`` - histogram, request latency
- ``guardex_requests_total`` - counter, by endpoint + result
- ``guardex_errors_total`` - counter, by error type
- ``guardex_cascade_path_total`` - counter, by cascade decision
- ``guardex_keyword_gate_total`` - counter, matched / not matched
- ``guardex_normalization_changes_total`` - counter, text modified

Thread-safe via ``threading.Lock`` on each metric.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

class Counter:
    """Thread-safe monotonically increasing counter."""

    def __init__(self, name: str, help_text: str, labels: tuple[str, ...] = ()):
        self.name = name
        self.help_text = help_text
        self.labels = labels
        self._values: dict[tuple[str, ...], float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, value: float = 1.0, **label_values: str) -> None:
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] += value

    def collect(self) -> str:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} counter"]
        with self._lock:
            for key, val in sorted(self._values.items()):
                if self.labels:
                    label_str = ",".join(
                        f'{l}="{v}"' for l, v in zip(self.labels, key)
                    )
                    lines.append(f"{self.name}{{{label_str}}} {val}")
                else:
                    lines.append(f"{self.name} {val}")
        return "\n".join(lines)


# Histogram

class Histogram:
    """Thread-safe histogram with fixed buckets.

    Buckets follow Prometheus convention: each bucket counts observations
    <= the bucket boundary. +Inf bucket counts all observations.
    """

    def __init__(self, name: str, help_text: str, buckets: tuple[float, ...]):
        self.name = name
        self.help_text = help_text
        self.buckets = buckets
        self._counts: dict[float, int] = {b: 0 for b in buckets}
        self._counts[float("inf")] = 0
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for b in self.buckets:
                if value <= b:
                    self._counts[b] += 1
            self._counts[float("inf")] += 1

    def collect(self) -> str:
        lines = [f"# HELP {self.name} {self.help_text}", f"# TYPE {self.name} histogram"]
        with self._lock:
            for b in self.buckets:
                lines.append(f'{self.name}_bucket{{le="{b}"}} {self._counts[b]}')
            lines.append(f'{self.name}_bucket{{le="+Inf"}} {self._counts[float("inf")]}')
            lines.append(f"{self.name}_sum {self._sum}")
            lines.append(f"{self.name}_count {self._count}")
        return "\n".join(lines)


# Metric instances (module-level singletons)

# Latency histogram - buckets chosen for safety classifier latency profile:
# 10ms (cache hit), 50ms (ONNX fast), 100ms (ONNX slow), 500ms (LlamaGuard),
# 1s (slow LlamaGuard), 5s (timeout territory)
REQUEST_DURATION = Histogram(
    "guardex_request_duration_seconds",
    "Total request processing time in seconds",
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 5.0),
)

REQUESTS_TOTAL = Counter(
    "guardex_requests_total",
    "Total number of screening requests",
    labels=("endpoint", "result"),
)

ERRORS_TOTAL = Counter(
    "guardex_errors_total",
    "Total number of errors",
    labels=("error_type",),
)

CASCADE_PATH = Counter(
    "guardex_cascade_path_total",
    "Cascade decision path distribution",
    labels=("path",),
)

KEYWORD_GATE = Counter(
    "guardex_keyword_gate_total",
    "Keyword gate results",
    labels=("matched",),
)

NORMALIZATION_CHANGES = Counter(
    "guardex_normalization_changes_total",
    "Text normalization changed the input",
    labels=("changed",),
)

INPUT_VALIDATION = Counter(
    "guardex_input_validation_total",
    "Input validation results",
    labels=("result",),
)

# Collection

_ALL_METRICS = [
    REQUEST_DURATION,
    REQUESTS_TOTAL,
    ERRORS_TOTAL,
    CASCADE_PATH,
    KEYWORD_GATE,
    NORMALIZATION_CHANGES,
    INPUT_VALIDATION,
]


def collect_metrics() -> str:
    """Collect all metrics in Prometheus text exposition format."""
    return "\n\n".join(m.collect() for m in _ALL_METRICS) + "\n"
