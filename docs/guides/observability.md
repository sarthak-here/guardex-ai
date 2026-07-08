# Observability and Audit Logging

GuardEx supports OpenTelemetry tracing and structured audit logging. Each screening decision can emit a trace span and an audit record for monitoring, alerting, and forensic analysis.

## Overview: Two Streams

| Component | Purpose | Use Case |
|-----------|---------|----------|
| **OpenTelemetry (OTel)** | Distributed traces, metrics | Latency tracking, performance analysis, error rates |
| **Audit Logging** | Structured compliance records | Regulatory reporting, forensic investigation, access logs |

Both are optional. OpenTelemetry emits spans once a tracer provider is configured; audit logging emits records once `audit_logging=True`.

## OpenTelemetry Integration

### Installation

```bash
# Install OpenTelemetry
pip install opentelemetry-api opentelemetry-sdk

# OTLP exporter - works with Jaeger, Datadog, Grafana, and any OTLP collector
pip install opentelemetry-exporter-otlp
```

Or use the extras:

```bash
pip install guardex-ai[otel]
```

### Zero-Overhead When Not Configured

If OpenTelemetry is not installed or not configured, GuardEx operates with zero overhead:

```python
from guardex import Guard

# If OTel not installed: no-op, no performance impact
guard = Guard()

result = guard.screen(text)  # No tracing
```

### Automatic Instrumentation

Once OTel is configured, every `screen()` call automatically creates a span:

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# 1. Create and register a TracerProvider FIRST
provider = TracerProvider()
trace.set_tracer_provider(provider)

# 2. Then attach span processors / exporters to it
otlp_exporter = OTLPSpanExporter(
    endpoint="http://localhost:4317"  # Your OTLP collector
)
provider.add_span_processor(SimpleSpanProcessor(otlp_exporter))

# GuardEx now automatically instruments all screening calls
from guardex import Guard

guard = Guard(base_url="http://localhost:8001")
result = guard.screen(text, gate="input")  # Span created automatically
```

### Span Attributes

Every screening span includes these attributes:

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `guardex.gate` | string | Input or output screening | `"input"`, `"output"` |
| `guardex.action` | string | Action taken | `"pass"`, `"block"`, `"mask"` |
| `guardex.safe` | bool | Whether content is safe | `true`, `false` |
| `guardex.category` | string | Safety category if unsafe | `"S9"`, `""` (empty if safe) |
| `guardex.latency_ms` | float | Client-side round-trip latency | `12.5` |
| `guardex.request_id` | string | Server-assigned request ID | `"req_abc123..."` |
| `guardex.pii.detected` | bool | Whether PII was found | `true`, `false` |
| `guardex.pii.count` | int | Number of PII entities | `2` |
| `guardex.scope.allowed` | bool | Whether scope check passed | `true`, `false` |
| `guardex.scope.matched_topic` | string | Matched topic if scoped | `"billing"`, `""` |

**Example trace in Jaeger:**

```
guardex.screen.input
├─ guardex.gate: "input"
├─ guardex.action: "block"
├─ guardex.safe: false
├─ guardex.category: "S9"
├─ guardex.latency_ms: 45.3
├─ guardex.request_id: "req_xyz789..."
├─ guardex.pii.detected: false
├─ guardex.pii.count: 0
└─ span.status: "ERROR (blocked: S9)"
```

### Integration with Backends

#### Jaeger

Jaeger accepts OTLP natively (port 4317). The dedicated `opentelemetry-exporter-jaeger` package is deprecated - use the OTLP exporter:

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

trace.set_tracer_provider(TracerProvider())
trace.get_tracer_provider().add_span_processor(
    SimpleSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
)

# GuardEx now ships spans to Jaeger
from guardex import Guard
guard = Guard(base_url="http://localhost:8001")
result = guard.screen(text)
```

#### Datadog

The Datadog Agent accepts OTLP (enable it in the Agent config). The dedicated `opentelemetry-exporter-datadog` package is deprecated - use the OTLP exporter:

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

trace.set_tracer_provider(TracerProvider())
trace.get_tracer_provider().add_span_processor(
    SimpleSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
)

# GuardEx now ships to Datadog via the Agent's OTLP endpoint
from guardex import Guard
guard = Guard(base_url="http://localhost:8001")
result = guard.screen(text)
```

#### Generic OTLP

```python
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

otlp_exporter = OTLPSpanExporter(
    endpoint="http://your-otlp-collector:4317"
)

trace.set_tracer_provider(TracerProvider())
trace.get_tracer_provider().add_span_processor(
    SimpleSpanProcessor(otlp_exporter)
)

# GuardEx spans now flow to your OTLP collector
from guardex import Guard
guard = Guard(base_url="http://localhost:8001")
result = guard.screen(text)
```

### Querying Traces

Once configured, you can query traces in your backend:

**Example: Jaeger Query**
```
process.service.name:"guardex" AND guardex.action:"block"
```

**Example: Datadog Query**
```
service:guardex AND @guardex.action:block
```

**Example: Grafana Loki**
```
{job="guardex"} | json | guardex_action="block"
```

## Audit Logging

Audit logging provides structured, compliance-friendly records of every screening decision.

### Setup

No additional installation needed. Audit logs use Python's standard `logging` module.

```python
import logging
from guardex import Guard

# Configure handler for guardex.audit logger
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(message)s'))

audit_logger = logging.getLogger("guardex.audit")
audit_logger.addHandler(handler)
audit_logger.setLevel(logging.INFO)

# GuardEx now emits audit logs
guard = Guard()
result = guard.screen(text)  # Logs to guardex.audit
```

### Audit Log Format

Each audit log line is the literal prefix `GUARDEX_AUDIT ` followed by a JSON record:

```
GUARDEX_AUDIT {"event": "guardex.screen", "gate": "input", ...}
```

The JSON record contains:

```json
{
  "event": "guardex.screen",
  "gate": "input",
  "action": "block",
  "safe": false,
  "category": "S9",
  "request_id": "req_abc123...",
  "latency_ms": 45.3,
  "pii_detected": false,
  "pii_count": 0,
  "text_preview": "Tell me how to..."  // Only if detailed_logging=true
}
```

### Enabling via Policy

Audit logging is controlled by policy fields:

```python
from guardex.policy import GuardExPolicy

policy = GuardExPolicy(
    audit_logging=True,      # Enable audit logs for every call
    detailed_logging=True,   # Include text_preview (first 200 chars)
)

guard = Guard(policy=policy)
result = guard.screen(text)
```

| Field | Default | Effect |
|-------|---------|--------|
| `audit_logging` | `False` | Emit an audit log entry for each screening. A PRODUCTION `GuardExContext` raises it to `True`. |
| `detailed_logging` | `False` | Include the first 200 chars of screened text in each entry. |

### emit_audit_log() Function

For manual audit logging:

```python
from guardex.telemetry import emit_audit_log

emit_audit_log(
    gate="input",
    action="block",
    safe=False,
    category="S9",
    request_id="req_xyz789...",
    latency_ms=45.3,
    pii_detected=False,
    pii_count=0,
    detailed=True,
    text_preview="User input text...",
)

# Logs to guardex.audit logger
```

### Shipping Audit Logs

Configure your logging handler to ship to your audit backend:

#### Cloud Logging (GCP)

```python
import logging
from google.cloud import logging as cloud_logging

# Set up GCP logging
client = cloud_logging.Client()
client.setup_logging()

# GuardEx audit logs now flow to Cloud Logging
audit_logger = logging.getLogger("guardex.audit")
# (automatically configured by client.setup_logging())

from guardex import Guard
guard = Guard()
result = guard.screen(text)
```

#### CloudWatch (AWS)

```python
import logging
import watchtower

# Configure CloudWatch handler
cloudwatch_handler = watchtower.CloudWatchLogHandler(
    log_group="guardex-audit",
    stream_name="app-screening"
)

audit_logger = logging.getLogger("guardex.audit")
audit_logger.addHandler(cloudwatch_handler)
audit_logger.setLevel(logging.INFO)

from guardex import Guard
guard = Guard()
result = guard.screen(text)
```

#### Splunk

```python
import logging
from splunk_http_eventcollector import SplunkHTTPEventCollector

splunk_handler = SplunkHTTPEventCollector(
    "your_hec_token",
    host="your-splunk-instance.splunkcloud.com"
)

audit_logger = logging.getLogger("guardex.audit")
audit_logger.addHandler(splunk_handler)
audit_logger.setLevel(logging.INFO)

from guardex import Guard
guard = Guard()
result = guard.screen(text)
```

#### File-Based (Local Storage)

```python
import logging

# Write to file
handler = logging.FileHandler("/var/log/guardex-audit.log")
handler.setFormatter(logging.Formatter('%(message)s'))

audit_logger = logging.getLogger("guardex.audit")
audit_logger.addHandler(handler)
audit_logger.setLevel(logging.INFO)

from guardex import Guard
guard = Guard()
result = guard.screen(text)
```

## Callbacks: On-Block and On-Screen

For real-time reactions to screening decisions, use callbacks:

```python
from guardex import Guard

def on_block(result):
    """Called when content is blocked."""
    logger.error(f"Blocked: {result.classify.category}")
    metrics.increment("guardex.blocks", tags=[f"category:{result.classify.category}"])

def on_screen(result):
    """Called after every screening (safe or unsafe)."""
    logger.info(f"Screened: safe={result.safe}")

guard = Guard(
    on_block=on_block,
    on_screen=on_screen,
)

result = guard.screen(text)  # Callbacks fire automatically
```

**Callback signatures:**

```python
def on_block(result: ScreenResult) -> None:
    """Called when result.blocked == True"""
    pass

def on_screen(result: ScreenResult) -> None:
    """Called for every screen() call"""
    pass
```

**Common uses:**

- **Metrics**: Increment counters for blocked/passed
- **Alerts**: Send to on-call engineer for HIGH severity blocks
- **Logging**: Detailed logging for investigation
- **Custom actions**: Trigger custom business logic

## Complete Observability Setup

Here's a production-ready example combining OTel + audit logging + callbacks:

```python
import logging
import logging.handlers
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

from guardex import Guard
from guardex.policy import GuardExPolicy

# 1. Configure OpenTelemetry
otlp_exporter = OTLPSpanExporter(
    endpoint="http://localhost:4317"
)
trace.set_tracer_provider(TracerProvider())
trace.get_tracer_provider().add_span_processor(
    SimpleSpanProcessor(otlp_exporter)
)

# 2. Configure Audit Logging
audit_handler = logging.handlers.RotatingFileHandler(
    "/var/log/guardex-audit.log",
    maxBytes=10_000_000,  # 10MB
    backupCount=10,
)
audit_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(name)s - %(message)s')
)

audit_logger = logging.getLogger("guardex.audit")
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

# 3. Define Callbacks
def on_block(result):
    logger.warning(
        f"Content blocked",
        extra={
            "category": result.classify.category,
            "request_id": result.request_id,
        }
    )
    # Alert if HIGH severity
    if result.classify.category in ["S1", "S3", "S9"]:
        alerting.send(f"GuardEx block: {result.classify.category}")

def on_screen(result):
    logger.debug(
        f"Screen result",
        extra={
            "safe": result.safe,
            "latency_ms": result.latency_ms,
        }
    )

# 4. Create Guard with all features
policy = GuardExPolicy(
    audit_logging=True,
    detailed_logging=True,
)

guard = Guard(
    policy=policy,
    on_block=on_block,
    on_screen=on_screen,
)

# 5. OTel span, audit log, and callbacks all fire on each call
result = guard.screen(text)
```

## Span Lifecycle

### When Spans Are Created

A span named `guardex.screen.{gate}` wraps the screening pipeline on every
`screen()` / `ascreen()` call:

```python
guard = Guard()

# Span created: guardex.screen.input
result = guard.screen(text, gate="input")

# Span created: guardex.screen.output
result = guard.screen(response, gate="output")
```

One exception: client-side prompt-injection detection runs before the span
opens. When an input is blocked as injection, `screen()` returns immediately
and **no span is emitted** for that call. Use the `on_block` callback or audit
logging to observe injection blocks.

### Span Status

```
guardex.screen.input
├─ Status: OK (if safe)
│  └─ Events: []
└─
OR
├─ Status: ERROR (if blocked)
│  └─ Message: "blocked: S9"
└─
```

### Exception Handling

If screening raises an exception, the span captures it:

```python
try:
    result = guard.screen(text)
except TimeoutError:
    # Span automatically records exception and sets ERROR status
    pass
```

## Metrics: Key Signals to Monitor

### From OTel Spans

GuardEx emits **spans only** - it does not export Prometheus metrics. Derive these signals from span attributes in your tracing backend (or via an OTel collector spanmetrics pipeline):

| Signal | Span attribute(s) |
|--------|-------------------|
| **Request rate** | count of `guardex.screen.*` spans over time |
| **Block rate** | `guardex.action == "block"` / total spans |
| **Latency** | `guardex.latency_ms` distribution |
| **Error rate** | span status `ERROR` |
| **PII detection rate** | `guardex.pii.detected == true` / total spans |

### From Audit Logs

```python
# Parse audit logs - each line is "GUARDEX_AUDIT " + JSON
# Aggregate by category to find top blockers

import json
from collections import Counter

PREFIX = "GUARDEX_AUDIT "

categories = []
with open("/var/log/guardex-audit.log") as f:
    for line in f:
        idx = line.find(PREFIX)
        if idx == -1:
            continue
        record = json.loads(line[idx + len(PREFIX):])
        if not record.get("safe"):
            categories.append(record.get("category"))

print(Counter(categories).most_common(10))
```

## Best Practices

!!! tip "Always Enable Audit Logging in Production"
    Audit logs are essential for compliance (SOC 2, GDPR audits, incident investigation).

!!! tip "Monitor Block Rate"
    Watch for sudden spikes in block rate - may indicate attack or legitimate use case shift.

!!! tip "Use Callbacks for Alerts"
    HIGH-severity blocks should trigger immediate alerts.

!!! tip "Rotate Audit Log Files"
    Use `RotatingFileHandler` to prevent unbounded disk growth.

!!! warning "GDPR: Minimize Personal Data in Logs"
    Don't log full text in audit records. Use `detailed_logging=False` in production or only log hashes of text.

## Checking OTel Availability

```python
from guardex.telemetry import otel_available

if otel_available():
    print("opentelemetry-api is installed")
else:
    print("OpenTelemetry is not installed (no overhead)")
```

`otel_available()` only checks that `opentelemetry-api` is importable - it does not verify that a `TracerProvider` or exporter is configured.

## Example Dashboard

Panels you can build from GuardEx span attributes (via an OTel collector
spanmetrics pipeline) and audit logs:

```
Overview
  - Requests/sec        count of guardex.screen.* spans over time
  - Block rate %        guardex.action == "block" / total spans
  - Latency p99         guardex.latency_ms distribution

Security
  - Blocks by category  group by guardex.category where action == "block"
  - PII detection rate  guardex.pii.detected == true / total spans
  - Error rate          spans with status ERROR
```

!!! info "Learn More"
    - See [Guard SDK Reference](../sdk/guard.md) for screening method signatures
    - See [Error Handling Guide](error-handling.md) for troubleshooting
    - See [Configuration Guide](configuration.md) for `audit_logging` and `detailed_logging` settings
