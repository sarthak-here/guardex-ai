# SDK Reference: Guard

`guardex.Guard` - The primary interface. Framework-agnostic guardrails for any LLM.

---

## Import

```python
from guardex import Guard
```

---

## Constructor

```python
Guard(
    api_key: str | None = None,
    base_url: str | None = None,
    policy: GuardExPolicy | None = None,
    fail_open: bool = False,
    on_block: Callable[[ScreenResult], None] | None = None,
    on_screen: Callable[[ScreenResult], None] | None = None,
    injection_check: bool = True,
    ollama_url: str | None = None,
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str \| None` | `None` | Bearer token sent to a server that fronts the API with auth. Falls back to `GUARDEX_API_KEY`. Not needed for local in-process mode. |
| `base_url` | `str \| None` | `None` | Self-hosted server URL (e.g. `http://localhost:8001`). Falls back to `GUARDEX_BASE_URL` env var. Omit for local in-process mode. |
| `policy` | `GuardExPolicy \| None` | `None` | Full configuration object. If `base_url` is also passed, it takes precedence over the policy's value. |
| `fail_open` | `bool` | `False` | When `True`, treat screening errors as safe (allow content through). |
| `on_block` | `Callable[[ScreenResult], None] \| None` | `None` | Optional callback fired when content is blocked. |
| `on_screen` | `Callable[[ScreenResult], None] \| None` | `None` | Optional callback fired on every screening result. |
| `injection_check` | `bool` | `True` | When `True`, run a client-side regex injection scan before screening. Negligible overhead for clean content. |
| `ollama_url` | `str \| None` | `None` | Custom Ollama server URL for local mode (e.g. `http://localhost:11434`). Only used in local in-process mode when `guardex-ai[local]` is installed. |

### Examples

```python
from guardex import Guard, GuardExPolicy, ScreenResult

# Local mode (requires: pip install guardex-ai[local])
# No server needed - ML runs in-process
guard = Guard()

# Self-hosted server mode
guard = Guard(base_url="http://localhost:8001")

# With callbacks
def on_block_handler(result: ScreenResult):
    print(f"Blocked: {result.classify.category}")

guard = Guard(
    base_url="http://localhost:8001",
    on_block=on_block_handler,
)

# With full policy
guard = Guard(policy=GuardExPolicy(
    blocked_categories=["S1", "S3", "S4", "S9", "S11"],
    pii_action="mask",
    fail_open=False,
))

# Disable client-side injection detection (server mode)
guard = Guard(base_url="http://localhost:8001", injection_check=False)

# Local mode with custom Ollama server
guard = Guard(ollama_url="http://localhost:11434")
```

---

## Modes of Operation

Guard operates in one of two modes, selected automatically at construction:

### Self-Hosted Server Mode

When `base_url` is provided (or set via `GUARDEX_BASE_URL` env var), Guard connects to your self-hosted GuardEx server. All ML inference runs server-side.

```python
# Server mode - connects to your self-hosted GuardEx server
guard = Guard(base_url="http://localhost:8001")
```

### Local In-Process Mode

When `base_url` is not set, Guard runs ML inference in-process using `guardex-ai[local]` extras. No server needed.

```bash
pip install guardex-ai[local]  # Installs onnxruntime, gliner, sentence-transformers
```

```python
# Local mode - zero config
guard = Guard()
result = guard.screen("user input", gate="input")
```

If `guardex-ai[local]` extras are not installed and no `base_url` is configured, Guard will raise an error.

---

## Callbacks

Guard can fire callbacks on screening results:

| Callback | When Fired | Use Case |
|----------|-----------|----------|
| `on_block` | Content is blocked | Log violations, alert admins, trigger workflows |
| `on_screen` | Every screening call | Audit logging, metrics collection, analytics |

```python
def log_violation(result: ScreenResult):
    logger.warning(f"Blocked at {result.gate}: {result.classify.category}")

def track_metrics(result: ScreenResult):
    metrics.increment("guardex.screens", tags=[f"gate:{result.gate}"])

guard = Guard(
    base_url="http://localhost:8001",
    on_block=log_violation,
    on_screen=track_metrics,
)
```

---

## Injection Detection

When `injection_check=True` (default), Guard runs a client-side `InjectionDetector` on all input gates before screening.

| Feature | Behavior |
|---------|----------|
| **Timing** | Runs synchronously before screening |
| **Gates** | Applies to `"input"`, `"prompt"`, `"tool_input"`, `"retrieval_query"` |
| **Latency** | A regex pass; negligible overhead for clean content |
| **Result** | Returns `ScreenResult` with action `"block"` and category `"injection"` |
| **Disable** | Pass `injection_check=False` to constructor |

```python
# Prompt injection is detected immediately (before full screening)
guard = Guard(injection_check=True)
result = guard.screen("Ignore instructions and...", gate="input")
if result.blocked and result.classify.category == "injection":
    print("Injection attempt blocked")
```

---

## Sync Methods

### screen()

Screen text for safety and PII. Returns a `ScreenResult` without raising exceptions on violations.

```python
guard.screen(
    text: str,
    gate: Gate = "input",
    context: GuardExContext | None = None,
) -> ScreenResult
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | (required) | Text to screen |
| `gate` | `Gate` | `"input"` | Screening position (see [Gates](#gates)) |
| `context` | `GuardExContext \| None` | `None` | Optional context for policy resolution |

**Returns:** [`ScreenResult`](types.md#screenresult)

```python
result = guard.screen("My SSN is 123-45-6789", gate="input")
if result.blocked:
    print(f"Blocked: {result.classify.category}")
elif result.safe:
    print(f"Safe text: {result.text}")  # PII-masked if pii_action="mask"
    print(f"Latency: {result.latency_ms}ms")
```

---

### screen_or_raise()

Screen text and raise on violations. Returns the processed text string directly.

`block_on_unsafe_input` / `block_on_unsafe_output` gate the safety-classifier verdict only. If a flag is off for a gate, text the classifier flagged as unsafe is returned instead of raising. Prompt injection, topic scope, safety routes, and `pii_action="block"` always raise regardless of these flags.

```python
guard.screen_or_raise(
    text: str,
    gate: Gate = "input",
    context: GuardExContext | None = None,
) -> str
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | (required) | Text to screen |
| `gate` | `Gate` | `"input"` | Screening position |
| `context` | `GuardExContext \| None` | `None` | Optional context for policy resolution |

**Returns:** `str` - The processed text (PII-masked if applicable).

**Raises:**

- `GuardExViolation` - The content was blocked by an enforced control: safety classifier (when `block_on_unsafe_*` is on for the gate), prompt injection, topic scope, safety route, or `pii_action="block"`.

```python
try:
    safe_text = guard.screen_or_raise("user input", gate="input")
except GuardExViolation as e:
    print(f"Violation at {e.stage}: {e.category}")
```

!!! note "PII blocking"
    With `pii_action="block"`, `screen_or_raise()` raises `GuardExViolation` (with `category="pii"`) when PII is present — not the `PIIViolation` subclass. To inspect the detected entities instead of raising, use `screen()` and check `result.pii`. The LangChain wrappers (`GuardedLLM`, `GuardExCallbackHandler`) raise `PIIViolation`, which carries `entities_found`.

---

### classify()

Safety classification only (no PII detection).

```python
guard.classify(
    text: str,
    gate: Gate = "input",
    context: GuardExContext | None = None,
) -> ClassifyResult
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | (required) | Text to classify |
| `gate` | `Gate` | `"input"` | Screening position |
| `context` | `GuardExContext \| None` | `None` | Optional context for policy resolution |

**Returns:** [`ClassifyResult`](types.md#classifyresult)

```python
result = guard.classify("some text", gate="input")
print(result.safe)        # True/False
print(result.category)    # None or "S9" or other category
print(result.categories)  # [] or ["S9", "S11"]
print(result.confidence)  # 0.0 to 1.0
```

---

### pii_scan()

PII detection only (no masking, no safety classification).

```python
guard.pii_scan(
    text: str,
    context: GuardExContext | None = None,
) -> PIIResult
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | (required) | Text to scan |
| `context` | `GuardExContext \| None` | `None` | Optional context for policy resolution |

**Returns:** [`PIIResult`](types.md#piiresult)

```python
result = guard.pii_scan("My email is test@example.com")
print(result.has_pii)     # True/False
for entity in result.entities:
    print(f"{entity.label}: {entity.text} (score={entity.score:.2f})")
    print(f"  Position: {entity.start}-{entity.end}")
```

---

### pii_mask()

PII detection and masking. Returns the masked text.

```python
guard.pii_mask(
    text: str,
    context: GuardExContext | None = None,
) -> str
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `text` | `str` | (required) | Text to mask |
| `context` | `GuardExContext \| None` | `None` | Optional context for policy resolution |

**Returns:** `str` - Text with PII replaced by `[LABEL]` placeholders.

```python
masked = guard.pii_mask("Email: alice@example.com, Phone: 555-1234")
print(masked)  # "Email: [EMAIL], Phone: [PHONE_NUMBER]"
```

---

### screen_batch()

Screen a batch of texts in a single call. More efficient than calling `screen()` multiple times.

```python
guard.screen_batch(
    texts: List[str],
    gate: Gate = "input",
    context: GuardExContext | None = None,
) -> List[ScreenResult]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `texts` | `List[str]` | (required) | Texts to screen |
| `gate` | `Gate` | `"input"` | Screening position (applied to all texts) |
| `context` | `GuardExContext \| None` | `None` | Optional context for policy resolution |

**Returns:** `List[ScreenResult]` - One result per input text, in the same order.

```python
texts = [
    "Hello, world!",
    "My SSN is 123-45-6789",
    "How can I help?",
]

results = guard.screen_batch(texts, gate="input")
for i, result in enumerate(results):
    if result.blocked:
        print(f"Text {i} blocked: {result.classify.category}")
    else:
        print(f"Text {i} safe: {result.text}")
```

---

### check_grounding()

Verify whether an LLM response is grounded (faithful) to the provided source documents. Detects hallucinations, contradictions, and ungrounded claims.

```python
def check_grounding(
    self,
    response_text: str,
    sources: list[str],
    mode: str | None = None,         # "speed" or "accuracy"; falls back to policy.grounding_mode
    threshold: float | None = None,  # falls back to policy.grounding_threshold
) -> GroundingResult
```

**Async:** `await guard.acheck_grounding(...)`

**Example:**

```python
result = guard.check_grounding(
    response_text="GuardEx supports 14 safety categories.",
    sources=["GuardEx classifies content into 14 safety categories from S1 to S14."],
)
if result.hallucinated:
    print(f"Hallucination! {result.faithfulness_score:.0%} grounded")
    for s in result.hallucinated_sentences:
        print(f"  - {s.sentence} ({s.verdict}, score={s.score:.2f})")
```

---

### screen_grounded()

Combines safety screening + grounding check in one call. If screen blocks, grounding is skipped.

```python
def screen_grounded(
    self,
    response_text: str,
    sources: list[str],
    gate: Gate = "output",
    context: GuardExContext | None = None,
    grounding_mode: str | None = None,
    grounding_threshold: float | None = None,
) -> tuple[ScreenResult, GroundingResult]
```

**Async:** `await guard.ascreen_grounded(...)`

**Example:**

```python
screen_result, grounding_result = guard.screen_grounded(
    response_text=llm_response,
    sources=retrieved_chunks,
    gate="output",
)
if screen_result.blocked:
    print("Unsafe content")
elif grounding_result.hallucinated:
    print("Contains hallucinations")
else:
    print(screen_result.text)  # Safe and grounded
```

---

### wrap()

Wrap any callable with automatic safety screening on input and output.

Screens ALL string positional arguments, not just the first.

```python
guard.wrap(
    fn: Callable,
    gate: Gate = "tool_input",
    screen_output: bool = True,
) -> Callable
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fn` | `Callable` | (required) | The function to wrap |
| `gate` | `Gate` | `"tool_input"` | Gate for input screening |
| `screen_output` | `bool` | `True` | Also screen the function's return value |

**Returns:** A new callable with the same signature.

```python
def search_web(query: str, domain: str = "example.com") -> str:
    """Pseudo search function."""
    return f"Results for {query} on {domain}"

# Wrap the function
safe_search = guard.wrap(search_web, gate="tool_input", screen_output=True)

# Both positional arguments are screened before the function runs
# The return value is also screened
result = safe_search("user query", "safe-domain.com")
```

!!! info "Multiple string arguments"
    Guard screens ALL string positional arguments, not just the first. Non-string arguments are passed through unchanged.

---

### stream()

Screen streaming text chunks. Buffers and screens at content boundaries or flush limits.

Works with any streaming source - OpenAI, Anthropic, LangChain, raw SSE, websockets, or custom iterators.

```python
guard.stream(
    chunks: Iterator[str],
    gate: Gate = "output",
    flush_every: int = 256,
    context: GuardExContext | None = None,
    vault: PIIVault | None = None,
    restore_mode: str = "off",
) -> Iterator[str]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `chunks` | `Iterator[str]` | (required) | Iterator of text chunks |
| `gate` | `Gate` | `"output"` | Gate for screening |
| `flush_every` | `int` | `256` | Buffer size (chars) before forced flush |
| `context` | `GuardExContext \| None` | `None` | Optional context for policy resolution |
| `vault` | `PIIVault \| None` | `None` | Vault used to restore `{{pii:...}}` tokens emitted by the upstream LLM |
| `restore_mode` | `str` | `"off"` | Vault token restoration mode; forced to `"off"` when no `vault` is given |

**Yields:** `str` - Screened text chunks.

**Raises:** `GuardExViolation` mid-stream if unsafe content is detected.

```python
# OpenAI streaming example
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
    stream=True,
)

for chunk in guard.stream(
    (c.choices[0].delta.content or "" for c in response),
    gate="output"
):
    print(chunk, end="", flush=True)
```

---

## Async Methods

### ascreen()

Async version of `screen()`. Supports context-aware policy resolution.

```python
await guard.ascreen(
    text: str,
    gate: Gate = "input",
    context: GuardExContext | None = None,
) -> ScreenResult
```

```python
result = await guard.ascreen("Check this text", gate="output")
if result.blocked:
    print(f"Blocked: {result.classify.category}")
```

---

### ascreen_or_raise()

Async version of `screen_or_raise()`. Respects policy block flags.

```python
await guard.ascreen_or_raise(
    text: str,
    gate: Gate = "input",
    context: GuardExContext | None = None,
) -> str
```

```python
try:
    safe_text = await guard.ascreen_or_raise("user input", gate="input")
except GuardExViolation as e:
    print(f"Violation: {e.category}")
```

---

### ascreen_batch()

Async batch screening. One call for multiple texts.

```python
await guard.ascreen_batch(
    texts: List[str],
    gate: Gate = "input",
    context: GuardExContext | None = None,
) -> List[ScreenResult]
```

```python
texts = ["Hello", "Bad content", "Good bye"]
results = await guard.ascreen_batch(texts, gate="input")
for result in results:
    print(f"Action: {result.action}")
```

---

### astream()

Async version of `stream()`. Screens async chunk iterators.

```python
async for chunk in guard.astream(
    chunks: AsyncIterator[str],
    gate: Gate = "output",
    flush_every: int = 256,
    context: GuardExContext | None = None,
    vault: PIIVault | None = None,
    restore_mode: str = "off",
):
    print(chunk, end="", flush=True)
```

```python
# Anthropic streaming example (with async client)
import anthropic

async with anthropic.AsyncAnthropic().messages.stream(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
) as stream:
    async for chunk in guard.astream(stream.text_stream, gate="output"):
        print(chunk, end="", flush=True)
```

---

## Context Manager

`Guard` supports both sync and async context managers for automatic resource cleanup.

```python
# Sync - local mode
with Guard() as guard:
    result = guard.screen("Hello", gate="input")

# Sync - server mode
with Guard(base_url="http://localhost:8001") as guard:
    result = guard.screen("Hello", gate="input")
# HTTP client automatically closed

# Async - server mode
async with Guard(base_url="http://localhost:8001") as guard:
    result = await guard.ascreen("Hello", gate="input")
# HTTP client automatically closed
```

---

## Lifecycle

### warmup()

Eagerly load the local ML models so the first `screen()` call is fast. No-op in server mode. Call from your app's startup hook. On a cold cache this downloads the GLiNER, sentence-transformer, ONNX classifier, and (if grounding is enabled) NLI models.

```python
guard = Guard()
guard.warmup()          # sync; async: await guard.awarmup()
```

Raises `ImportError` if the `[local]` extras are not installed.

### close()

Close the underlying HTTP client. Called automatically when using the context manager. No-op in local mode.

```python
guard = Guard(base_url="http://localhost:8001")
try:
    result = guard.screen("Hello", gate="input")
finally:
    guard.close()
```

---

## Properties

### policy

```python
guard.policy  # → GuardExPolicy
```

Access the current policy configuration. Useful for inspecting enabled categories, PII settings, and other policy details.

```python
guard = Guard()
print(f"Blocked categories: {guard.policy.blocked_categories}")
print(f"PII action: {guard.policy.pii_action}")
```

---

## classify_min_confidence

The `classify_min_confidence` setting on the policy enables automatic false-positive tuning.

When `classify_min_confidence > 0.0` and a classification confidence falls below the threshold, that result is automatically overridden to `safe=True`, even if the classifier returned an unsafe category.

```python
from guardex import GuardExPolicy

policy = GuardExPolicy(
    blocked_categories=["S1", "S3"],
    classify_min_confidence=0.85,  # Override low-confidence detections
)

guard = Guard(policy=policy)
result = guard.screen("ambiguous text", gate="input")
# If classifier returns S1 with 0.70 confidence, result.safe overrides to True
```

---

## Gates

The `gate` parameter specifies where in the LLM pipeline the text is being screened:

| Gate | API Stage | Purpose | Direction |
|------|-----------|---------|-----------|
| `"input"` | `input` | Raw user prompt | Input |
| `"prompt"` | `prompt` | Assembled prompt (system + user + context) | Input |
| `"output"` | `output` | Full LLM response | Output |
| `"stream"` | `stream` | Streaming response chunks (use `guard.stream()`) | Output |
| `"tool_input"` | `tool_input` | Tool/function call arguments | Input |
| `"tool_output"` | `tool_output` | Tool/function return value | Output |
| `"retrieval_query"` | `retrieval_query` | Query sent to vector store | Input |
| `"retrieval_result"` | `retrieval_result` | Documents returned from retrieval | Output |

The gate name maps directly to the engine's stage parameter (identity mapping). The engine — the in-process runner in local mode, or the server in server mode — uses it to determine direction and select the appropriate checks for that stage.

```python
# Screen at different gates
guard.screen("user input", gate="input")           # User prompt
guard.screen("assembled prompt", gate="prompt")    # Full prompt
guard.screen("llm response", gate="output")        # LLM output
guard.screen("tool args", gate="tool_input")       # Function args
guard.screen("search query", gate="retrieval_query")  # RAG query
```

---

## Exceptions

| Exception | When | Key Attributes |
|-----------|------|----------------|
| `GuardExViolation` | Unsafe content detected | `stage`, `category`, `description` |
| `GuardExAPIError` | Server error (when `fail_open=False`) | `status_code`, `error_type`, `message`, `code` |

!!! note "PIIViolation"
    The `PIIViolation` subclass is raised only by the LangChain wrappers (`GuardedLLM`, `GuardExCallbackHandler`). With `pii_action="block"`, `Guard.screen_or_raise()` still blocks PII — it raises a `GuardExViolation` with `category="pii"`. To inspect entities without raising, use `screen()` and check `result.pii`.

```python
from guardex import GuardExViolation, GuardExAPIError

guard = Guard(base_url="http://localhost:8001")

try:
    result = guard.screen_or_raise("some text", gate="input")
except GuardExViolation as e:
    print(f"Content violation at {e.stage}: {e.category}")
except GuardExAPIError as e:
    print(f"Server error: {e.message} (code: {e.code})")
```

---

## Context-Aware Screening

Use `GuardExContext` to provide deployment, user, and organizational context for policy resolution.

```python
from guardex import Guard, GuardExContext, DeploymentContext, UserContext, Region, Industry

guard = Guard(base_url="http://localhost:8001")

# Define context
ctx = GuardExContext(
    deployment=DeploymentContext.PRODUCTION,
    user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE),
)

# Screen with context - policy may be adjusted based on context
result = guard.screen("patient data", gate="input", context=ctx)
```

See [Context-Aware Policy guide](../guides/context-aware-policy.md) for full details.

---

## Example Workflows

### Basic Safety Screening

```python
from guardex import Guard

guard = Guard()  # local mode; or Guard(base_url="http://localhost:8001") for server

# Screen user input
user_input = "Can you help me with..."
result = guard.screen(user_input, gate="input")

if result.blocked:
    print(f"Input blocked: {result.classify.category}")
elif result.safe:
    print("Input approved")
    # Process safe input
```

### LLM Output Protection

```python
from openai import OpenAI

guard = Guard()  # or Guard(base_url="http://localhost:8001")
client = OpenAI()

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}],
)

# Screen LLM response
result = guard.screen(response.choices[0].message.content, gate="output")
if result.blocked:
    print("LLM generated unsafe content")
else:
    print(result.text)  # Safe text (possibly PII-masked)
```

### Tool Integration

```python
def wikipedia_search(query: str) -> str:
    """Search Wikipedia."""
    # Actual implementation...
    return "Results..."

guard = Guard()  # or Guard(base_url="http://localhost:8001")

# Wrap the tool
safe_search = guard.wrap(wikipedia_search, gate="tool_input")

# Both input and output are screened
result = safe_search("user query")
```

### Streaming with Real-Time Protection

```python
from anthropic import Anthropic
from guardex import GuardExViolation

guard = Guard()  # or Guard(base_url="http://localhost:8001")
client = Anthropic()

try:
    with client.messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Tell me a story"}],
    ) as stream:
        for chunk in guard.stream(stream.text_stream, gate="output"):
            print(chunk, end="", flush=True)
except GuardExViolation as e:
    print(f"\nStream blocked: {e.category}")
```

### Batch Processing

```python
guard = Guard()  # or Guard(base_url="http://localhost:8001")

# Screen multiple comments at once
comments = [
    "Great product!",
    "Terrible service!",
    "Love it!",
]

results = guard.screen_batch(comments, gate="input")
for comment, result in zip(comments, results):
    action = result.action
    print(f"{comment}: {action}")
```

---

## Best Practices

!!! tip "Use context for dynamic policies"
    Provide `GuardExContext` to enable deployment-aware and user-aware policy resolution. This allows you to enforce stricter policies in production or sensitive regions.

!!! tip "Prefer screen_batch() for multiple texts"
    Screening multiple texts should use `screen_batch()` rather than calling `screen()` repeatedly. A single batch call is more efficient.

!!! tip "Handle streaming exceptions"
    When using `stream()` or `astream()`, wrap the iteration in a try-except to catch `GuardExViolation` exceptions that may occur mid-stream.

!!! tip "Use callbacks for observability"
    Register `on_block` and `on_screen` callbacks to build audit logs, metrics, and alerting without cluttering your application code.

!!! tip "Set classify_min_confidence for false-positive tuning"
    If you see false positives (legitimate content flagged as unsafe), increase `classify_min_confidence` on the policy to require higher confidence before blocking.
