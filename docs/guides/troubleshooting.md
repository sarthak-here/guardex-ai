# Troubleshooting & FAQ

Common issues and solutions when using the GuardEx SDK.

---

## Common Errors

### "Connection error" when no `base_url` configured

```
httpx.ConnectError: [Errno 111] Connection refused
```

**Cause:** The SDK could not connect to your GuardEx server. Either the server is not running or `base_url` was not specified.

**Fix:**

```python
# Option 1: Pass base_url directly
guard = Guard(base_url="http://localhost:8001")

# Option 2: Set environment variable
import os
os.environ["GUARDEX_BASE_URL"] = "http://localhost:8001"
guard = Guard()

# Option 3: Export in your shell before running your script
# export GUARDEX_BASE_URL=http://localhost:8001
```

!!! tip "Make sure the server is running"
    Before using the SDK in server mode, start your local GuardEx server (or install `guardex-ai[local]` and use in-process mode instead).

    ```bash
    pip install guardex-ai[local]
    # Run your server however you've packaged it (e.g. uvicorn against your app)
    # uvicorn your_app.server:app --host 0.0.0.0 --port 8001
    ```

    Verify it's up: `curl http://localhost:8001/v1/health`

---

### "422 Unprocessable Entity - Validation error"

```
guardex.exceptions.GuardExAPIError: [422] validation_error: ...
```

**Cause:** The request payload was malformed or missing required fields.

**Fix:**
- Verify you are passing valid `gate` values (e.g., `"input"`, `"output"`)
- Check that your `GuardExPolicy` fields are correct
- Ensure text input is a non-empty string

!!! danger "422 errors always raise"
    Validation errors are never retried and never silenced by `fail_open=True`. They always raise `GuardExAPIError`.

---

### "429 Too Many Requests - Rate limit exceeded"

```
httpx.HTTPStatusError: Client error '429 Too Many Requests'
```

**Cause:** Your self-hosted server has rate limiting configured and you've exceeded the limit.

**Fix:**
- The SDK automatically retries 429 errors up to 2 times, honoring the `Retry-After` header when present and falling back to exponential backoff otherwise (configurable via `max_retries` on `GuardExClient`)
- Add spacing between requests in batch operations
- Adjust your server's rate limit configuration if needed
- Use `fail_open=True` if you prefer to pass through on rate limits (not recommended for production)

---

### "Connection refused" or "Connect error"

```
httpx.ConnectError: [Errno 111] Connection refused
```

**Cause:** The GuardEx server is unreachable.

**Fix:**
- Verify your server is running: `curl http://localhost:8001/v1/health`
- Verify your `base_url` is correct (default: `http://localhost:8001`)
- Check if a firewall is blocking the server address
- Ensure `guardex-ai[local]` is installed, or that your GuardEx server is running on the expected port

**Behavior with `fail_open`:**
- `fail_open=False` (default): Raises the connection error after retries
- `fail_open=True`: Logs a warning and treats the result as safe

---

### "GuardEx blocked at gate=input"

```
guardex.exceptions.GuardExViolation: GuardEx blocked at gate=input, category=S9, (Indiscriminate Weapons)
```

**Cause:** The content was classified as unsafe by LlamaGuard 3. This is expected behavior - your guardrails are working.

**Fix:** This is not an error to fix - it's a safety block. Handle it in your code:

```python
from guardex import Guard, GuardExViolation

guard = Guard()

try:
    safe_text = guard.screen_or_raise(user_input, gate="input")
except GuardExViolation as e:
    # Return a safe message to the user
    print(f"I can't help with that. (category: {e.category})")
```

If you want to inspect without raising, use `screen()` instead:

```python
result = guard.screen(user_input, gate="input")
if result.blocked:
    print(f"Blocked: {result.classify.category}")
else:
    print(f"Safe: {result.text}")
```

---

### Timeout errors

```
httpx.ReadTimeout: timed out
```

**Cause:** The API request took longer than the configured timeout (default: 30 seconds for read, 5 seconds for connect).

**Fix:**
- The default 30-second timeout is generous for most use cases
- For batch processing, you may want a longer timeout:

```python
from guardex import Guard, GuardExPolicy

guard = Guard(policy=GuardExPolicy(timeout=60))  # 60 second read timeout
```

- For interactive chatbots, consider a shorter timeout with `fail_open=True`:

```python
guard = Guard(
    policy=GuardExPolicy(timeout=10),
    fail_open=True,  # don't block the user on timeout
)
```

---

## FAQ

### Which method should I use: `screen()` or `screen_or_raise()`?

| Use case | Method | Why |
|----------|--------|-----|
| **Simple chatbot** | `screen_or_raise()` | Raises on unsafe, returns clean text. Wrap in try/except. |
| **Need to inspect the result** | `screen()` | Returns `ScreenResult` with details - you decide what to do. |
| **Checking PII with `pii_action="block"`** | `screen()` | `screen_or_raise()` does not raise `PIIViolation`. Check `result.pii.has_pii`. |
| **Logging/analytics** | `screen()` | Access `result.latency_ms`, `result.classify.category`, etc. |

**Rule of thumb:** Start with `screen_or_raise()`. Switch to `screen()` when you need more control.

```python
# Simple - raises on unsafe, returns safe/masked text
safe_text = guard.screen_or_raise(user_input, gate="input")

# Detailed - inspect the full result
result = guard.screen(user_input, gate="input")
if result.blocked:
    handle_blocked(result)
elif result.pii.has_pii:
    handle_pii(result)
else:
    use_text(result.text)
```

---

### Do I need all 8 gates?

**No.** For most applications, you only need `input` and `output`:

```python
# This is sufficient for a simple chatbot
safe_input = guard.screen_or_raise(user_message, gate="input")
response = call_your_llm(safe_input)
safe_output = guard.screen_or_raise(response, gate="output")
```

Use additional gates only when your architecture needs them:

| Your architecture | Gates to use |
|-------------------|-------------|
| Simple chatbot | `input`, `output` |
| Chatbot with streaming | `input`, `output` (via `guard.stream()`) |
| Agent with tool calls | `input`, `output`, `tool_input`, `tool_output` |
| RAG pipeline | `input`, `output`, `retrieval_query`, `retrieval_result` |
| Complex agent + RAG | All 8 as needed |

---

### What is the difference between `gate` and `stage`?

- **`gate`** is what you use with the `Guard` class. It has 8 values: `input`, `output`, `prompt`, `stream`, `tool_input`, `tool_output`, `retrieval_query`, `retrieval_result`.
- **`stage`** is what you use with the low-level `GuardExClient`. It maps to what the server accepts.

The `Guard` class translates gates to stages automatically. You never need to think about stages unless you use `GuardExClient` directly.

```python
# Guard class - use gate=
guard.screen("text", gate="input")

# GuardExClient - use stage=
client.screen("text", stage="input")
```

---

### What does `result.safe = True` mean when `result.pii.has_pii = True`?

This is normal. `safe` means the content was not **blocked** - it was successfully processed. When PII is found and `pii_action="mask"` (the default):

- `result.safe` → `True` (content passed through after masking)
- `result.action` → `"mask"` (PII was replaced with placeholders)
- `result.pii.has_pii` → `True` (PII was detected)
- `result.text` → The masked text (e.g., `"My email is [EMAIL]"`)

The LLM never sees the real PII. The text in `result.text` is safe to use.

---

### How fast is the API?

The SDK uses HTTP/2 multiplexing with persistent connection pooling. Typical latency depends on the operation:

| Operation | What it does | Relative speed |
|-----------|-------------|----------------|
| `guard.classify()` | Safety check only | Fastest |
| `guard.pii_scan()` | PII detection only | Fast |
| `guard.screen()` | Safety + PII combined | One round-trip (recommended) |
| `guard.pii_mask()` | PII detection + masking | Fast |

**Recommendation:** Use `guard.screen()` for most cases - it combines safety classification and PII detection in a **single API call**, which is faster than calling `classify()` and `pii_scan()` separately.

Check latency on any call:

```python
result = guard.screen("text", gate="input")
print(f"Latency: {result.latency_ms:.1f}ms")
```

### Timeout recommendations

| Use case | Suggested timeout |
|----------|------------------|
| Interactive chatbot | `10-15` seconds |
| API endpoint | `10-30` seconds (default) |
| Batch processing | `60` seconds |
| CI/CD testing | `30` seconds (default) |

---

### How does retry work?

The SDK automatically retries on transient errors:

- **Retried:** 429 (rate limit), 5xx (server errors), network errors
- **Never retried:** 401 (auth), 403 (forbidden), 422 (validation)
- **Default retries:** 2 attempts after the initial request (3 total)
- **Retry timing:** Exponential backoff (0.5 × 2^n seconds); respects `Retry-After` header on 429s

```python
from guardex import GuardExClient

# Custom retry config (only available on GuardExClient)
client = GuardExClient(max_retries=3, timeout=15)
```

---

### Where is the dashboard?

GuardEx ships with an optional self-hosted Flask-based telemetry dashboard. Install and launch it with the `dashboard` extras:

```bash
pip install guardex-ai[dashboard]
guardex-dashboard
```

This starts the dashboard at `http://localhost:7865` by default. The dashboard is a **read-only trace viewer**:

- **Traces** - Inspect individual screening calls and their gate decisions
- **Stats** - Screening volume, block rates, latency
- **Info** - Runtime and configuration details

Policy is configured in code via `GuardExPolicy` - the dashboard does not edit policy.

---

### Does `PIIViolation` get raised by `Guard`?

**No.** `PIIViolation` is only raised by the LangChain wrappers (`GuardedLLM`, `GuardExCallbackHandler`).

If you use the `Guard` class (recommended), PII blocking works like this:

```python
guard = Guard(policy=GuardExPolicy(pii_action="block"))

result = guard.screen("My SSN is 123-45-6789", gate="input")
# result.blocked → True (because pii_action="block" and PII was found)
# result.pii.has_pii → True

# screen_or_raise() raises GuardExViolation (not PIIViolation) when blocked
try:
    text = guard.screen_or_raise("My SSN is 123-45-6789", gate="input")
except GuardExViolation as e:
    print(f"Blocked at {e.stage}")  # not PIIViolation
```

---

### What happens when the server is down?

Depends on your `fail_open` setting:

| `fail_open` | Behavior on server error | Use for |
|-------------|----------------------|---------|
| `False` (default) | Raises exception - request is blocked | Production (ensures all content is screened) |
| `True` | Logs warning, treats result as safe | Development, or when availability > safety |

```python
# Production: fail-closed (default)
guard = Guard()  # fail_open=False

# Development: fail-open
guard = Guard(fail_open=True)
```

**Important:** Validation errors (422) **always** raise regardless of `fail_open`.
