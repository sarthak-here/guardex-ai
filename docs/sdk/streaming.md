# SDK Reference: Streaming

`guardex.StreamGuard` and `guardex.AsyncStreamGuard` - Buffer and screen streaming text chunks.

!!! tip "Prefer guard.stream()"
    In most cases, use `guard.stream()` or `guard.astream()` instead of creating `StreamGuard` instances directly. The `Guard` methods handle setup for you.

---

## Import

```python
from guardex import StreamGuard, AsyncStreamGuard
```

---

## StreamGuard (Sync)

Buffers streaming text chunks and screens at sentence boundaries or when the buffer exceeds a threshold.

### How It Works

1. Chunks are accumulated in an internal buffer
2. The buffer is screened when it reaches `flush_every` characters, or once it passes 50 characters and hits a content boundary (sentence end, paragraph break, closing code block)
3. If the result is `safe`, the screened text is yielded
4. On input gates, detected PII is masked in the yielded text. On output gates PII is **not** masked by default — pass `mask_output_pii=True` to `guard.stream()` to mask it
5. If unsafe content is detected, `GuardExViolation` is raised immediately (terminates the stream)

!!! warning "Output PII is not masked by default"
    Streaming an `gate="output"` response screens for safety but does not
    mask PII, so personal data an LLM emits streams through unchanged. Pass
    `mask_output_pii=True` to mask it, or screen the full response with
    `guard.screen(text, gate="output")` after streaming.

Injection detection (input gates), custom safety routes, and topic scope
apply to streaming the same way they apply to `guard.screen()`. These run
on each flushed buffer, so a pattern that straddles a flush boundary is
evaluated in parts — screen the full text with `guard.screen()` when you
need whole-message guarantees.

### Usage via Guard

```python
from guardex import Guard

guard = Guard()

def llm_chunks():
    yield "Hello, "
    yield "world! "
    yield "This is "
    yield "a streaming response."

for chunk in guard.stream(llm_chunks(), gate="output", flush_every=256):
    print(chunk, end="", flush=True)
```

### Direct Usage

```python
from guardex import StreamGuard, GuardExClient, GuardExPolicy

client = GuardExClient(base_url="http://localhost:8001")
policy = GuardExPolicy()
stream_guard = StreamGuard(client=client, policy=policy, gate="output", flush_every=256)

for chunk in stream_guard.run(llm_chunks()):
    print(chunk, end="", flush=True)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `client` | `GuardExClient` | (required) | HTTP client for API calls |
| `policy` | `GuardExPolicy` | (required) | Policy configuration for screening behavior |
| `gate` | `Gate` | `"output"` | Gate position for screening |
| `flush_every` | `int` | `256` | Max buffer size before forced flush |
| `vault` | `PIIVault \| None` | `None` | Vault used to restore `{{pii:...}}` tokens emitted by the upstream LLM |
| `restore_mode` | `"off" \| "buffered" \| "stream-safe"` | `"off"` | Vault token restoration mode; forced to `"off"` when no `vault` is given. `"buffered"` accumulates the whole stream then restores (correctness-first); `"stream-safe"` yields the longest prefix with no open `{{pii:` token |
| `mask_output_pii` | `bool` | `False` | Mask detected PII on output gates too. Off by default so LLM-generated names are not rewritten as real personal data |

---

## AsyncStreamGuard (Async)

Async version of `StreamGuard` for use with async generators and `async for`.

### Usage via Guard

```python
from guardex import Guard

guard = Guard()

async def llm_chunks():
    yield "Hello, "
    yield "world!"

async for chunk in guard.astream(llm_chunks(), gate="output"):
    print(chunk, end="", flush=True)
```

### Direct Usage

```python
from guardex import AsyncStreamGuard, AsyncGuardExClient, GuardExPolicy

client = AsyncGuardExClient(base_url="http://localhost:8001")
policy = GuardExPolicy()
stream_guard = AsyncStreamGuard(client=client, policy=policy, gate="output", flush_every=256)

async for chunk in stream_guard.run(async_llm_chunks()):
    print(chunk, end="", flush=True)
```

---

## Buffering Strategy

The streaming guard flushes on size or on a content boundary once the buffer clears a 50-character minimum:

```
Buffer fills to: "Hi, my name is John and my email is john@acme.com. "
                 ← 51 chars, ends on a sentence boundary → flush
                 → Screen the buffer
                 → gate="input":  yield "Hi, my name is [NAME] and my email is [EMAIL]. "
                 → gate="output": yield the text unchanged (unless mask_output_pii=True)
Remaining buffer flushes when the stream ends.
```

- Content boundaries are `.`, `!`, `?` followed by whitespace, paragraph breaks (`\n\n`), and closing code blocks (`` ``` ``)
- Boundary flushing only starts after the buffer exceeds 50 characters; below that the buffer keeps accumulating
- The buffer is flushed unconditionally once it reaches `flush_every` characters (default 256)
- On stream end, any remaining buffer is flushed

---

## Error Behavior

- **Unsafe content detected:** `GuardExViolation` is raised immediately, terminating the stream
- **PII detected (mask):** Masked text is yielded on input gates (and on output gates when `mask_output_pii=True`); the stream continues
- **PII detected (block):** The chunk is blocked - downstream consumers should check the result. (The LangChain wrappers raise `PIIViolation`; `Guard.stream()` does not.)
- **API error + fail_open=True:** Original text is yielded
- **API error + fail_open=False:** `GuardExAPIError` is raised
