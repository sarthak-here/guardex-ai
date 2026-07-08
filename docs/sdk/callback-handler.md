# SDK Reference: GuardExCallbackHandler

`guardex.GuardExCallbackHandler` - LangChain callback handler that screens LLM inputs and outputs through a `Guard` instance. It works in zero-config local mode and includes injection detection and safety routes.

---

## Import

```python
# Requires: pip install guardex-ai[langchain]
from guardex import GuardExCallbackHandler
```

---

## Constructor

```python
GuardExCallbackHandler(
    api_key: str | None = None,
    policy: GuardExPolicy | None = None,
    debug: bool = False,
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_key` | `str \| None` | `None` | API key for a hosted server. With no key and no `base_url` configured, screening runs in local in-process mode. |
| `policy` | `GuardExPolicy \| None` | `None` | Configuration object. Set `policy=GuardExPolicy(base_url=...)` to point at a server. |
| `debug` | `bool` | `False` | Print effective config on first call. |

There is no `base_url` constructor parameter. To use a server, pass `policy=GuardExPolicy(base_url=...)`.

### Example

```python
from guardex import GuardExCallbackHandler, GuardExPolicy
from langchain_openai import ChatOpenAI

# Zero-config: runs in local in-process mode
handler = GuardExCallbackHandler()
llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[handler])
response = llm.invoke("Hello!")

# Server mode
handler = GuardExCallbackHandler(
    policy=GuardExPolicy(base_url="http://localhost:8001")
)
```

---

## Using Guard Instead

For framework-agnostic screening, you can use `Guard` directly:

```python
# Callback approach (LangChain-specific)
from guardex import GuardExCallbackHandler
handler = GuardExCallbackHandler()
llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[handler])
response = llm.invoke("Hello!")

# Guard approach (works with any LLM framework)
from guardex import Guard
guard = Guard()
safe_input = guard.screen_or_raise("Hello!", gate="input")
response = llm.invoke(safe_input)
safe_output = guard.screen_or_raise(response.content, gate="output")
```

---

## PII Limitation

!!! warning "Important limitation"
    The callback handler fires **after** LangChain has built the prompt, so it cannot rewrite input text.

| PII Action | Input Behavior | Output Behavior |
|-----------|----------------|-----------------|
| `mask` | Cannot mask (logs warning) | Full masking works |
| `block` | Raises `PIIViolation` | Raises `PIIViolation` |

If you need **input PII masking**, use [`Guard`](guard.md) instead.

---

## Exceptions

| Exception | When |
|-----------|------|
| `GuardExViolation` | Unsafe content detected |
| `PIIViolation` | PII detected with `pii_action='block'` |
