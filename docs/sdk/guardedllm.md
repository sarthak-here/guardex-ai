# SDK Reference: GuardedLLM

`guardex.GuardedLLM` - A LangChain integration wrapper that adds PII detection and safety rails to any LangChain `BaseChatModel`. Internally, it uses a [`Guard`](guard.md) instance to screen inputs and outputs.

!!! note "Requires LangChain extras"
    Install with `pip install guardex-ai[langchain]`.

---

## Import

```python
# Requires: pip install guardex-ai[langchain]
from guardex import GuardedLLM
```

---

## Constructor

```python
GuardedLLM(
    llm: BaseChatModel,
    api_key: str | None = None,
    policy: GuardExPolicy | None = None,
    guard: Guard | None = None,
    debug: bool = False,
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `llm` | `BaseChatModel` | (required) | The underlying LangChain chat model |
| `api_key` | `str \| None` | `None` | API key for a hosted server. With no key and no `base_url` configured, screening runs in local in-process mode. |
| `policy` | `GuardExPolicy \| None` | `None` | Configuration object. Set `policy=GuardExPolicy(base_url=...)` to point at a server. |
| `guard` | `Guard \| None` | `None` | Pre-configured `Guard` instance. If provided, `api_key` and `policy` are ignored and this guard is used directly. |
| `debug` | `bool` | `False` | Print effective config on first call. |

There is no `base_url` constructor parameter. To use a server, pass `policy=GuardExPolicy(base_url=...)` or `guard=Guard(base_url=...)`.

### Example

```python
from guardex import GuardedLLM, GuardExPolicy
from langchain_openai import ChatOpenAI

llm = GuardedLLM(ChatOpenAI(model="gpt-4o-mini"))
response = llm.invoke("Tell me a joke")
```

With a pre-configured `Guard`:

```python
from guardex import Guard, GuardedLLM
from langchain_openai import ChatOpenAI

guard = Guard(base_url="http://localhost:8001")
llm = GuardedLLM(ChatOpenAI(model="gpt-4o-mini"), guard=guard)
response = llm.invoke("Tell me a joke")
```

---

## Pipeline Details

Every call to `invoke()` runs a 3-stage pipeline:

```
[1] screen(input)   →  PII detection + safety classification
[2] LLM call         →  Uses masked text if PII was masked
[3] screen(output)  →  PII detection + safety classification
```

---

## Exceptions

| Exception | When |
|-----------|------|
| `GuardExViolation` | Unsafe content detected |
| `PIIViolation` | PII detected with `pii_action='block'` |
| `GuardExAPIError` | Server error (when `fail_open=False`) |
