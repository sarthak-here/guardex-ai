# Choosing Your Setup

GuardEx offers two main interfaces. Pick the one that fits your stack.

## Guard (Recommended)

Framework-agnostic. Works with any Python code.

```python
from guardex import Guard

guard = Guard()  # local in-process mode; pass base_url= to use a server
result = guard.screen("Check this text for safety issues", gate="input")

if result.blocked:
    print(f"Blocked: {result.classify.category}")
```

`Guard` supports PII detection, prompt-injection defense, and streaming out of the box.

## GuardedLLM (LangChain Wrapper)

Drop-in `BaseChatModel` replacement for LangChain pipelines. Wraps any LangChain chat model with GuardEx screening.

```python
from langchain_openai import ChatOpenAI
from guardex import GuardedLLM

llm = GuardedLLM(
    ChatOpenAI(model="gpt-4o-mini"),
    base_url="http://localhost:8001",
)
response = llm.invoke("Summarize this document")
```

Use `GuardedLLM` only if you need LangChain chain compatibility. For everything else, use `Guard`.

## LlamaGuardClassifier (LlamaGuard-compatible interface)

If your code calls LlamaGuard directly, GuardEx exposes the same interface so you can switch with minimal changes:

```python
from guardex import LlamaGuardClassifier
from guardex import GuardExPolicy

classifier = LlamaGuardClassifier(
    policy=GuardExPolicy(base_url="http://localhost:8001"),
)
result = classifier.classify(messages)
```

`LlamaGuardClassifier` talks to a GuardEx server, so it needs `base_url=` (or an API key). In local in-process mode use `Guard().classify(...)` instead. Prefer `Guard.screen()` unless you need the LlamaGuard-compatible interface.

## Future Upgrades

Breaking changes between releases will be documented in the project changelog.
