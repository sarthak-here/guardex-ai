# SDK Reference

Complete API reference for every class, method, and type in the `guardex` package.

---

## Which class should I use?

```
Do you want to screen text for safety + PII?
  └─ Yes → Guard (recommended for most users)

Do you need direct HTTP access to the API?
  └─ Yes → GuardExClient / AsyncGuardExClient

Do you need reversible PII tokenization?
  └─ Yes → PIIVault

Do you need client-side injection detection?
  └─ Yes → InjectionDetector

Do you need multi-turn escalation detection?
  └─ Yes → ConversationGuard

Do you need to configure policies?
  └─ Yes → GuardExPolicy
```

---

## Core Classes

| Class | Module | Description |
|-------|--------|-------------|
| [Guard](guard.md) | `guardex` | Primary interface - `screen()`, `stream()`, `wrap()`, `screen_batch()` |
| [GuardExClient](client.md) | `guardex` | Low-level sync HTTP client with retry, backoff, batch |
| [AsyncGuardExClient](client.md) | `guardex` | Async version of GuardExClient |
| [StreamGuard](streaming.md) | `guardex` | Buffer and screen streaming chunks at content boundaries |

## Configuration

| Class | Module | Description |
|-------|--------|-------------|
| [GuardExPolicy](policy.md) | `guardex` | All configuration fields (17+ options) |
| [TopicScope](policy.md) | `guardex` | Topic restriction configuration |

## Security

| Class | Module | Description |
|-------|--------|-------------|
| [InjectionDetector](injection.md) | `guardex` | 25+ regex patterns for prompt injection detection |
| [PIIVault](pii-vault.md) | `guardex` | Reversible PII tokenization with de-masking |
| [ConversationGuard](conversation-guard.md) | `guardex` | Multi-turn sliding window screening |

## Types

| Type | Description |
|------|-------------|
| [ScreenResult](types.md) | Complete screening result (safety + PII + scope) |
| [ClassifyResult](types.md) | Safety classification only |
| [PIIResult](types.md) | PII detection result |
| [PIIEntity](types.md) | Single PII entity with span offsets |
| [ScopeResult](types.md) | Topic scope check result |
| [GroundingResult](types.md) | Grounding/hallucination check result |
| [SentenceGroundingResult](types.md) | Per-sentence grounding verdict |
| [InjectionResult](injection.md) | Injection scan result |
| [InjectionMatch](injection.md) | Single matched injection pattern |
| [Turn](conversation-guard.md) | Single conversation turn |

## Exceptions

| Exception | When raised |
|-----------|-------------|
| `GuardExViolation` | Unsafe content detected by `screen_or_raise()` |
| `PIIViolation` | PII detected when `pii_action="block"` (raised by `GuardedLLM`, `CallbackHandler`; `Guard.screen()` returns a `ScreenResult` instead - check `result.pii.has_pii`) |
| `GuardExAPIError` | HTTP error from the GuardEx API |

## LangChain integration

| Class | Note |
|-------|------|
| [GuardedLLM](guardedllm.md) | LangChain convenience wrapper; use `Guard` directly outside LangChain |
| [GuardExCallbackHandler](callback-handler.md) | LangChain callback; use `Guard` with `on_block`/`on_screen` outside LangChain |
