# User Guide

Practical guides for building safe LLM applications with GuardEx. Start with the basics, then explore advanced features as needed.

---

## Getting Started

| Guide | What you'll learn |
|-------|-------------------|
| [Integration Patterns](integration-patterns.md) | How to add GuardEx to any LLM framework (OpenAI, Anthropic, LangChain, etc.) |
| [Error Handling](error-handling.md) | The 3 exception types, fail-open mode, retry behavior |
| [Configuration](configuration.md) | GuardExPolicy fields, YAML config, and environment variables |

## Safety & PII

| Guide | What you'll learn |
|-------|-------------------|
| [Safety Categories](safety-categories.md) | The 14 content safety categories (S1-S14), choosing which to block |
| [PII Detection](pii-detection.md) | 31 PII entity types, mask vs. block, threshold tuning |
| [PII Vault](pii-vault.md) | Reversible PII tokenization for LLM round-trips |

## Advanced Security

| Guide | What you'll learn |
|-------|-------------------|
| [Injection Detection](injection-detection.md) | Two-layer prompt injection defense (client regex + server ML) |
| [Context-Aware Policy](context-aware-policy.md) | Per-request policy based on deployment, region, industry, role |
| [Multi-Turn Conversations](multi-turn.md) | Detecting incremental escalation across conversation turns |

## Operations

| Guide | What you'll learn |
|-------|-------------------|
| [Observability](observability.md) | OpenTelemetry spans, audit logging, callbacks |
| [Testing & CI/CD](testing.md) | Mocking GuardEx in tests, CI patterns |
| [Recipes & Examples](examples.md) | Copy-paste examples for 15+ frameworks and patterns |

## Choosing an interface

| Guide | What you'll learn |
|-------|-------------------|
| [Choosing Your Setup](migration.md) | Guard vs GuardedLLM vs LlamaGuardClassifier |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |
