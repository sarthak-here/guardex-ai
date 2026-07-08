# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in GuardEx, please report it responsibly:

1. **Email**: Send a detailed report to **developer@atliq.com**
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)
3. **Response timeline**:
   - **Acknowledgment**: Within 48 hours
   - **Initial assessment**: Within 5 business days
   - **Fix timeline**: Critical vulnerabilities patched within 7 days

## Threat Model

GuardEx is an AI safety guardrails SDK. Our threat model covers:

- **Prompt injection attacks** against the screening pipeline
- **PII leakage** through logs, responses, or error messages
- **Model supply chain** - models are downloaded from Hugging Face on first use
- **Adversarial evasion** of content classifiers (encoding, homoglyphs, etc.)

## Known Limitations

GuardEx openly acknowledges these undefended attack classes:

- GCG adversarial suffix attacks (industry-wide unsolved)
- Many-shot jailbreaking via long context
- Cross-lingual attacks (English-only patterns)
- Adaptive adversaries with knowledge of the screening pipeline

## Security Best Practices for Deployment

GuardEx ships the SDK only - there is no bundled server. SDK-side hardening:

1. **Never commit `.env` files** - use environment variables or a secrets manager
2. **Keep `fail_open=False`** (the default) in production so screening errors block rather than pass
3. **Enable audit logging** (`audit_logging=True`) for compliance
4. **Local mode runs fully in-process** - models download from Hugging Face on first use, then no text leaves your process; mount a verified model cache in containers
5. **If you point the SDK at your own server**, use HTTPS and manage that server's credentials according to its own security guidance

## Dependency Security

We use range-pinned dependencies and recommend running `pip-audit` regularly against your installed environment:

```bash
pip install pip-audit
pip-audit
```
