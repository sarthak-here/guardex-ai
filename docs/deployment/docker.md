# Running GuardEx in Docker

This page is the canonical recipe for running `guardex` in a container. It
covers three deployment shapes:

1. **Minimal** - regex-only injection detection (no ML, ~50 MB image).
2. **Local ML** - in-process safety + PII + scope (default `Guard()`).
3. **With Ollama** - `cascade_mode="safety"` and full LlamaGuard escalation.

The configuration knobs that matter are `GUARDEX_*` environment variables and
two cache mounts. Mount both caches or your container will re-download
~250 MB of models on every restart.

---

## Shape 1 - minimal regex-only

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir guardex-ai   # core only, ~5 MB of deps
COPY app.py /app/app.py
CMD ["python", "/app/app.py"]
```

Use this when your app only needs `InjectionDetector` or HTTP-mode `Guard(base_url=...)`.

```python
from guardex import InjectionDetector
det = InjectionDetector()
print(det.scan("Ignore all prior instructions").detected)
```

---

## Shape 2 - full local ML (recommended)

`docker-compose.yml`:

```yaml
services:
  app:
    build: .
    environment:
      - GUARDEX_CACHE_DIR=/cache/guardex
      - HF_HOME=/cache/huggingface
      - HF_HUB_DISABLE_TELEMETRY=1
      # Grounding is off by default; set GUARDEX_GROUNDING_ENABLED=1 to load
      # the ~700 MB NLI model for hallucination detection
      # - GUARDEX_GROUNDING_ENABLED=1
      # Speed mode = ONNX-only safety, skips LlamaGuard escalation. Set to
      # "safety" only if Ollama is reachable (see Shape 3).
      - GUARDEX_CASCADE_MODE=speed
    volumes:
      - guardex-cache:/cache/guardex
      - huggingface-cache:/cache/huggingface

volumes:
  guardex-cache:
  huggingface-cache:
```

`Dockerfile`:

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir 'guardex-ai[local]'
COPY app.py /app/app.py
CMD ["python", "/app/app.py"]
```

Pre-warm the model cache at startup so the first request is fast:

```python
from guardex import Guard
guard = Guard()
guard.warmup()    # blocks until GLiNER + sentence-transformers + ONNX are loaded
```

Inspect what's in the cache with:

```python
from guardex import Guard
print(Guard.cache_info())
# {'guardex_cache': {...}, 'huggingface_hub': {...}, 'total_bytes': 287654321}
```

---

## Shape 3 - with Ollama for LlamaGuard escalation

Add an `ollama` service alongside your app. GuardEx auto-probes Ollama at
`Guard()` construction; if it's unreachable, `cascade_mode` is downgraded to
`"speed"` automatically and a single warning is logged. Setting
`GUARDEX_CASCADE_MODE` explicitly disables the auto-downgrade.

```yaml
services:
  app:
    build: .
    environment:
      - GUARDEX_CACHE_DIR=/cache/guardex
      - HF_HOME=/cache/huggingface
      - GUARDEX_OLLAMA_URL=http://ollama:11434
      - GUARDEX_OLLAMA_MODEL=llama-guard3:1b
      - GUARDEX_CASCADE_MODE=safety
    depends_on:
      ollama:
        condition: service_healthy
    volumes:
      - guardex-cache:/cache/guardex
      - huggingface-cache:/cache/huggingface

  ollama:
    image: ollama/ollama:latest
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:11434/api/tags"]
      interval: 5s
      timeout: 2s
      retries: 30
    volumes:
      - ollama-cache:/root/.ollama
    # Pull the LlamaGuard model on first start
    entrypoint: >
      bash -c "ollama serve &
               sleep 2 &&
               ollama pull llama-guard3:1b &&
               wait"

volumes:
  guardex-cache:
  huggingface-cache:
  ollama-cache:
```

---

## Environment variable reference

| Variable                          | Purpose                                                | Default                     |
|-----------------------------------|--------------------------------------------------------|-----------------------------|
| `GUARDEX_CACHE_DIR`               | GuardEx-managed cache root                             | `~/.cache/guardex`          |
| `HF_HOME`                         | Hugging Face cache root (snapshot models live here)    | `~/.cache/huggingface`      |
| `GUARDEX_CASCADE_MODE`            | `"safety"` or `"speed"`                                | `"safety"` *(auto-downgrades to `"speed"` if Ollama unreachable)* |
| `GUARDEX_OLLAMA_URL`              | LlamaGuard endpoint                                    | `http://localhost:11434`    |
| `GUARDEX_OLLAMA_MODEL`            | LlamaGuard model tag                                   | `llama-guard3:1b`           |
| `GUARDEX_ONNX_MODEL_PATH`         | Local ONNX classifier `.onnx` file (skips HF download) | *(auto-download)*           |
| `GUARDEX_ONNX_TOKENIZER_PATH`     | Local ONNX tokenizer dir                               | *(auto-download)*           |
| `GUARDEX_GROUNDING_ENABLED`       | Load the NLI grounding model                           | `false`                     |
| `GUARDEX_TOPIC_SCOPE_ENABLED`     | Load the sentence-transformer scope engine             | `true`                      |
| `HF_HUB_DISABLE_TELEMETRY`        | Quiet down HF telemetry pings                          | unset                       |

---

## Cache layout (what to mount)

GuardEx writes to **two** independent locations. Mount both or you'll see
re-downloads on every container recreate.

```
/cache/guardex/                          ← GUARDEX_CACHE_DIR
├── topic_scope/                         (compiled scope artifacts)
└── ...

/cache/huggingface/                      ← HF_HOME
└── hub/
    ├── models--AtliQ-Technologies--toxicity-fast-onnx/    (~100 MB, ONNX safety classifier)
    ├── models--nvidia--gliner-pii/      (~150 MB)
    ├── models--sentence-transformers--all-MiniLM-L6-v2/   (~90 MB)
    └── models--cross-encoder--nli-deberta-v3-base/        (~700 MB, only if grounding_enabled)
```
