# Provider Behavior & Fallback Routing

Eva provides an abstraction layer over multiple LLM providers, enabling automatic fallback routing, local rate-limit tracking, response streaming, and disk caching.

---

## Supported Providers

| Provider | Type | API Key Env Var | Keyring Provider Name |
| --- | --- | --- | --- |
| **Groq** | Cloud API | `EVA_GROQ_API_KEY` | `groq` |
| **OpenRouter** | Cloud API | `EVA_OPENROUTER_API_KEY` | `openrouter` |
| **Gemini** | Cloud API | `EVA_GEMINI_API_KEY` | `gemini` |
| **OpenCode Zen** | Cloud API | `EVA_OPENCODE_ZEN_API_KEY` | `opencode_zen` |
| **Ollama** | Local Offline | N/A | `ollama` |
| **llama.cpp** | Local GGUF | N/A | `llamacpp` |

Custom providers can also be registered via the [Plugin System](plugins.md).

---

## Fallback Routing Strategy

When a user initiates an AI request (e.g. `eva ask` or `eva work`):

1. **Primary Provider Execution**: Eva attempts the request using the primary provider configured via `eva use <provider>`.
2. **Graceful Fallback**: If the primary provider fails due to network outage, invalid API key, or quota exhaustion (429 Rate Limit / 403 Auth Error), Eva logs a diagnostic warning and routes the prompt to the next provider in `fallback_order`.
3. **Transparent Failure Summaries**: If all providers in the fallback list fail, Eva presents a consolidated error report summarizing the exact failure reason for each provider.

---

## Local Budget & Rate Limit Tracking

Free-tier LLM providers impose strict Requests Per Minute (RPM) and Requests Per Day (RPD) limits. To avoid hitting remote 429 rate limit exceptions:

- Eva tracks local request counters in `~/.cache/eva/usage.json`.
- `eva usage` displays real-time RPM and RPD estimates for configured providers.
- When a provider approaches 95% of its free-tier RPM limit, Eva automatically shifts non-critical queries to the next fallback provider.

---

## Disk-Backed Response Caching

To conserve provider quota and minimize latency, Eva caches deterministic responses based on SHA-256 digests of the input prompt, file context, and model parameters:

- Caches are stored at `~/.cache/eva/response_cache/`.
- Cache keys include the model name to prevent stale responses when switching models.
- Identical queries return cached results instantaneously.
- Clear cached responses anytime with `eva cache clear`.
- Bypass the cache with `eva ask --no-cache`.

---

## Offline Tokenization

Eva uses `tiktoken` (BPE tokenizer) for accurate token counting and context trimming. In restricted-network or air-gapped environments:

- If `tiktoken` cannot download the BPE vocabulary (`cl100k_base.tiktoken`), Eva falls back to a `len(text) // 4` character-based approximation.
- A single `WARNING` log is emitted; subsequent calls are silent.
- For fully offline deployments, pre-download the vocabulary and set `EVA_TIKTOKEN_ENCODING_PATH` or `tiktoken_encoding_path` in `config.toml`.
