# Contributing to Eva CLI

Thank you for your interest in contributing to Eva! This document provides guidelines and ideas for contribution.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/eva-cli.git
cd eva-cli

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install in editable mode with dev dependencies
python -m pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
```

## Code Style

- We use [Ruff](https://docs.astral.sh/ruff/) for linting with a line length of 120 characters.
- Target Python 3.10+.
- Type hints are encouraged for all public functions.
- Use docstrings for public modules, classes, and functions.

## Project Structure

```
src/eva/
├── cli.py              # Typer command definitions
├── chat_session.py     # Chat REPL session logic
├── git_ops.py          # Git diff/apply/commit operations
├── config.py           # Configuration and keyring management
├── budget.py           # Local RPM/RPD budget tracking
├── cache.py            # Disk-backed response cache
├── diagnostics.py      # Logging setup
├── work_safety.py      # Command safety validation
├── context/            # File reading, trees, tokenizer
├── prompts/            # System prompt definitions
├── router/             # Provider dispatch and fallback
│   ├── __init__.py     # Registry, dispatch, error types
│   ├── openai_compat.py # Base class for OpenAI-compatible providers
│   ├── openrouter_provider.py
│   ├── groq_provider.py
│   ├── gemini_provider.py
│   └── opencode_zen_provider.py
└── ui/                 # Terminal output, streaming, formatting
```

## Making Changes

1. Fork the repository and create a feature branch.
2. Make your changes with clear, descriptive commit messages.
3. Add tests for new functionality where applicable.
4. Run `ruff check .` and `pytest` before submitting.
5. Open a pull request with a clear description of what changed and why.

## Areas for Contribution

### 🟢 Good First Issues

- Add shell completion documentation and setup instructions.
- Improve error messages for common misconfiguration scenarios.
- Add more file type detection in `context/io.py`.

### 🟡 Medium Difficulty

- **Local Model Support (Ollama / llama.cpp / vLLM):** Add a new provider that connects to a local LLM server. This would allow fully offline usage. The provider should implement the `Provider` protocol from `eva/router/__init__.py` and register itself. Ollama exposes an OpenAI-compatible API, so subclassing `OpenAICompatibleProvider` from `eva/router/openai_compat.py` would be the easiest approach.
- **`eva review` Command:** Implement a multi-file code review command that collects context from multiple files and generates a structured review.
- **`eva test` Command:** Generate unit tests for specified files using the LLM.
- **Cost Estimation:** Show estimated cost before sending paid-tier requests.
- **Conversation Branching:** Allow saving and restoring conversation branches during chat sessions.

### 🔴 Advanced

- **MCP (Model Context Protocol) Integration:** Connect Eva to external tool servers for database queries, API calls, and documentation lookup.
- **RAG over Codebase:** Build a codebase embedding and semantic search system for intelligent context selection.

- **Plugin/Extension System:** Allow community-contributed providers and custom commands.

## Adding a New Provider

1. Create a new file in `src/eva/router/` (e.g., `ollama_provider.py`).
2. If the provider exposes an OpenAI-compatible API, subclass `OpenAICompatibleProvider` from `openai_compat.py`.
3. If it uses a different SDK, implement the `Provider` protocol directly (see `gemini_provider.py` as an example).
4. Register the provider at the bottom of your file:
   ```python
   from eva.router import register_provider

   register_provider(YourProvider())
   ```
5. Import your provider module in `cli.py` so it self-registers on startup.
6. Add a default configuration entry in `config.py`.

## License

By contributing to Eva CLI, you agree that your contributions will be licensed under the MIT License.
