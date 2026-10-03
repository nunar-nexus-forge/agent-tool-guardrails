# Contributing to agent-tool-guardrails

Thanks for your interest. This document explains how to set up a development
environment, what we expect in a pull request, and where help is most useful.

## Development setup

The project uses [uv](https://docs.astral.sh/uv/). Everything is installed into a
project-local virtual environment (`./.venv`); nothing touches your global Python.

```bash
git clone https://github.com/nunar-nexus-forge/agent-tool-guardrails
cd agent-tool-guardrails
make sync             # uv sync --group dev --group frameworks  -> ./.venv
make check            # ruff + mypy + pytest
```

Without `make`: `uv sync --group dev --group frameworks`, then `uv run pytest`.

## What makes a good pull request

- **Tests.** Every behaviour change comes with a test in `tests/`. Adapter tests must
  not require network access or API keys (use fakes, as the existing tests do).
- **Type hints and docstrings** on public API.
- **Lint clean**: `uv run ruff check . && uv run ruff format --check .`.
- **A CHANGELOG entry** under "Unreleased".
- **No copied text or figures** from other projects or publications; write it in your own
  words and credit your sources.

## Where help is most welcome

- Requirement templates for specific regimes (HIPAA minimum-necessary, PCI-DSS scope, SOC 2 change control, EU AI Act logging).
- Streamable-HTTP transport for the MCP proxy.
- Adapters for the OpenAI Agents SDK, Semantic Kernel and CrewAI tools.
- Evidence exporters (OpenTelemetry logs, SIEM formats) and approval-handler integrations (Slack, ticketing).

## Reporting bugs and requesting features

Use the issue templates. For security problems see [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Release process (maintainers)

1. Bump `version` in `pyproject.toml` and `src/typed_rails/_version.py`, update `CHANGELOG.md` and `CITATION.cff`.
2. Tag: `git tag v0.2.0 && git push --tags`.
3. The `release.yml` workflow builds and publishes to PyPI via trusted publishing.
