# SPDX-License-Identifier: Apache-2.0
"""Framework helpers built on :meth:`PolicyEngine.guard`."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .engine import PolicyEngine


def guard_callable(
    engine: PolicyEngine,
    fn: Callable[..., Any],
    *,
    tool: str | None = None,
    agent: str = "agent",
    evidence: Mapping[str, Any] | None = None,
) -> Callable[..., Any]:
    return engine.guard(tool, agent=agent, evidence=evidence)(fn)


def guard_langchain_tool(
    tool: Any, engine: PolicyEngine, *, agent: str = "agent", evidence: Mapping[str, Any] | None = None
) -> Any:
    """Return a policy-guarded copy of a LangChain ``BaseTool`` (requires ``langchain-core``)."""
    try:
        from langchain_core.tools import BaseTool, StructuredTool
    except ImportError as e:  # pragma: no cover - only without the extra
        raise ImportError(
            "guard_langchain_tool needs langchain-core: pip install 'agent-tool-guardrails[langchain]'"
        ) from e
    if not isinstance(tool, BaseTool):
        raise TypeError("expected a LangChain BaseTool")
    original = tool

    def call(**kwargs: Any) -> Any:
        return original.invoke(kwargs)

    call.__name__ = original.name
    guarded = engine.guard(original.name, agent=agent, evidence=evidence)(call)
    return StructuredTool.from_function(
        func=guarded, name=original.name, description=original.description, args_schema=original.args_schema
    )
