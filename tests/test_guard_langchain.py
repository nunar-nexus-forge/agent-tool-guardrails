from __future__ import annotations

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import tool

from typed_rails import PolicyDenied, PolicyEngine, compile_policy
from typed_rails.guard import guard_callable, guard_langchain_tool


@tool
def drop_database(confirm: bool) -> str:
    """Destroy everything."""
    return "dropped"


@tool
def echo(text: str) -> str:
    """Echo."""
    return text


def test_guarded_langchain_tools():
    engine = PolicyEngine(
        compile_policy(
            {
                "version": 1,
                "name": "lc",
                "requirements": [
                    {"template": "deny_tools", "tools": ["drop_database"]},
                    {"template": "pii_redaction", "tools": ["echo"]},
                ],
            }
        )
    )
    guarded = guard_langchain_tool(drop_database, engine, agent="bot")
    assert guarded.name == "drop_database"
    with pytest.raises(PolicyDenied):
        guarded.invoke({"confirm": True})
    safe_echo = guard_langchain_tool(echo, engine)
    assert safe_echo.invoke({"text": "a@b.com"}) == "[REDACTED:email]"
    assert guard_callable(engine, lambda text: text, tool="echo")("x@y.io") == "[REDACTED:email]"
    with pytest.raises(TypeError):
        guard_langchain_tool(object(), engine)
