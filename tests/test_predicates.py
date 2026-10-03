from __future__ import annotations

import pytest

from typed_rails.predicates import Predicate, PredicateError, PredicateSyntaxError, tokenize

NS = {
    "tool": "transfer_funds",
    "args": {"amount": 1500, "to": "ACME", "tags": ["urgent", "eu"], "customer": {"email": "a@b.com"}},
    "agent": {"name": "bot", "trust": 0.8, "role": None},
    "evidence": {"anonymised": True, "region": "EU"},
    "time": {"hour": 10, "weekday": 2},
    "result": "Call me at 555-123-4567",
    "env": {},
}


@pytest.mark.parametrize(
    "source,expected",
    [
        ('tool == "transfer_funds"', True),
        ("args.amount > 1000 and agent.trust >= 0.7", True),
        ("args.amount > 1000 and not (agent.trust >= 0.7)", False),
        ("args.missing == null", True),
        ("args.missing > 5", False),
        ("evidence.anonymised == true", True),
        ('"urgent" in args.tags', True),
        ('args.to in ["ACME", "Globex"]', True),
        ('args.to not in ["Globex"]', True),
        ('matches(args.to, "(?i)^ac")', True),
        ('args.to matches "^AC"', True),
        ('args.customer.email contains "@"', True),
        ('args.to startswith "AC" and args.to endswith "ME"', True),
        ("len(args.tags) == 2", True),
        ("args.amount * 2 - 1000 == 2000", True),
        ("args.amount / 0 == null", True),
        ("-args.amount < 0", True),
        ('lower(args.to) == "acme"', True),
        ("count_pii(result) == 1", True),
        ("has_pii(args.customer)", True),
        ("time.hour >= 8 and time.hour < 18 and time.weekday in [0, 1, 2, 3, 4]", True),
        ("exists(args.amount) and not exists(args.nothing)", True),
        ('args["amount"] > 1000 and args.tags[0] == "urgent" and args.tags[-1] == "eu"', True),
        ("min(args.amount, 10) == 10 and max(1, 2, null) == 2", True),
        ("any([false, true]) and all([true, true]) and sum([1, 2.5]) == 3.5", True),
        ('str(args.amount) == "1500" and int("7") == 7 and float("1.5") == 1.5', True),
        ("(args.amount > 100) or false", True),
        ("null == null and true != false", True),
    ],
)
def test_predicates(source, expected):
    assert Predicate(source).evaluate(NS) is expected


def test_paths_functions_explain_static():
    p = Predicate('tool == "x" and args.amount > len(args.tags)')
    assert p.paths == ["tool", "args.amount", "args.tags"] and p.functions == ["len"]
    assert p.explain(NS) == {"tool": "transfer_funds", "args.amount": 1500, "args.tags": ["urgent", "eu"]}
    assert not p.is_static
    assert Predicate('tool in ["a", "b"] and agent.name != "x"').is_static
    assert Predicate("false").is_static and not Predicate("rate(tool, 60) < 3").is_static
    assert Predicate("a == 1") == Predicate("a == 1") and hash(Predicate("a==1")) == hash(Predicate("a==1"))
    assert "Predicate(" in repr(p)


@pytest.mark.parametrize(
    "source",
    [
        "",
        "   ",
        "args.amount >",
        "(args.amount",
        "args.amount == 1 2",
        "unknown_fn(1)",
        "args.[1]",
        "1 +",
        "@",
    ],
)
def test_syntax_errors(source):
    with pytest.raises(PredicateSyntaxError):
        Predicate(source)


def test_runtime_functions_and_errors():
    p = Predicate("rate(tool, 60) < 3")
    assert p.evaluate(NS, {"rate": lambda tool, window: 1}) is True
    with pytest.raises(PredicateError):
        p.evaluate(NS)  # runtime function not provided
    with pytest.raises(PredicateError):
        Predicate('matches(args.to, "(")').evaluate(NS)
    long_pattern = "a" * 501
    with pytest.raises(PredicateError):
        Predicate(f'matches(args.to, "{long_pattern}")').evaluate(NS)


def test_tokenizer_strings_and_numbers():
    toks = tokenize("x == 'it\\'s' and y >= 1.5e3")
    assert [t.kind for t in toks] == ["name", "op", "string", "keyword", "name", "op", "number", "end"]
    assert Predicate("y >= 1.5e3").evaluate({"y": 1500}) is True
    assert Predicate("s == 'it\\'s'").evaluate({"s": "it's"}) is True
