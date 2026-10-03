from __future__ import annotations

from typed_rails.redaction import count_pii, find_pii, redact_text, redact_value, register_pattern


def test_find_and_redact_text():
    text = "Contact jane.doe@example.com or +1 (555) 123-4567; card 4111 1111 1111 1111; ssn 123-45-6789; ip 10.0.0.1"
    kinds = [m.kind for m in find_pii(text)]
    assert kinds == ["email", "phone", "credit_card", "ssn", "ipv4"]
    redacted = redact_text(text)
    assert "[REDACTED:email]" in redacted and "[REDACTED:credit_card]" in redacted and "4111" not in redacted
    assert find_pii("card 1234 5678 9012 3456") == []  # fails the Luhn check
    assert find_pii("") == [] and find_pii(None) == []  # type: ignore[arg-type]
    assert count_pii({"a": ["x@y.io", {"b": "555-123-4567"}], "n": 3}) == 2
    assert count_pii(12) == 0


def test_kinds_filter_and_custom_pattern():
    text = "a@b.com EMP-12345"
    assert [m.kind for m in find_pii(text, kinds=["email"])] == ["email"]
    register_pattern("employee_id", r"EMP-\d{5}")
    assert "employee_id" in [m.kind for m in find_pii(text)]
    assert redact_text(text, kinds=["employee_id"]) == "a@b.com [REDACTED:employee_id]"


def test_redact_value_fields_and_detection():
    args = {"customer": {"email": "a@b.com", "name": "Jane"}, "note": "call 555-123-4567", "amount": 5}
    out, paths = redact_value(args, ["args.customer.email"], detect=True)
    assert out["customer"]["email"] == "[REDACTED]" and out["customer"]["name"] == "Jane"
    assert out["note"] == "call [REDACTED:phone]" and out["amount"] == 5
    assert paths == ["customer.email", "note"]
    assert args["customer"]["email"] == "a@b.com"  # original untouched
    out2, _ = redact_value(args, ["args.customer.*"], detect=False)
    assert (
        out2["customer"] == {"email": "[REDACTED]", "name": "[REDACTED]"}
        and out2["note"] == "call 555-123-4567"
    )
    out3, _ = redact_value(args, ["**"], detect=False)
    assert out3 == {"customer": "[REDACTED]", "note": "[REDACTED]", "amount": "[REDACTED]"}
    out4, paths4 = redact_value("mail a@b.com", None)
    assert out4 == "mail [REDACTED:email]" and paths4 == ["$"]
    out5, _ = redact_value(["x@y.io", ("t", "555-123-4567")], None)
    assert out5 == ["[REDACTED:email]", ("t", "[REDACTED:phone]")]
