"""Unit tests for the condition language in audit_report.rules."""

import pytest

from audit_report.rules import match


@pytest.mark.parametrize(
    ("condition", "row", "expected"),
    [
        ({"column": "x", "op": "equals", "value": "read"}, {"x": "read"}, True),
        ({"column": "x", "op": "equals", "value": "Read"}, {"x": "read"}, True),  # case-insensitive
        ({"column": "x", "op": "not_equals", "value": "read"}, {"x": "write"}, True),
        ({"column": "x", "op": "is_true"}, {"x": "True"}, True),
        ({"column": "x", "op": "is_true"}, {"x": "yes"}, True),
        ({"column": "x", "op": "is_false"}, {"x": "False"}, True),
        ({"column": "x", "op": "is_false"}, {"x": ""}, True),  # empty reads as false
        ({"column": "x", "op": "gt", "value": 90}, {"x": "404"}, True),
        ({"column": "x", "op": "gt", "value": 90}, {"x": "30"}, False),
        ({"column": "x", "op": "lte", "value": 90}, {"x": "90"}, True),
        ({"column": "x", "op": "gt", "value": 90}, {"x": ""}, False),  # non-numeric -> False
        ({"column": "x", "op": "in", "value": ["read", "none"]}, {"x": "none"}, True),
        ({"column": "x", "op": "not_in", "value": ["read", "none"]}, {"x": "admin"}, True),
        ({"column": "x", "op": "empty"}, {"x": "  "}, True),
        ({"column": "x", "op": "not_empty"}, {"x": "v"}, True),
    ],
)
def test_leaf_conditions(condition, row, expected):
    assert match(condition, row) is expected


def test_boolean_combinators():
    row = {"console_password": "True", "mfa_enabled": "False"}
    cond = {
        "all": [
            {"column": "console_password", "op": "is_true"},
            {"column": "mfa_enabled", "op": "is_false"},
        ]
    }
    assert match(cond, row) is True
    assert match({"any": [{"column": "mfa_enabled", "op": "is_true"}]}, row) is False
    assert match({"not": {"column": "mfa_enabled", "op": "is_true"}}, row) is True


def test_malformed_condition_raises():
    with pytest.raises(ValueError, match="malformed condition"):
        match({"value": "x"}, {"x": "y"})


def test_unknown_operator_raises():
    with pytest.raises(ValueError, match="unknown operator"):
        match({"column": "x", "op": "wat"}, {"x": "y"})
