"""Rule model and the small condition language rulesets are written in.

A **ruleset** is a YAML file: a platform name plus a list of rules. Each rule
names a table, a check, the controls it maps to, and human text. Checks are
evaluated by :mod:`audit_report.engine`.

The condition language is intentionally tiny. A *condition* is one of:

* a leaf ``{column, op, value}`` — test one column of a row
* ``{all: [cond, ...]}`` — every sub-condition holds
* ``{any: [cond, ...]}`` — at least one holds
* ``{not: cond}`` — the sub-condition does not hold

Operators (``op``): ``equals``, ``not_equals``, ``is_true``, ``is_false``,
``in``, ``not_in``, ``gt``, ``gte``, ``lt``, ``lte``, ``empty``, ``not_empty``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_TRUTHY = {"true", "yes", "1", "y", "t", "enabled", "on"}
_FALSY = {"false", "no", "0", "n", "f", "disabled", "off", ""}

VALID_CHECK_TYPES = {
    "fail_rows_where",
    "fail_if_any_rows",
    "assert_row",
    "require_any_row",
}


@dataclass
class Rule:
    """A single control check declared in a ruleset."""

    id: str
    title: str
    table: str
    check: dict
    severity: str = "medium"
    controls: list[str] = field(default_factory=list)
    rationale: str = ""
    remediation: str = ""


@dataclass
class Ruleset:
    """A named collection of rules for one platform."""

    platform: str
    rules: list[Rule]


def _as_number(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def match(condition: dict, row: dict[str, str]) -> bool:
    """Return True if *condition* holds for *row*.

    Raises ``ValueError`` on a malformed condition so ruleset bugs surface
    loudly rather than silently evaluating to False.
    """
    if "all" in condition:
        return all(match(c, row) for c in condition["all"])
    if "any" in condition:
        return any(match(c, row) for c in condition["any"])
    if "not" in condition:
        return not match(condition["not"], row)

    column = condition.get("column")
    op = condition.get("op")
    if column is None or op is None:
        raise ValueError(f"malformed condition: {condition!r}")

    raw = row.get(column, "")
    value = condition.get("value")
    norm = raw.strip().lower()

    if op == "equals":
        return norm == str(value).strip().lower()
    if op == "not_equals":
        return norm != str(value).strip().lower()
    if op == "is_true":
        return norm in _TRUTHY
    if op == "is_false":
        return norm in _FALSY
    if op == "empty":
        return raw.strip() == ""
    if op == "not_empty":
        return raw.strip() != ""
    if op in ("in", "not_in"):
        choices = {str(v).strip().lower() for v in (value or [])}
        return (norm in choices) if op == "in" else (norm not in choices)
    if op in ("gt", "gte", "lt", "lte"):
        left, right = _as_number(raw), _as_number(str(value))
        if left is None or right is None:
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[op]

    raise ValueError(f"unknown operator: {op!r}")


def load_ruleset(path: str | Path) -> Ruleset:
    """Parse a ruleset YAML file into a :class:`Ruleset`, validating each rule."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    platform = data.get("platform")
    if not platform:
        raise ValueError(f"{path}: ruleset is missing a 'platform'")

    rules: list[Rule] = []
    for entry in data.get("rules", []):
        rule = Rule(
            id=entry["id"],
            title=entry["title"],
            table=entry["table"],
            check=entry["check"],
            severity=entry.get("severity", "medium"),
            controls=entry.get("controls", []),
            rationale=entry.get("rationale", ""),
            remediation=entry.get("remediation", ""),
        )
        check_type = rule.check.get("type")
        if check_type not in VALID_CHECK_TYPES:
            raise ValueError(f"{rule.id}: unknown check type {check_type!r}")
        rules.append(rule)

    return Ruleset(platform=platform, rules=rules)
