"""Evaluate a ruleset against a loaded package to produce findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from .loader import Package, Row
from .rules import Rule, Ruleset, match

PASS = "pass"
FAIL = "fail"
NOT_APPLICABLE = "not_applicable"


@dataclass
class Finding:
    """The outcome of evaluating one rule against one package."""

    rule: Rule
    status: str
    reason: str
    evidence: list[Row] = field(default_factory=list)

    @property
    def controls(self) -> list[str]:
        return self.rule.controls


def _evaluate_rule(rule: Rule, package: Package) -> Finding:
    if not package.has(rule.table):
        return Finding(rule, NOT_APPLICABLE, f"table '{rule.table}' not in package")

    rows = package.table(rule.table)
    check = rule.check
    ctype = check["type"]

    if ctype == "assert_row":
        return _assert_row(rule, rows)

    if ctype == "require_any_row":
        return _require_any_row(rule, rows)

    # fail_rows_where / fail_if_any_rows both scan rows for failures.
    condition = check.get("when")
    if ctype == "fail_if_any_rows" and condition is None:
        failing = list(rows)
    else:
        # fail_rows_where requires a condition; fail_if_any_rows may filter too.
        if condition is None:
            raise ValueError(f"{rule.id}: check needs a 'when' condition")
        failing = [r for r in rows if match(condition, r)]

    if failing:
        noun = "row" if len(failing) == 1 else "rows"
        return Finding(rule, FAIL, f"{len(failing)} {noun} failed the check", failing)

    # A present-but-empty table means the scan found nothing to fault — the
    # absence of bad rows is a pass (e.g. no publicly readable buckets).
    if not rows:
        return Finding(rule, PASS, "no rows present — no violations found")
    return Finding(rule, PASS, f"all {len(rows)} rows passed the check")


def _assert_row(rule: Rule, rows: list[Row]) -> Finding:
    """Assert conditions against a single-row configuration table."""
    if not rows:
        return Finding(rule, NOT_APPLICABLE, f"table '{rule.table}' is empty")

    row = rows[0]
    failed = [req for req in rule.check.get("require", []) if not match(req, row)]
    if failed:
        columns = ", ".join(req.get("column", "?") for req in failed)
        return Finding(rule, FAIL, f"configuration failed on: {columns}", [row])
    return Finding(rule, PASS, "configuration meets all requirements")


def _require_any_row(rule: Rule, rows: list[Row]) -> Finding:
    """Pass if at least one row satisfies the condition; fail otherwise."""
    condition = rule.check.get("when")
    if condition is None:
        raise ValueError(f"{rule.id}: require_any_row needs a 'when' condition")
    if any(match(condition, row) for row in rows):
        return Finding(rule, PASS, "at least one row satisfies the requirement")
    reason = "no row satisfies the requirement" if rows else f"table '{rule.table}' is empty"
    return Finding(rule, FAIL, reason, rows)


def evaluate(package: Package, ruleset: Ruleset) -> list[Finding]:
    """Run every rule in *ruleset* against *package*."""
    return [_evaluate_rule(rule, package) for rule in ruleset.rules]


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Count findings by status."""
    counts = {PASS: 0, FAIL: 0, NOT_APPLICABLE: 0}
    for finding in findings:
        counts[finding.status] += 1
    return counts


# Worst-wins ordering when rolling several findings up to one control.
_STATUS_RANK = {FAIL: 2, PASS: 1, NOT_APPLICABLE: 0}


def control_coverage(findings: list[Finding]) -> dict[str, dict]:
    """Roll findings up to a per-control view.

    Returns ``{control: {"status": ..., "rules": [rule_id, ...]}}`` where a
    control's status is the worst status among the rules that cite it — one
    failing rule means the control is not fully evidenced.
    """
    coverage: dict[str, dict] = {}
    for finding in findings:
        for control in finding.controls:
            entry = coverage.setdefault(control, {"status": NOT_APPLICABLE, "rules": []})
            entry["rules"].append(finding.rule.id)
            if _STATUS_RANK[finding.status] > _STATUS_RANK[entry["status"]]:
                entry["status"] = finding.status
    return dict(sorted(coverage.items()))
