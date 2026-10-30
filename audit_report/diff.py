"""Diff mode — compare two evidence packages and report drift.

Both packages are evaluated with the same ruleset; this module compares the two
sets of findings and classifies each rule's change:

* **regressed** — a control that was supported (or not yet observed) now fails
* **fixed** — a control that failed now passes (or is no longer observed)
* **drifted** — an ongoing failure whose failing evidence rows changed
* **changed** — a non-failure status change (e.g. a table stopped being collected)
* **unchanged** — same status, same evidence

Evidence rows are compared as whole rows, so drift shows exactly which items
appeared or disappeared (a new MFA-less user, a security group that was closed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .engine import FAIL, Finding
from .loader import Package

ABSENT = "absent"  # rule present in only one of the two packages

REGRESSED = "regressed"
FIXED = "fixed"
DRIFTED = "drifted"
CHANGED = "changed"
UNCHANGED = "unchanged"

# Order categories appear in a report and how they roll up in the summary.
CATEGORY_ORDER = [REGRESSED, FIXED, DRIFTED, CHANGED, UNCHANGED]
_STATUS_LABEL = {FAIL: "fail", "pass": "pass", "not_applicable": "n/a", ABSENT: "absent"}
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _row_key(row: dict[str, str]) -> tuple:
    return tuple(sorted(row.items()))


@dataclass
class RuleDelta:
    """How one rule's finding changed between the two packages."""

    rule: object  # audit_report.rules.Rule
    old_status: str
    new_status: str
    category: str
    new_reason: str = ""
    evidence_added: list[dict[str, str]] = field(default_factory=list)
    evidence_removed: list[dict[str, str]] = field(default_factory=list)

    @property
    def controls(self) -> list[str]:
        return self.rule.controls


def _classify(old_status, new_status, added, removed) -> str:
    if old_status == ABSENT:
        return REGRESSED if new_status == FAIL else CHANGED
    if new_status == ABSENT:
        return CHANGED  # rule dropped from the current ruleset
    if new_status == FAIL and old_status != FAIL:
        return REGRESSED
    if old_status == FAIL and new_status != FAIL:
        return FIXED
    if old_status == FAIL and new_status == FAIL:
        return DRIFTED if (added or removed) else UNCHANGED
    return CHANGED if old_status != new_status else UNCHANGED


def diff_findings(old: list[Finding], new: list[Finding]) -> list[RuleDelta]:
    """Compare two finding lists (same ruleset) into a list of deltas."""
    old_by_id = {f.rule.id: f for f in old}
    new_by_id = {f.rule.id: f for f in new}

    # New order first (ruleset order), then any rules only the baseline had.
    ordered_ids = [f.rule.id for f in new]
    ordered_ids += [f.rule.id for f in old if f.rule.id not in new_by_id]

    deltas: list[RuleDelta] = []
    for rid in ordered_ids:
        of, nf = old_by_id.get(rid), new_by_id.get(rid)
        rule = (nf or of).rule
        old_status = of.status if of else ABSENT
        new_status = nf.status if nf else ABSENT

        old_ev = {_row_key(r): r for r in (of.evidence if of else [])}
        new_ev = {_row_key(r): r for r in (nf.evidence if nf else [])}
        added = [r for k, r in new_ev.items() if k not in old_ev]
        removed = [r for k, r in old_ev.items() if k not in new_ev]

        category = _classify(old_status, new_status, added, removed)
        deltas.append(
            RuleDelta(
                rule=rule,
                old_status=old_status,
                new_status=new_status,
                category=category,
                new_reason=nf.reason if nf else "",
                evidence_added=added,
                evidence_removed=removed,
            )
        )
    return deltas


@dataclass
class DiffReport:
    """A computed comparison of two packages, ready to render."""

    baseline: Package
    current: Package
    deltas: list[RuleDelta]
    generated_at: str

    def by_category(self, category: str) -> list[RuleDelta]:
        rows = [d for d in self.deltas if d.category == category]
        return sorted(rows, key=lambda d: _SEVERITY_ORDER.get(d.rule.severity, 1))

    @property
    def counts(self) -> dict[str, int]:
        return {cat: len(self.by_category(cat)) for cat in CATEGORY_ORDER}


def build_diff(
    baseline: Package,
    current: Package,
    old_findings: list[Finding],
    new_findings: list[Finding],
) -> DiffReport:
    """Assemble a :class:`DiffReport` with a UTC timestamp."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return DiffReport(
        baseline=baseline,
        current=current,
        deltas=diff_findings(old_findings, new_findings),
        generated_at=stamp,
    )


def has_regression(diff: DiffReport, threshold: str) -> bool:
    """True if any regressed rule meets the severity *threshold* ('none' = off)."""
    if threshold == "none":
        return False
    floor = _SEVERITY_ORDER[threshold]
    return any(
        _SEVERITY_ORDER.get(d.rule.severity, 1) <= floor
        for d in diff.by_category(REGRESSED)
    )


def render(diff: DiffReport, fmt: str) -> str:
    """Render a diff in the named format ('md', 'html', or 'json')."""
    from .reporters.diff import render as render_diff

    return render_diff(diff, fmt)
