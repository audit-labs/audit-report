"""Markdown renderer — the auditor-facing evidence report."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .. import catalog
from ..engine import FAIL, NOT_APPLICABLE, PASS

if TYPE_CHECKING:
    from . import Report

_STATUS_LABEL = {PASS: "PASS", FAIL: "FAIL", NOT_APPLICABLE: "N/A"}
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _evidence_table(rows: list[dict[str, str]]) -> list[str]:
    """Render up to a handful of evidence rows as a Markdown table."""
    if not rows:
        return []
    shown = rows[:10]
    headers = list(shown[0].keys())
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in shown:
        lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    if len(rows) > len(shown):
        lines.append(f"\n_+{len(rows) - len(shown)} more row(s) omitted._")
    return lines


def render(report: Report) -> str:
    pkg = report.package
    counts = report.counts
    out: list[str] = []

    out.append(f"# Evidence Report — {pkg.subject}")
    out.append("")
    out.append(f"- **Platform:** {pkg.platform}")
    out.append(f"- **Subject:** {pkg.subject}")
    out.append(f"- **Source package:** `{pkg.path.name}`")
    out.append(f"- **Generated:** {report.generated_at}")
    out.append(
        f"- **Result:** {counts[FAIL]} failing · {counts[PASS]} passing · "
        f"{counts[NOT_APPLICABLE]} not applicable"
    )
    out.append("")
    out.append(
        "> This report presents *evidence*, not a compliance verdict. A failing "
        "row means a setting is in a state that does not support a control; the "
        "final judgment belongs to the organization and its auditor."
    )
    out.append("")

    # Control coverage matrix.
    out.append("## Control coverage")
    out.append("")
    out.append("| Control | Framework | Status | Checked by | Description |")
    out.append("| --- | --- | --- | --- | --- |")
    for control, entry in report.coverage.items():
        out.append(
            f"| {control} | {catalog.framework_of(control)} | "
            f"{_STATUS_LABEL[entry['status']]} | {', '.join(entry['rules'])} | "
            f"{catalog.describe(control)} |"
        )
    out.append("")

    # Findings, failures first then by severity.
    out.append("## Findings")
    out.append("")
    ordered = sorted(
        report.findings,
        key=lambda f: (f.status != FAIL, _SEVERITY_ORDER.get(f.rule.severity, 1)),
    )
    for finding in ordered:
        rule = finding.rule
        out.append(f"### {_STATUS_LABEL[finding.status]} · {rule.title}")
        out.append("")
        out.append(f"- **Rule:** `{rule.id}`  ·  **Severity:** {rule.severity}")
        out.append(f"- **Controls:** {', '.join(rule.controls) or '—'}")
        out.append(f"- **Result:** {finding.reason}")
        if rule.rationale:
            out.append(f"- **Why it matters:** {rule.rationale.strip()}")
        if finding.status == FAIL and rule.remediation:
            out.append(f"- **Remediation:** {rule.remediation.strip()}")
        out.append("")
        if finding.status == FAIL and finding.evidence:
            out.append("**Evidence:**")
            out.append("")
            out.extend(_evidence_table(finding.evidence))
            out.append("")

    return "\n".join(out).rstrip() + "\n"
