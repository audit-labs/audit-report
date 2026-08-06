"""Trend mode — track each rule across a series of dated packages.

Given a folder of audit-tools packages for the same platform and subject
(``aws_audit_prod_2026-01-01/``, ``…_2026-02-01/``, …), this evaluates every
package with the same ruleset and lays the results out as a timeline: one row
per rule, one column per package date, so you can see a control drift in and out
of compliance over time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from .engine import FAIL, NOT_APPLICABLE, PASS, Finding
from .loader import Package, detect_platform, package_date
from .reporters.html import CSS as _CSS

_STATUS_SYMBOL = {PASS: "✓", FAIL: "✗", NOT_APPLICABLE: "·"}
_STATUS_CLASS = {PASS: "pass", FAIL: "fail", NOT_APPLICABLE: "na"}
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def discover(parent: str | Path, subject: str | None = None) -> tuple[str, str, list[Path]]:
    """Find a single series of packages under *parent*.

    Returns ``(platform, subject, [paths sorted by date])``. Raises ``ValueError``
    if no packages are found, if fewer than two share a platform/subject, or if
    several distinct series are present and *subject* does not narrow it to one.
    """
    directory = Path(parent)
    if not directory.is_dir():
        raise ValueError(f"not a directory: {directory}")

    groups: dict[tuple[str, str], list[Path]] = {}
    for child in sorted(directory.iterdir()):
        if not child.is_dir() or not any(child.glob("*.csv")):
            continue
        platform, subj = detect_platform(child.name)
        if platform == "unknown":
            continue
        if subject and subj != subject:
            continue
        groups.setdefault((platform, subj), []).append(child)

    if not groups:
        raise ValueError(
            f"no audit-tools packages found under {directory}"
            + (f" for subject '{subject}'" if subject else "")
        )
    if len(groups) > 1:
        listed = ", ".join(f"{p}/{s}" for p, s in sorted(groups))
        raise ValueError(
            f"multiple series found ({listed}); narrow with --subject and a "
            "directory that holds one platform"
        )

    (platform, subj), paths = next(iter(groups.items()))
    if len(paths) < 2:
        raise ValueError("a trend needs at least two packages in the series")

    paths.sort(key=lambda p: (package_date(p.name), p.name))
    return platform, subj, paths


@dataclass
class TrendRow:
    """One rule's status across the timeline."""

    rule: object  # audit_report.rules.Rule
    statuses: list[str]

    @property
    def transitions(self) -> int:
        """How many times the status changed along the timeline."""
        return sum(1 for a, b in zip(self.statuses, self.statuses[1:]) if a != b)


@dataclass
class TrendReport:
    """Rules-over-time view of a package series."""

    platform: str
    subject: str
    dates: list[str]  # column labels (package date or dir name)
    rows: list[TrendRow]
    generated_at: str

    def fails_per_date(self) -> list[int]:
        return [
            sum(1 for row in self.rows if row.statuses[i] == FAIL)
            for i in range(len(self.dates))
        ]


def build_trend(
    packages: list[Package], findings_per_package: list[list[Finding]]
) -> TrendReport:
    """Assemble a :class:`TrendReport` from aligned packages and findings."""
    dates = [pkg.date or pkg.path.name for pkg in packages]

    # Preserve rule order from the first package; align by rule id across dates.
    order = [f.rule for f in findings_per_package[0]]
    by_date = [{f.rule.id: f for f in findings} for findings in findings_per_package]

    rows = [
        TrendRow(
            rule=rule,
            statuses=[
                col.get(rule.id).status if col.get(rule.id) else NOT_APPLICABLE
                for col in by_date
            ],
        )
        for rule in order
    ]
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return TrendReport(
        platform=packages[0].platform,
        subject=packages[0].subject,
        dates=dates,
        rows=rows,
        generated_at=stamp,
    )


def latest_findings(findings_per_package: list[list[Finding]]) -> list[Finding]:
    """The findings of the most recent package (for --fail-on gating)."""
    return findings_per_package[-1]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _render_md(trend: TrendReport) -> str:
    out: list[str] = []
    out.append(f"# Evidence Trend — {trend.subject} ({trend.platform})")
    out.append("")
    out.append(f"- **Packages:** {len(trend.dates)}")
    out.append(f"- **Timeline:** {trend.dates[0]} → {trend.dates[-1]}")
    out.append(f"- **Generated:** {trend.generated_at}")
    out.append("")
    out.append("Legend: ✓ pass · ✗ fail · · not applicable")
    out.append("")

    header = "| Rule | Sev | " + " | ".join(trend.dates) + " |"
    sep = "| --- | --- | " + " | ".join("---" for _ in trend.dates) + " |"
    out.append(header)
    out.append(sep)
    for row in sorted(trend.rows, key=lambda r: _SEVERITY_ORDER.get(r.rule.severity, 1)):
        cells = " | ".join(_STATUS_SYMBOL.get(s, "?") for s in row.statuses)
        out.append(f"| {row.rule.title} | {row.rule.severity} | {cells} |")

    fails = trend.fails_per_date()
    out.append("| **Failing total** | | " + " | ".join(str(n) for n in fails) + " |")
    return "\n".join(out).rstrip() + "\n"


_TREND_CSS = (
    _CSS
    + """
.trend { border-collapse: collapse; }
.trend th.date { font-size: .78rem; white-space: nowrap; }
.trend td.cell { text-align: center; font-weight: 700; width: 2.4rem; }
.trend td.cell.pass { background: #e5f6ea; color: #1a7f37; }
.trend td.cell.fail { background: #fdeaea; color: #c1272d; }
.trend td.cell.na { background: #f4f4f6; color: #999; }
.trend tr.totals td { font-weight: 700; background: #fafafa; }
.rulecol { max-width: 22rem; }
.legend { font-size: .85rem; color: #555; margin: .25rem 0 1rem; }
@media (prefers-color-scheme: dark) {
  .trend td.cell.pass { background: #12321d; color: #4ac36a; }
  .trend td.cell.fail { background: #3a1416; color: #ff6b70; }
  .trend td.cell.na { background: #202126; color: #888; }
  .trend tr.totals td { background: #1c1d21; }
  .legend { color: #aaa; }
}
"""
)


def _render_html(trend: TrendReport) -> str:
    date_heads = "".join(f"<th class='date'>{escape(d)}</th>" for d in trend.dates)
    body_rows: list[str] = []
    for row in sorted(trend.rows, key=lambda r: _SEVERITY_ORDER.get(r.rule.severity, 1)):
        cells = "".join(
            f"<td class='cell {_STATUS_CLASS.get(s, 'na')}' title='{escape(s)}'>"
            f"{_STATUS_SYMBOL.get(s, '?')}</td>"
            for s in row.statuses
        )
        body_rows.append(
            f"<tr><td class='rulecol'>{escape(row.rule.title)}"
            f"<br><code>{escape(row.rule.id)}</code></td>"
            f"<td>{escape(row.rule.severity)}</td>{cells}</tr>"
        )
    totals = "".join(f"<td class='cell'>{n}</td>" for n in trend.fails_per_date())

    table = (
        "<table class='trend'><thead><tr><th class='rulecol'>Rule</th><th>Sev</th>"
        f"{date_heads}</tr></thead><tbody>{''.join(body_rows)}"
        f"<tr class='totals'><td>Failing total</td><td></td>{totals}</tr>"
        "</tbody></table>"
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>Evidence Trend — {escape(trend.subject)}</title>"
        f"<style>{_TREND_CSS}</style></head><body><main>"
        f"<h1>Evidence Trend — {escape(trend.subject)} ({escape(trend.platform)})</h1>"
        f"<p class='meta'>{len(trend.dates)} packages · {escape(trend.dates[0])} → "
        f"{escape(trend.dates[-1])} · Generated {escape(trend.generated_at)}</p>"
        "<p class='legend'>✓ pass · ✗ fail · · not applicable — cell colour tracks "
        "each control over time.</p>"
        f"{table}"
        "<footer>Generated by audit-report · Audit Labs · evidence, not a verdict.</footer>"
        "</main></body></html>\n"
    )


def _render_json(trend: TrendReport) -> str:
    import json as _json

    payload = {
        "subject": trend.subject,
        "platform": trend.platform,
        "dates": trend.dates,
        "generated_at": trend.generated_at,
        "fails_per_date": trend.fails_per_date(),
        "rules": [
            {
                "id": row.rule.id,
                "title": row.rule.title,
                "severity": row.rule.severity,
                "controls": row.rule.controls,
                "statuses": row.statuses,
            }
            for row in trend.rows
        ],
    }
    return _json.dumps(payload, indent=2) + "\n"


_RENDERERS = {"md": _render_md, "html": _render_html, "json": _render_json}


def render(trend: TrendReport, fmt: str) -> str:
    """Render a trend in the named format ('md', 'html', or 'json')."""
    try:
        return _RENDERERS[fmt](trend)
    except KeyError:
        raise ValueError(f"unknown format: {fmt!r}") from None
