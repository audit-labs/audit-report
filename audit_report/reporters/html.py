"""HTML renderer — a self-contained, printable evidence report.

No external assets: all CSS is inlined so the file can be attached to an audit
workpaper and opened anywhere, including offline.
"""

from __future__ import annotations

from html import escape
from typing import TYPE_CHECKING

from .. import catalog
from ..engine import FAIL, NOT_APPLICABLE, PASS

if TYPE_CHECKING:
    from . import Report

_STATUS_LABEL = {PASS: "PASS", FAIL: "FAIL", NOT_APPLICABLE: "N/A"}
_STATUS_CLASS = {PASS: "pass", FAIL: "fail", NOT_APPLICABLE: "na"}
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 0; padding: 2rem; line-height: 1.5; color: #1a1a1a; background: #fff; }
main { max-width: 60rem; margin: 0 auto; }
h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
h2 { margin: 2rem 0 .75rem; font-size: 1.25rem; border-bottom: 2px solid #e5e5e5; padding-bottom: .25rem; }
.meta { color: #555; font-size: .9rem; margin: 0 0 1rem; }
.meta code { background: #f2f2f2; padding: .05rem .3rem; border-radius: 3px; }
.note { background: #f7f7f9; border-left: 3px solid #b9b9c6; padding: .6rem .9rem;
  font-size: .9rem; color: #444; border-radius: 0 4px 4px 0; }
table { border-collapse: collapse; width: 100%; font-size: .85rem; margin: .5rem 0; }
th, td { border: 1px solid #e0e0e0; padding: .35rem .5rem; text-align: left; vertical-align: top; }
th { background: #f5f5f7; }
.badge { display: inline-block; font-weight: 700; font-size: .72rem; letter-spacing: .03em;
  padding: .12rem .5rem; border-radius: 999px; }
.badge.pass { background: #e5f6ea; color: #1a7f37; }
.badge.fail { background: #fdeaea; color: #c1272d; }
.badge.na { background: #eee; color: #666; }
.finding { border: 1px solid #e5e5e5; border-radius: 6px; padding: 1rem 1.1rem; margin: .8rem 0; }
.finding.fail { border-left: 4px solid #c1272d; }
.finding.pass { border-left: 4px solid #1a7f37; }
.finding.na { border-left: 4px solid #bbb; }
.finding h3 { margin: 0 0 .5rem; font-size: 1.05rem; display: flex; gap: .5rem; align-items: center; }
.finding dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .8rem; margin: .4rem 0 0; font-size: .9rem; }
.finding dt { color: #666; font-weight: 600; }
.finding dd { margin: 0; }
.summary-pills span { display: inline-block; margin-right: .5rem; font-weight: 600; }
footer { margin-top: 3rem; font-size: .8rem; color: #888; border-top: 1px solid #eee; padding-top: .75rem; }
@media (prefers-color-scheme: dark) {
  body { color: #e6e6e6; background: #16171a; }
  h2 { border-color: #333; }
  .meta { color: #aaa; } .meta code { background: #26272b; }
  .note { background: #1e1f24; border-color: #444; color: #bbb; }
  th, td { border-color: #333; } th { background: #202126; }
  .finding { border-color: #2d2e33; }
  .badge.pass { background: #12321d; color: #4ac36a; }
  .badge.fail { background: #3a1416; color: #ff6b70; }
  .badge.na { background: #26272b; color: #999; }
  footer { border-color: #2a2b30; }
}
"""


def _badge(status: str) -> str:
    return f'<span class="badge {_STATUS_CLASS[status]}">{_STATUS_LABEL[status]}</span>'


def _evidence_table(rows: list[dict[str, str]]) -> str:
    shown = rows[:10]
    headers = list(shown[0].keys())
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(str(r.get(h, '')))}</td>" for h in headers) + "</tr>"
        for r in shown
    )
    extra = (
        f"<p class='meta'>+{len(rows) - len(shown)} more row(s) omitted.</p>"
        if len(rows) > len(shown)
        else ""
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{extra}"


def render(report: Report) -> str:
    pkg = report.package
    counts = report.counts
    parts: list[str] = []

    parts.append(f"<h1>Evidence Report — {escape(pkg.subject)}</h1>")
    parts.append(
        f"<p class='meta'>Platform <code>{escape(pkg.platform)}</code> · "
        f"Source <code>{escape(pkg.path.name)}</code> · "
        f"Generated {escape(report.generated_at)}</p>"
    )
    parts.append(
        "<p class='summary-pills'>"
        f"<span>{_badge(FAIL)} {counts[FAIL]} failing</span>"
        f"<span>{_badge(PASS)} {counts[PASS]} passing</span>"
        f"<span>{_badge(NOT_APPLICABLE)} {counts[NOT_APPLICABLE]} not applicable</span>"
        "</p>"
    )
    parts.append(
        "<p class='note'>This report presents <strong>evidence</strong>, not a "
        "compliance verdict. A failing row means a setting is in a state that does "
        "not support a control; the final judgment belongs to the organization and "
        "its auditor.</p>"
    )

    # Coverage matrix.
    parts.append("<h2>Control coverage</h2>")
    cov_rows = "".join(
        f"<tr><td>{escape(control)}</td><td>{escape(catalog.framework_of(control))}</td>"
        f"<td>{_badge(entry['status'])}</td>"
        f"<td><code>{escape(', '.join(entry['rules']))}</code></td>"
        f"<td>{escape(catalog.describe(control))}</td></tr>"
        for control, entry in report.coverage.items()
    )
    parts.append(
        "<table><thead><tr><th>Control</th><th>Framework</th><th>Status</th>"
        f"<th>Checked by</th><th>Description</th></tr></thead><tbody>{cov_rows}</tbody></table>"
    )

    # Findings.
    parts.append("<h2>Findings</h2>")
    ordered = sorted(
        report.findings,
        key=lambda f: (f.status != FAIL, _SEVERITY_ORDER.get(f.rule.severity, 1)),
    )
    for finding in ordered:
        rule = finding.rule
        rows = [
            f"<dt>Rule</dt><dd><code>{escape(rule.id)}</code> · {escape(rule.severity)}</dd>",
            f"<dt>Controls</dt><dd>{escape(', '.join(rule.controls) or '—')}</dd>",
            f"<dt>Result</dt><dd>{escape(finding.reason)}</dd>",
        ]
        if rule.rationale:
            rows.append(f"<dt>Why it matters</dt><dd>{escape(rule.rationale.strip())}</dd>")
        if finding.status == FAIL and rule.remediation:
            rows.append(f"<dt>Remediation</dt><dd>{escape(rule.remediation.strip())}</dd>")
        evidence = (
            _evidence_table(finding.evidence)
            if finding.status == FAIL and finding.evidence
            else ""
        )
        parts.append(
            f"<div class='finding {_STATUS_CLASS[finding.status]}'>"
            f"<h3>{_badge(finding.status)} {escape(rule.title)}</h3>"
            f"<dl>{''.join(rows)}</dl>{evidence}</div>"
        )

    parts.append(
        "<footer>Generated by audit-report · Audit Labs · "
        "evidence, not a verdict.</footer>"
    )

    body = "\n".join(parts)
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>Evidence Report — {escape(pkg.subject)}</title>"
        f"<style>{CSS}</style></head><body><main>{body}</main></body></html>\n"
    )
