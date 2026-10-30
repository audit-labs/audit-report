"""Renderers for diff mode: Markdown, HTML, and JSON."""

from __future__ import annotations

import json
from html import escape

from ..diff import (
    _STATUS_LABEL,
    CATEGORY_ORDER,
    CHANGED,
    DRIFTED,
    FIXED,
    REGRESSED,
    UNCHANGED,
    DiffReport,
    RuleDelta,
)
from .html import CSS as _CSS

_CATEGORY_HEADING = {
    REGRESSED: "Regressions — a control is no longer supported",
    FIXED: "Fixed — a previously failing control now passes",
    DRIFTED: "Ongoing failures with changed evidence",
    CHANGED: "Other status changes",
    UNCHANGED: "Unchanged",
}


def _transition(delta: RuleDelta) -> str:
    return f"{_STATUS_LABEL.get(delta.old_status, delta.old_status)} → {_STATUS_LABEL.get(delta.new_status, delta.new_status)}"


def _md_table(rows: list[dict[str, str]]) -> list[str]:
    if not rows:
        return []
    shown = rows[:10]
    headers = list(shown[0].keys())
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    out += ["| " + " | ".join(str(r.get(h, "")) for h in headers) + " |" for r in shown]
    if len(rows) > len(shown):
        out.append(f"\n_+{len(rows) - len(shown)} more row(s) omitted._")
    return out


def _render_delta_md(delta, category: str) -> list[str]:
    rule = delta.rule
    out = [
        f"### {rule.title}",
        "",
        f"- **Rule:** `{rule.id}` · **Severity:** {rule.severity}",
        f"- **Controls:** {', '.join(rule.controls) or '—'}",
        f"- **Change:** {_transition(delta)}",
    ]
    if delta.new_reason:
        out.append(f"- **Now:** {delta.new_reason}")
    if category == REGRESSED and rule.remediation:
        out.append(f"- **Remediation:** {rule.remediation.strip()}")
    out.append("")
    if delta.evidence_added:
        out.append("**Newly failing rows:**")
        out.append("")
        out.extend(_md_table(delta.evidence_added))
        out.append("")
    if delta.evidence_removed:
        out.append("**No longer failing rows:**")
        out.append("")
        out.extend(_md_table(delta.evidence_removed))
        out.append("")
    return out


def _render_md(diff: DiffReport) -> str:
    counts = diff.counts
    out: list[str] = []
    out.append(f"# Evidence Drift — {diff.current.subject} ({diff.current.platform})")
    out.append("")
    out.append(f"- **Baseline:** `{diff.baseline.path.name}`")
    out.append(f"- **Current:** `{diff.current.path.name}`")
    out.append(f"- **Generated:** {diff.generated_at}")
    out.append(
        f"- **Drift:** {counts[REGRESSED]} regressed · {counts[FIXED]} fixed · "
        f"{counts[DRIFTED]} drifted · {counts[CHANGED]} changed · "
        f"{counts[UNCHANGED]} unchanged"
    )
    out.append("")
    out.append(
        "> A *regression* means a setting moved into a state that no longer "
        "supports a control since the baseline. As always this is evidence, not "
        "a verdict."
    )
    out.append("")

    for category in CATEGORY_ORDER:
        rows = diff.by_category(category)
        if not rows or category == UNCHANGED:
            continue
        out.append(f"## {_CATEGORY_HEADING[category]}")
        out.append("")
        for delta in rows:
            out.extend(_render_delta_md(delta, category))

    unchanged = diff.counts[UNCHANGED]
    if unchanged:
        out.append(f"_{unchanged} rule(s) unchanged._")
    return "\n".join(out).rstrip() + "\n"


def _html_table(rows: list[dict[str, str]], caption: str, cls: str) -> str:
    shown = rows[:10]
    headers = list(shown[0].keys())
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(str(r.get(h, '')))}</td>" for h in headers) + "</tr>"
        for r in shown
    )
    return (
        f"<table class='{cls}'><caption>{escape(caption)}</caption>"
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    )


_DIFF_CSS = (
    _CSS
    + """
.delta { border: 1px solid #e5e5e5; border-radius: 6px; padding: 1rem 1.1rem; margin: .8rem 0; }
.delta.regressed { border-left: 4px solid #c1272d; }
.delta.fixed { border-left: 4px solid #1a7f37; }
.delta.drifted { border-left: 4px solid #d08700; }
.delta.changed { border-left: 4px solid #bbb; }
.delta h3 { margin: 0 0 .4rem; font-size: 1.05rem; }
.transition { font-weight: 700; }
table.added caption, table.removed caption { text-align: left; font-weight: 600; font-size: .85rem; padding: .2rem 0; }
table.added caption { color: #c1272d; } table.removed caption { color: #1a7f37; }
@media (prefers-color-scheme: dark) {
  .delta { border-color: #2d2e33; }
  table.added caption { color: #ff6b70; } table.removed caption { color: #4ac36a; }
}
"""
)


def _render_delta_html(delta, category: str) -> str:
    rule = delta.rule
    body = [
        f"<h3>{escape(rule.title)}</h3>",
        (
            f"<dl><dt>Rule</dt><dd><code>{escape(rule.id)}</code> · "
            f"{escape(rule.severity)}</dd>"
        ),
        f"<dt>Controls</dt><dd>{escape(', '.join(rule.controls) or '—')}</dd>",
        f"<dt>Change</dt><dd class='transition'>{escape(_transition(delta))}</dd>",
    ]
    if delta.new_reason:
        body.append(f"<dt>Now</dt><dd>{escape(delta.new_reason)}</dd>")
    if category == REGRESSED and rule.remediation:
        body.append(f"<dt>Remediation</dt><dd>{escape(rule.remediation.strip())}</dd>")
    body.append("</dl>")
    if delta.evidence_added:
        body.append(_html_table(delta.evidence_added, "Newly failing rows", "added"))
    if delta.evidence_removed:
        body.append(
            _html_table(delta.evidence_removed, "No longer failing rows", "removed")
        )
    return f"<div class='delta {category}'>{''.join(body)}</div>"


def _render_html(diff: DiffReport) -> str:
    counts = diff.counts
    parts: list[str] = []
    parts.append(
        f"<h1>Evidence Drift — {escape(diff.current.subject)} "
        f"({escape(diff.current.platform)})</h1>"
    )
    parts.append(
        f"<p class='meta'>Baseline <code>{escape(diff.baseline.path.name)}</code> → "
        f"Current <code>{escape(diff.current.path.name)}</code> · "
        f"Generated {escape(diff.generated_at)}</p>"
    )
    parts.append(
        "<p class='summary-pills'>"
        f"<span>{counts[REGRESSED]} regressed</span>"
        f"<span>{counts[FIXED]} fixed</span>"
        f"<span>{counts[DRIFTED]} drifted</span>"
        f"<span>{counts[CHANGED]} changed</span>"
        f"<span>{counts[UNCHANGED]} unchanged</span></p>"
    )
    parts.append(
        "<p class='note'>A <strong>regression</strong> means a setting moved into "
        "a state that no longer supports a control since the baseline. As always "
        "this is evidence, not a verdict.</p>"
    )

    for category in CATEGORY_ORDER:
        rows = diff.by_category(category)
        if not rows or category == UNCHANGED:
            continue
        parts.append(f"<h2>{escape(_CATEGORY_HEADING[category])}</h2>")
        for delta in rows:
            parts.append(_render_delta_html(delta, category))

    if counts[UNCHANGED]:
        parts.append(f"<p class='meta'>{counts[UNCHANGED]} rule(s) unchanged.</p>")
    parts.append("<footer>Generated by audit-report · Audit Labs · evidence, not a verdict.</footer>")

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>Evidence Drift — {escape(diff.current.subject)}</title>"
        f"<style>{_DIFF_CSS}</style></head><body><main>{''.join(parts)}</main></body></html>\n"
    )


def _render_json(diff: DiffReport) -> str:
    payload = {
        "subject": diff.current.subject,
        "platform": diff.current.platform,
        "baseline_package": diff.baseline.path.name,
        "current_package": diff.current.path.name,
        "generated_at": diff.generated_at,
        "summary": diff.counts,
        "deltas": [
            {
                "id": d.rule.id,
                "title": d.rule.title,
                "severity": d.rule.severity,
                "controls": d.rule.controls,
                "category": d.category,
                "old_status": d.old_status,
                "new_status": d.new_status,
                "evidence_added": d.evidence_added,
                "evidence_removed": d.evidence_removed,
            }
            for d in diff.deltas
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


_RENDERERS = {"md": _render_md, "html": _render_html, "json": _render_json}


def render(diff: DiffReport, fmt: str) -> str:
    """Render a diff in the named format ('md', 'html', or 'json')."""
    try:
        return _RENDERERS[fmt](diff)
    except KeyError:
        raise ValueError(f"unknown format: {fmt!r}") from None
