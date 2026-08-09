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
from html import escape

from .engine import FAIL, Finding
from .loader import Package
from .reporters.html import CSS as _CSS

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


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

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
    import json as _json

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
    return _json.dumps(payload, indent=2) + "\n"


_RENDERERS = {"md": _render_md, "html": _render_html, "json": _render_json}


def render(diff: DiffReport, fmt: str) -> str:
    """Render a diff in the named format ('md', 'html', or 'json')."""
    try:
        return _RENDERERS[fmt](diff)
    except KeyError:
        raise ValueError(f"unknown format: {fmt!r}") from None
