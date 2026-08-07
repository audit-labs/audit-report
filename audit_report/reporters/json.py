"""JSON renderer — a machine-readable record of the same findings.

Useful for feeding results into a dashboard, a ticket pipeline, or a diff
between two audit runs.
"""

from __future__ import annotations

import json as _json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import Report


def to_dict(report: Report) -> dict:
    """Serialize a report to a plain dict (stable key order for diffing)."""
    pkg = report.package
    return {
        "subject": pkg.subject,
        "platform": pkg.platform,
        "source_package": pkg.path.name,
        "generated_at": report.generated_at,
        "tool": report.provenance["tool"],
        "ruleset": report.provenance["ruleset"],
        "summary": report.counts,
        "coverage": report.coverage,
        "findings": [
            {
                "id": f.rule.id,
                "title": f.rule.title,
                "status": f.status,
                "severity": f.rule.severity,
                "controls": f.rule.controls,
                "reason": f.reason,
                "evidence": f.evidence,
            }
            for f in report.findings
        ],
    }


def render(report: Report) -> str:
    return _json.dumps(to_dict(report), indent=2, sort_keys=False) + "\n"
