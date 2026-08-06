"""Report renderers. Each takes a :class:`Report` and returns a string."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ..engine import Finding, control_coverage, summarize
from ..loader import Package
from . import html as _html
from . import json as _json
from . import markdown as _markdown


@dataclass
class Report:
    """Everything a renderer needs: the package, findings, and rollups."""

    package: Package
    findings: list[Finding]
    generated_at: str

    @property
    def counts(self) -> dict[str, int]:
        return summarize(self.findings)

    @property
    def coverage(self) -> dict[str, dict]:
        return control_coverage(self.findings)


def build_report(package: Package, findings: list[Finding]) -> Report:
    """Assemble a :class:`Report` with a UTC generation timestamp."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return Report(package=package, findings=findings, generated_at=stamp)


RENDERERS = {
    "md": _markdown.render,
    "html": _html.render,
    "json": _json.render,
}

# File extension per format (md and markdown both write .md).
EXTENSIONS = {"md": "md", "html": "html", "json": "json"}


def render(report: Report, fmt: str) -> str:
    """Render *report* in the named format ('md', 'html', or 'json')."""
    try:
        return RENDERERS[fmt](report)
    except KeyError:
        raise ValueError(f"unknown format: {fmt!r}") from None
