"""Tests for diff mode: status transitions, evidence drift, and the CLI."""

import json
from pathlib import Path

from audit_report import diff
from audit_report.cli import main
from audit_report.engine import evaluate
from audit_report.loader import load_package
from audit_report.rules import load_ruleset

FIXTURES = Path(__file__).parent / "fixtures"
RULESETS = Path("audit_report/rulesets")

BASELINE = FIXTURES / "aws_audit_acme_2025-12-01"
CURRENT = FIXTURES / "aws_audit_acme_2026-01-01"


def _build():
    ruleset = load_ruleset(RULESETS / "aws.yaml")
    old = load_package(BASELINE)
    new = load_package(CURRENT)
    return diff.build_diff(
        old, new, evaluate(old, ruleset), evaluate(new, ruleset)
    )


def test_diff_categories():
    report = _build()
    by_id = {d.rule.id: d for d in report.deltas}

    # Password policy was strong in the baseline, weak now -> regressed.
    assert by_id["aws.iam.password-policy"].category == diff.REGRESSED
    # Root MFA was off in the baseline, on now -> fixed.
    assert by_id["aws.root.mfa"].category == diff.FIXED
    # Open SSH fails in both, but on a different security group -> drifted.
    ssh = by_id["aws.network.no-open-ssh"]
    assert ssh.category == diff.DRIFTED
    assert ssh.evidence_added[0]["group_name"] == "web"
    assert ssh.evidence_removed[0]["group_name"] == "legacy"
    # Bob still lacks MFA with the same evidence in both -> unchanged.
    assert by_id["aws.iam.console-mfa"].category == diff.UNCHANGED


def test_diff_counts():
    counts = _build().counts
    assert counts[diff.REGRESSED] == 1
    assert counts[diff.FIXED] == 1
    assert counts[diff.DRIFTED] == 1


def test_has_regression_respects_threshold():
    report = _build()
    # The regression (password policy) is medium severity.
    assert diff.has_regression(report, "none") is False
    assert diff.has_regression(report, "medium") is True
    assert diff.has_regression(report, "high") is False  # nothing high regressed


def test_diff_render_markdown():
    md = diff.render(_build(), "md")
    assert "# Evidence Drift — acme" in md
    assert "Regressions" in md
    assert "Newly failing rows" in md


def test_diff_render_html_self_contained():
    html = diff.render(_build(), "html")
    assert html.startswith("<!doctype html>")
    assert "http://" not in html
    assert "https://" not in html
    assert "Evidence Drift" in html


def test_diff_render_json():
    data = json.loads(diff.render(_build(), "json"))
    cats = {d["id"]: d["category"] for d in data["deltas"]}
    assert cats["aws.root.mfa"] == "fixed"
    assert data["baseline_package"] == "aws_audit_acme_2025-12-01"


def test_cli_diff_mode(tmp_path):
    out = tmp_path / "out"
    code = main(
        [
            str(CURRENT),
            "--baseline",
            str(BASELINE),
            "--format",
            "md,html,json",
            "--out",
            str(out),
            "--fail-on",
            "medium",
        ]
    )
    assert (out / "diff.md").exists()
    assert (out / "diff.html").exists()
    assert (out / "diff.json").exists()
    # A medium-severity regression is present -> non-zero exit.
    assert code == 1


def test_cli_diff_platform_mismatch_returns_2():
    code = main(
        [
            str(FIXTURES / "github_audit_acme_2026-01-01"),
            "--baseline",
            str(BASELINE),
            "--format",
            "json",
        ]
    )
    assert code == 2
