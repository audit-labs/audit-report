"""Tests for trend mode: discovery, timeline building, rendering, and the CLI."""

import json
from pathlib import Path

import pytest

from audit_report import trend
from audit_report.cli import main
from audit_report.engine import FAIL, PASS, evaluate
from audit_report.loader import load_package
from audit_report.rules import load_ruleset

FIXTURES = Path(__file__).parent / "fixtures"
SERIES = FIXTURES / "series"
RULESETS = Path("audit_report/rulesets")


def _build():
    platform, _subject, paths = trend.discover(SERIES)
    ruleset = load_ruleset(RULESETS / f"{platform}.yaml")
    packages = [load_package(p) for p in paths]
    findings = [evaluate(pkg, ruleset) for pkg in packages]
    return trend.build_trend(packages, findings)


def test_discover_orders_by_date():
    platform, subject, paths = trend.discover(SERIES)
    assert (platform, subject) == ("aws", "prod")
    assert [p.name for p in paths] == [
        "aws_audit_prod_2026-01-01",
        "aws_audit_prod_2026-02-01",
        "aws_audit_prod_2026-03-01",
    ]


def test_discover_rejects_mixed_series():
    # The fixtures root holds aws/github/gitlab packages for several subjects.
    with pytest.raises(ValueError, match="multiple series"):
        trend.discover(FIXTURES)


def test_discover_requires_two(tmp_path):
    # A parent directory holding a single package is not a trend.
    pkg = tmp_path / "aws_audit_solo_2026-01-01"
    pkg.mkdir()
    (pkg / "account_security.csv").write_text("root_mfa_enabled\nTrue\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at least two"):
        trend.discover(tmp_path)


def test_discover_no_packages(tmp_path):
    with pytest.raises(ValueError, match="no audit-tools packages"):
        trend.discover(tmp_path)


def test_trend_timeline_and_totals():
    report = _build()
    assert report.dates == ["2026-01-01", "2026-02-01", "2026-03-01"]
    assert report.fails_per_date() == [8, 3, 0]

    by_id = {row.rule.id: row for row in report.rows}
    # Root MFA: fail, then fixed and stays fixed.
    assert by_id["aws.root.mfa"].statuses == [FAIL, PASS, PASS]
    # Access-key rotation lags: fixed only in the final package.
    assert by_id["aws.iam.key-rotation"].statuses == [FAIL, FAIL, PASS]


def test_trend_row_transitions():
    report = _build()
    by_id = {row.rule.id: row for row in report.rows}
    assert by_id["aws.root.mfa"].transitions == 1  # one fail->pass change
    assert by_id["aws.s3.no-public-access"].transitions == 1


def test_trend_render_markdown():
    md = trend.render(_build(), "md")
    assert "# Evidence Trend — prod (aws)" in md
    assert "Failing total" in md
    assert "2026-03-01" in md


def test_trend_render_html_self_contained():
    html = trend.render(_build(), "html")
    assert html.startswith("<!doctype html>")
    assert "http://" not in html and "https://" not in html
    assert "class='trend'" in html


def test_trend_render_json():
    data = json.loads(trend.render(_build(), "json"))
    assert data["dates"] == ["2026-01-01", "2026-02-01", "2026-03-01"]
    assert data["fails_per_date"] == [8, 3, 0]
    rules = {r["id"]: r["statuses"] for r in data["rules"]}
    assert rules["aws.root.mfa"] == ["fail", "pass", "pass"]


def test_cli_trend_mode(tmp_path):
    out = tmp_path / "out"
    code = main([str(SERIES), "--trend", "--format", "md,html,json", "--out", str(out)])
    assert (out / "trend.md").exists()
    assert (out / "trend.html").exists()
    assert (out / "trend.json").exists()
    # The latest package is clean, so default --fail-on none exits 0.
    assert code == 0


def test_cli_trend_fail_on_uses_latest(tmp_path):
    # Latest package (2026-03) has no failures, so even --fail-on low passes.
    code = main([str(SERIES), "--trend", "--format", "json", "--out", str(tmp_path), "--fail-on", "low"])
    assert code == 0


def test_cli_trend_and_baseline_conflict():
    assert main([str(SERIES), "--trend", "--baseline", str(SERIES), "--format", "json"]) == 2
