"""Tests for the report renderers and the CLI entry point."""

import json
from pathlib import Path

import pytest

from audit_report import __version__, reporters
from audit_report.cli import main
from audit_report.engine import evaluate
from audit_report.loader import load_package
from audit_report.rules import load_ruleset

FIXTURES = Path(__file__).parent / "fixtures"
RULESETS = Path("audit_report/rulesets")


def _report(pkg_name="aws_audit_acme_2026-01-01", ruleset="aws.yaml"):
    pkg = load_package(FIXTURES / pkg_name)
    rs = load_ruleset(RULESETS / ruleset)
    findings = evaluate(pkg, rs)
    return reporters.build_report(pkg, findings, rs)


def test_markdown_render_contains_sections():
    md = reporters.render(_report(), "md")
    assert "# Evidence Report — acme" in md
    assert "## Control coverage" in md
    assert "## Findings" in md
    assert "aws.network.no-open-ssh" in md


def test_html_render_is_self_contained():
    html = reporters.render(_report(), "html")
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    # No external resource references.
    assert "http://" not in html
    assert "https://" not in html
    assert "src=" not in html


def test_json_render_roundtrips():
    data = json.loads(reporters.render(_report(), "json"))
    assert data["platform"] == "aws"
    assert data["subject"] == "acme"
    ids = {f["id"]: f["status"] for f in data["findings"]}
    assert ids["aws.iam.console-mfa"] == "fail"


def test_json_stamps_tool_and_ruleset_provenance():
    data = json.loads(reporters.render(_report(), "json"))
    assert data["tool"] == {"name": "audit-report", "version": __version__}
    rs = data["ruleset"]
    assert rs["name"] == "AWS ITGC ruleset"
    assert rs["platform"] == "aws"
    assert rs["version"] == "2026.08.0"
    assert len(rs["sha256"]) == 64  # full SHA-256 hex digest of the ruleset file


def test_markdown_shows_ruleset_provenance():
    md = reporters.render(_report(), "md")
    assert "**Tool:** audit-report" in md
    assert "sha256:" in md


def test_html_escapes_evidence(tmp_path):
    pkg_dir = tmp_path / "aws_audit_x_2026-01-01"
    pkg_dir.mkdir()
    (pkg_dir / "open_security_groups.csv").write_text(
        "region,group_id,group_name,protocol,from_port,to_port,open_to\n"
        "us-east-1,sg-1,<script>x</script>,tcp,22,22,0.0.0.0/0\n",
        encoding="utf-8",
    )
    pkg = load_package(pkg_dir)
    report = reporters.build_report(pkg, evaluate(pkg, load_ruleset(RULESETS / "aws.yaml")))
    html = reporters.render(report, "html")
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_unknown_format_raises():
    report = _report()
    with pytest.raises(ValueError, match="unknown format"):
        reporters.render(report, "pdf")


def test_cli_writes_files_and_exit_code(tmp_path):
    out = tmp_path / "out"
    code = main(
        [
            str(FIXTURES / "aws_audit_acme_2026-01-01"),
            "--format",
            "md,html,json",
            "--out",
            str(out),
            "--fail-on",
            "high",
        ]
    )
    assert (out / "report.md").exists()
    assert (out / "report.html").exists()
    assert (out / "report.json").exists()
    # The AWS fixture has high-severity failures (open SSH), so exit is non-zero.
    assert code == 1


def test_cli_fail_on_none_is_zero(tmp_path):
    code = main(
        [str(FIXTURES / "aws_audit_acme_2026-01-01"), "--format", "json", "--out", str(tmp_path)]
    )
    assert code == 0


def test_cli_missing_package_returns_2():
    assert main([str(FIXTURES / "nope")]) == 2
