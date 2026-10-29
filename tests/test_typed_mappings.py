"""Typed control mappings in rules and JSON reports."""

import json
from pathlib import Path

import pytest

from audit_report import engine, loader, reporters
from audit_report.rules import load_ruleset

RULESET = """
platform: aws
rules:
  - id: aws.iam.mfa
    title: MFA
    table: iam_users
    controls:
      - SOC2:CC6.1
      - {control: ISO:A.5.17, relationship: partial, rationale: covers MFA only, source: firm 2026}
    check: {type: fail_rows_where, when: {column: mfa_enabled, op: is_false}}
"""


def test_mappings_parse_and_reach_json(tmp_path: Path):
    rs_path = tmp_path / "aws.yaml"
    rs_path.write_text(RULESET)
    rs = load_ruleset(rs_path)
    assert rs.rules[0].controls == ["SOC2:CC6.1", "ISO:A.5.17"]
    assert rs.rules[0].control_mappings == {"ISO:A.5.17": {"relationship": "partial", "rationale": "covers MFA only", "source": "firm 2026"}}
    pkg_dir = tmp_path / "aws_audit_prod_2026-07-01"
    pkg_dir.mkdir()
    (pkg_dir / "iam_users.csv").write_text("user,mfa_enabled\na,True\n")
    pkg = loader.load_package(pkg_dir)
    report = reporters.build_report(pkg, engine.evaluate(pkg, rs), rs)
    finding = json.loads(reporters.render(report, "json"))["findings"][0]
    assert finding["controls"] == ["SOC2:CC6.1", "ISO:A.5.17"]
    assert finding["control_mappings"]["ISO:A.5.17"]["relationship"] == "partial"


def test_bad_mappings_are_refused(tmp_path: Path):
    path = tmp_path / "r.yaml"
    path.write_text(RULESET.replace("relationship: partial", "relationship: intersects"))
    with pytest.raises(ValueError, match="full or partial"):
        load_ruleset(path)
    path.write_text(RULESET.replace("{control: ISO:A.5.17,", "{"))
    with pytest.raises(ValueError, match="needs 'control'"):
        load_ruleset(path)
