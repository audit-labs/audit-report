"""Tests for rule evaluation against fixture packages, using bundled rulesets."""

from pathlib import Path

from audit_report.engine import (
    FAIL,
    NOT_APPLICABLE,
    PASS,
    control_coverage,
    evaluate,
    summarize,
)
from audit_report.loader import load_package
from audit_report.rules import load_ruleset

FIXTURES = Path(__file__).parent / "fixtures"
RULESETS = Path("audit_report/rulesets")


def _run(pkg_name, ruleset_name):
    pkg = load_package(FIXTURES / pkg_name)
    ruleset = load_ruleset(RULESETS / ruleset_name)
    findings = evaluate(pkg, ruleset)
    return {f.rule.id: f for f in findings}


def test_aws_fixture_findings():
    findings = _run("aws_audit_acme_2026-01-01", "aws.yaml")

    # bob has a console password and no MFA -> one failing row.
    mfa = findings["aws.iam.console-mfa"]
    assert mfa.status == FAIL
    assert len(mfa.evidence) == 1
    assert mfa.evidence[0]["user"] == "bob"

    # bob's key is 400 days old.
    assert findings["aws.iam.key-rotation"].status == FAIL

    # Root is healthy in the fixture.
    assert findings["aws.root.mfa"].status == PASS
    assert findings["aws.root.no-access-keys"].status == PASS

    # min length 8 < 14 -> policy fails.
    assert findings["aws.iam.password-policy"].status == FAIL

    # Only the port-22 group is open to the world.
    ssh = findings["aws.network.no-open-ssh"]
    assert ssh.status == FAIL
    assert len(ssh.evidence) == 1
    assert ssh.evidence[0]["group_name"] == "web"

    # Empty s3_public_access table means no public buckets -> pass.
    assert findings["aws.s3.no-public-access"].status == PASS

    # A healthy multi-region trail exists.
    assert findings["aws.cloudtrail.logging"].status == PASS


def test_github_fixture_findings():
    findings = _run("github_audit_acme_2026-01-01", "github.yaml")
    assert findings["github.org.require-2fa"].status == PASS
    assert findings["github.org.default-permission"].status == PASS
    assert findings["github.org.secret-scanning"].status == PASS
    # 'site' repo default branch is unprotected.
    branch = findings["github.branch.default-protected"]
    assert branch.status == FAIL
    assert branch.evidence[0]["repo"] == "site"
    # 'app' has 1 review, 'site' is unprotected -> require-reviews passes
    # (only counts protected branches with < 1 review).
    assert findings["github.branch.require-reviews"].status == PASS


def test_not_applicable_when_table_absent(tmp_path):
    (tmp_path / "aws_audit_x_2026-01-01").mkdir()
    pkg_dir = tmp_path / "aws_audit_x_2026-01-01"
    (pkg_dir / "iam_users.csv").write_text(
        "user,mfa_enabled,console_password,oldest_key_age_days\n", encoding="utf-8"
    )
    pkg = load_package(pkg_dir)
    findings = {f.rule.id: f for f in evaluate(pkg, load_ruleset(RULESETS / "aws.yaml"))}
    # Tables that were never collected are reported as not applicable.
    assert findings["aws.root.mfa"].status == NOT_APPLICABLE


def test_summary_and_coverage():
    pkg = load_package(FIXTURES / "aws_audit_acme_2026-01-01")
    findings = evaluate(pkg, load_ruleset(RULESETS / "aws.yaml"))
    counts = summarize(findings)
    assert counts[FAIL] + counts[PASS] + counts[NOT_APPLICABLE] == len(findings)

    coverage = control_coverage(findings)
    # SC-7 is cited by the open-SSH rule (fails), so the control rolls up to fail.
    assert coverage["NIST:SC-7"]["status"] == FAIL
    # A control cited only by passing rules (both root checks) rolls up to pass.
    assert coverage["ISO:A.8.2"]["status"] == PASS
