"""Tests for package loading and platform detection."""

from pathlib import Path

import pytest

from audit_report.loader import detect_platform, load_package

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("dir_name", "platform", "subject"),
    [
        ("aws_audit_default_2026-07-29", "aws", "default"),
        ("github_audit_audit-labs_2026-07-29", "github", "audit-labs"),
        ("gitlab_audit_my_group_2026-01-01", "gitlab", "my_group"),
        ("something_else", "unknown", "something_else"),
    ],
)
def test_detect_platform(dir_name, platform, subject):
    assert detect_platform(dir_name) == (platform, subject)


def test_load_package_reads_tables():
    pkg = load_package(FIXTURES / "aws_audit_acme_2026-01-01")
    assert pkg.platform == "aws"
    assert pkg.subject == "acme"
    assert pkg.has("iam_users")
    assert len(pkg.table("iam_users")) == 2
    assert pkg.table("iam_users")[0]["user"] == "alice"
    # Present-but-empty CSV is a known-empty table, not an absent one.
    assert pkg.has("s3_public_access")
    assert pkg.table("s3_public_access") == []
    # Absent table returns empty list, reports as not present.
    assert not pkg.has("nonexistent")
    assert pkg.table("nonexistent") == []


def test_load_missing_directory_raises():
    with pytest.raises(FileNotFoundError):
        load_package(FIXTURES / "does-not-exist")


def test_load_directory_without_csvs_raises(tmp_path):
    with pytest.raises(ValueError, match="no CSV files"):
        load_package(tmp_path)
