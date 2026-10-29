"""Row-level period checks (ruleset schema 2)."""

from pathlib import Path

import pytest

from audit_report import periods
from audit_report.rules import load_ruleset

ROWS = [{"at": "2026-07-01T10:00:00Z"}, {"at": "2026-07-03"}, {"at": "2026-07-20"}, {"at": "2026-06-30"}, {"at": "soon"}]


def test_outside_undated_and_gaps():
    res = periods.check(ROWS, "at", "2026-07-01", "2026-07-31", max_gap_days=7)
    assert res.rows_in_period == 3
    assert res.outside == [{"row": 3, "date": "2026-06-30"}]
    assert res.undated == [4]
    assert res.first == "2026-07-01" and res.last == "2026-07-20"
    assert res.gaps == [
        {"from": "2026-07-04", "to": "2026-07-19", "days": 16},
        {"from": "2026-07-21", "to": "2026-07-31", "days": 11},
    ]
    assert not res.ok


def test_no_gap_limit_and_clean_period():
    rows = [{"at": f"2026-07-{d:02d}"} for d in range(1, 32, 3)]
    assert periods.check(rows, "at", "2026-07-01", "2026-07-31", max_gap_days=2).ok
    assert periods.check(rows, "at", "2026-07-01", "2026-07-31").gaps == []
    empty = periods.check([], "at", "2026-07-01", "2026-07-10", max_gap_days=3)
    assert empty.gaps == [{"from": "2026-07-01", "to": "2026-07-10", "days": 10}]


def _ruleset(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "r.yaml"
    path.write_text(body)
    return path


RULE = """
rules:
  - id: x.logs
    title: Logs present
    table: events
    check: {type: fail_if_any_rows, when: {column: level, op: equals, value: error}}
    timestamp: at
    max_gap_days: 3
"""


def test_schema_2_fields(tmp_path):
    rs = load_ruleset(_ruleset(tmp_path, "schema: 2\nplatform: x\n" + RULE))
    assert rs.schema == 2 and rs.rules[0].timestamp == "at" and rs.rules[0].max_gap_days == 3


def test_schema_1_refuses_period_fields(tmp_path):
    with pytest.raises(ValueError, match="need 'schema: 2'"):
        load_ruleset(_ruleset(tmp_path, "platform: x\n" + RULE))
    with pytest.raises(ValueError, match="unsupported ruleset schema"):
        load_ruleset(_ruleset(tmp_path, "schema: 3\nplatform: x\nrules: []\n"))
    with pytest.raises(ValueError, match="positive integer with a timestamp"):
        load_ruleset(_ruleset(tmp_path, "schema: 2\nplatform: x\n" + RULE.replace("max_gap_days: 3", "max_gap_days: 0")))
