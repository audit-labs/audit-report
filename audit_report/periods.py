"""Row-level period checks for rules that declare a timestamp column (ruleset schema 2).

Evidence for a test period should be dated inside it and should not leave long
stretches with no rows (a log that stops for three weeks, a ticket export that
skips a month). :func:`check` reports, for one table and one period, which rows
fall outside it, which rows have no readable date, and the gaps longer than
``max_gap_days`` between the period start, each dated row, and the period end.

Multi-table logic (joins across packages) is not part of the rule schema; it
is done by analytics whose outputs are ordinary tables that rules evaluate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta


@dataclass
class PeriodCheck:
    column: str
    start: str
    end: str
    rows_in_period: int = 0
    outside: list[dict] = field(default_factory=list)  # {"row": index, "date": value}
    undated: list[int] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)  # {"from", "to", "days"}
    first: str = ""
    last: str = ""

    @property
    def ok(self) -> bool:
        return not self.outside and not self.undated and not self.gaps


def _date(value: str) -> date | None:
    text = str(value or "").strip()[:10]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def check(rows: list[dict], column: str, start: str, end: str, max_gap_days: int | None = None) -> PeriodCheck:
    """Check that ``rows`` are dated by ``column`` within ``start``..``end`` (inclusive)."""
    p_start, p_end = date.fromisoformat(start), date.fromisoformat(end)
    result = PeriodCheck(column=column, start=start, end=end)
    dated: list[date] = []
    for i, row in enumerate(rows):
        d = _date(row.get(column, ""))
        if d is None:
            result.undated.append(i)
        elif d < p_start or d > p_end:
            result.outside.append({"row": i, "date": d.isoformat()})
        else:
            dated.append(d)
    result.rows_in_period = len(dated)
    if dated:
        result.first, result.last = min(dated).isoformat(), max(dated).isoformat()
    if max_gap_days:
        # Runs of consecutive days in the period with no rows; a sentinel past each edge.
        prev = p_start - timedelta(days=1)
        for d in [*sorted(set(dated)), p_end + timedelta(days=1)]:
            empty = (d - prev).days - 1
            if empty > max_gap_days:
                first_empty, last_empty = prev + timedelta(days=1), d - timedelta(days=1)
                result.gaps.append({"from": first_empty.isoformat(), "to": last_empty.isoformat(), "days": empty})
            prev = d
    return result
