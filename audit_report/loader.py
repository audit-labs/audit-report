"""Load an audit-tools evidence package from disk.

An evidence package is a directory of CSV files produced by audit-tools, named
like ``github_audit_<org>_<date>/`` or ``aws_audit_<profile>_<date>/``. Each CSV
becomes a *table* keyed by its filename stem (``iam_users.csv`` -> ``iam_users``).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

# Directory-name prefixes audit-tools uses, mapped to a platform key.
_PLATFORM_PREFIXES = {
    "aws_audit_": "aws",
    "github_audit_": "github",
    "gitlab_audit_": "gitlab",
}

Row = dict[str, str]
Table = list[Row]


@dataclass
class Package:
    """A loaded evidence package."""

    path: Path
    platform: str
    subject: str  # the org / profile the audit was run against
    tables: dict[str, Table] = field(default_factory=dict)

    def table(self, name: str) -> Table:
        """Return a table by name, or an empty list if it is absent."""
        return self.tables.get(name, [])

    def has(self, name: str) -> bool:
        """True if the named CSV was present in the package."""
        return name in self.tables


def detect_platform(dir_name: str) -> tuple[str, str]:
    """Infer ``(platform, subject)`` from a package directory name.

    ``github_audit_audit-labs_2026-07-29`` -> ``("github", "audit-labs")``.
    Falls back to ``("unknown", <dir_name>)`` when no prefix matches.
    """
    for prefix, platform in _PLATFORM_PREFIXES.items():
        if dir_name.startswith(prefix):
            rest = dir_name[len(prefix) :]
            # Strip a trailing ISO date (…_YYYY-MM-DD) to recover the subject.
            parts = rest.rsplit("_", 1)
            subject = parts[0] if len(parts) == 2 and _looks_like_date(parts[1]) else rest
            return platform, subject or "unknown"
    return "unknown", dir_name


def _looks_like_date(token: str) -> bool:
    bits = token.split("-")
    return len(bits) == 3 and all(b.isdigit() for b in bits)


def load_package(path: str | Path) -> Package:
    """Load every ``*.csv`` in *path* into a :class:`Package`.

    Raises ``FileNotFoundError`` if the directory does not exist and
    ``ValueError`` if it contains no CSV files.
    """
    directory = Path(path)
    if not directory.is_dir():
        raise FileNotFoundError(f"not a directory: {directory}")

    platform, subject = detect_platform(directory.name)
    tables: dict[str, Table] = {}
    for csv_path in sorted(directory.glob("*.csv")):
        with csv_path.open(newline="", encoding="utf-8") as handle:
            tables[csv_path.stem] = list(csv.DictReader(handle))

    if not tables:
        raise ValueError(f"no CSV files found in {directory}")

    return Package(path=directory, platform=platform, subject=subject, tables=tables)
