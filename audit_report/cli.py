"""Command-line entry point for audit-report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, diff, reporters
from .engine import FAIL, evaluate
from .loader import load_package
from .rules import load_ruleset

# Bundled rulesets ship inside the package, one per platform.
_RULESET_DIR = Path(__file__).resolve().parent / "rulesets"

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def _default_ruleset(platform: str) -> Path:
    candidate = _RULESET_DIR / f"{platform}.yaml"
    if not candidate.exists():
        raise SystemExit(
            f"error: no bundled ruleset for platform '{platform}'. "
            f"Pass one with --ruleset. Available: "
            f"{', '.join(p.stem for p in sorted(_RULESET_DIR.glob('*.yaml'))) or 'none'}"
        )
    return candidate


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="audit-report",
        description="Turn an audit-tools evidence package into a control-mapped report.",
    )
    parser.add_argument("package", help="path to an audit-tools output package directory")
    parser.add_argument(
        "--baseline",
        help="path to an earlier package; diff mode reports how PACKAGE drifted from it",
    )
    parser.add_argument(
        "--ruleset",
        help="path to a ruleset YAML (default: bundled ruleset for the detected platform)",
    )
    parser.add_argument(
        "--format",
        default="md",
        help="comma-separated output formats: md, html, json (default: md)",
    )
    parser.add_argument(
        "--out",
        help="directory to write report files into (default: print Markdown to stdout)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "none"],
        default="none",
        help=(
            "exit non-zero if any finding fails (or, in diff mode, regresses) at or "
            "above this severity (default: none)"
        ),
    )
    parser.add_argument("--version", action="version", version=f"audit-report {__version__}")
    return parser.parse_args(argv)


def _exit_code(findings, threshold: str) -> int:
    if threshold == "none":
        return 0
    floor = _SEVERITY_ORDER[threshold]
    breached = any(
        f.status == FAIL and _SEVERITY_ORDER.get(f.rule.severity, 1) >= floor
        for f in findings
    )
    return 1 if breached else 0


def _emit(render_one, formats: list[str], out: str | None, basename: str) -> None:
    """Write one file per format into *out*, or print the first to stdout."""
    if out:
        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for fmt in formats:
            dest = out_dir / f"{basename}.{reporters.EXTENSIONS[fmt]}"
            dest.write_text(render_one(fmt), encoding="utf-8")
            print(f"wrote {dest}", file=sys.stderr)
    else:
        print(render_one(formats[0]), end="")


def _run_diff(args, package, ruleset, formats: list[str]) -> int:
    try:
        baseline = load_package(args.baseline)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if baseline.platform != package.platform:
        print(
            f"error: cannot diff a {baseline.platform} package against a "
            f"{package.platform} package",
            file=sys.stderr,
        )
        return 2

    old = evaluate(baseline, ruleset)
    new = evaluate(package, ruleset)
    report = diff.build_diff(baseline, package, old, new)

    _emit(lambda fmt: diff.render(report, fmt), formats, args.out, "diff")

    counts = report.counts
    print(
        f"{package.platform}/{package.subject}: "
        f"{counts[diff.REGRESSED]} regressed, {counts[diff.FIXED]} fixed, "
        f"{counts[diff.DRIFTED]} drifted",
        file=sys.stderr,
    )
    return 1 if diff.has_regression(report, args.fail_on) else 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    unknown = [f for f in formats if f not in reporters.EXTENSIONS]
    if not formats or unknown:
        print(f"error: unknown format(s): {', '.join(unknown) or '(none given)'}", file=sys.stderr)
        return 2

    try:
        package = load_package(args.package)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ruleset_path = Path(args.ruleset) if args.ruleset else _default_ruleset(package.platform)
    ruleset = load_ruleset(ruleset_path)

    if args.baseline:
        return _run_diff(args, package, ruleset, formats)

    findings = evaluate(package, ruleset)
    report = reporters.build_report(package, findings)
    _emit(lambda fmt: reporters.render(report, fmt), formats, args.out, "report")

    counts = report.counts
    print(
        f"{package.platform}/{package.subject}: "
        f"{counts[FAIL]} failing, {counts['pass']} passing, "
        f"{counts['not_applicable']} n/a",
        file=sys.stderr,
    )
    return _exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
