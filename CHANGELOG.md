# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-07

First stable release. The JSON report schema — findings carrying their `controls`
and `pass` / `fail` / `not_applicable` status — is now a committed contract that
[control-coverage](https://github.com/audit-labs/control-coverage) consumes
directly; it will not change in a breaking way without a major-version bump.

## [0.1.0] - 2026-08-06

### Added

- Control-mapped reports from an audit-tools evidence package: declarative YAML
  rulesets map pass/fail results to SOC 2, ISO 27001, and NIST SP 800-53 controls.
- Output as Markdown, self-contained HTML, or JSON; `--fail-on {low,medium,high,none}`
  gate for CI.
- Bundled rulesets for GitHub, GitLab, and AWS evidence.
- Trend mode to diff two evidence packages.
- Tool and ruleset provenance stamped into every report.
- PyPI trusted-publishing release workflow.

[1.0.0]: https://github.com/audit-labs/audit-report/releases/tag/v1.0.0
[0.1.0]: https://github.com/audit-labs/audit-report/releases/tag/v0.1.0
