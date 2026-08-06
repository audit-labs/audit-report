# audit-report

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()

Turns an [audit-tools](https://github.com/audit-labs/audit-tools) evidence
package into a control-mapped, auditor-ready report — Markdown, self-contained
HTML, or JSON — driven by declarative rulesets.

`audit-tools` collects raw CSVs (IAM users, branch protections, security
groups…). `audit-report` reads that package, applies pass/fail rules, maps each
result to **SOC 2, ISO 27001, and NIST SP 800-53** controls, and produces a
report you can hand to an auditor or gate a pipeline on.

> Like [gh-attest](https://github.com/audit-labs/gh-attest), this tool produces
> *evidence*, not a compliance verdict. A failing row means a setting is in a
> state that does not support a control; the final judgment belongs to the
> organization and its auditor.

## Install

```bash
git clone https://github.com/audit-labs/audit-report
cd audit-report
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

Point it at a package directory produced by `audit-tools`:

```bash
# Markdown report to stdout (platform + ruleset auto-detected from the dir name)
audit-report ./output/aws_audit_default_2026-07-29

# All three formats into ./report/
audit-report ./output/github_audit_acme_2026-07-29 --format md,html,json --out report/

# Gate CI: exit non-zero if any high-severity check fails
audit-report ./output/aws_audit_prod_2026-07-29 --fail-on high --out report/
```

### Diff mode — compare two packages

Pass `--baseline` to report how a package **drifted** from an earlier one. Both
are evaluated with the same ruleset; the report classifies each rule as
regressed, fixed, drifted (an ongoing failure whose evidence rows changed),
changed, or unchanged — and shows exactly which evidence rows appeared or
disappeared.

```bash
# How did prod change between two audit runs?
audit-report ./output/aws_audit_prod_2026-07-29 \
  --baseline ./output/aws_audit_prod_2026-06-29 \
  --format md,html --out drift/

# Fail CI if this change regressed any high-severity control
audit-report ./output/aws_audit_prod_2026-07-29 \
  --baseline ./output/aws_audit_prod_2026-06-29 --fail-on high
```

In diff mode `--fail-on` gates on **regressions** at or above the given
severity, and output files are named `diff.*` instead of `report.*`.

You can also run it without installing:

```bash
python -m audit_report ./output/aws_audit_default_2026-07-29
```

### Options

| Flag | Description |
| --- | --- |
| `--baseline PATH` | Diff mode: report how `PACKAGE` drifted from this earlier package. |
| `--ruleset PATH` | Use a specific ruleset instead of the bundled one for the detected platform. |
| `--format md,html,json` | One or more output formats (default: `md`). |
| `--out DIR` | Write `report.<ext>` files into `DIR`. Without it, the first format prints to stdout. |
| `--fail-on low\|medium\|high\|none` | Exit non-zero when a failing finding — or, in diff mode, a regression — meets this severity (default: `none`). |

## What a report contains

- **Summary** — failing / passing / not-applicable counts.
- **Control coverage matrix** — every cited control, its framework, and a
  worst-wins status rolled up from the rules that reference it. One failing rule
  marks the control as not fully evidenced.
- **Findings** — failures first, then by severity, each with the reason, why it
  matters, remediation, and the exact evidence rows that failed.

## Bundled rulesets

| Platform | Package prefix | Checks include |
| --- | --- | --- |
| AWS | `aws_audit_*` | Console-user MFA, access-key rotation, root MFA & keys, password policy, open SSH, public S3, CloudTrail logging |
| GitHub | `github_audit_*` | Org 2FA, base permission, secret-scanning push protection, default-branch protection, required reviews |
| GitLab | `gitlab_audit_*` | Force-push on protected branches, code-owner approval, approval-rule strength, public projects, instance password policy, audit logging |

## Writing your own rules

A ruleset is a YAML file: a `platform` and a list of `rules`. Each rule names a
CSV table, a check, the controls it maps to, and human-readable text. Point at
one with `--ruleset`.

```yaml
platform: aws
rules:
  - id: aws.iam.console-mfa
    title: Console users have MFA enabled
    table: iam_users            # <table>.csv inside the package
    severity: high              # high | medium | low
    controls: [SOC2:CC6.1, ISO:A.5.17, NIST:IA-2]
    rationale: A console user without a second factor is one stolen password from access.
    remediation: Enforce MFA for all console users, or remove their console password.
    check:
      type: fail_rows_where     # every matching row is a failure
      when:
        all:
          - {column: console_password, op: is_true}
          - {column: mfa_enabled, op: is_false}
```

**Check types**

| Type | Meaning |
| --- | --- |
| `fail_rows_where` | Each row matching `when` is a failing finding. |
| `fail_if_any_rows` | The presence of any row (optionally filtered by `when`) is a failure. |
| `require_any_row` | Passes only if at least one row satisfies `when`. |
| `assert_row` | Checks each condition in `require` against the first row of a single-row config table. |

**Condition language** — a condition is a leaf `{column, op, value}`, or one of
`{all: [...]}`, `{any: [...]}`, `{not: ...}`. Operators: `equals`, `not_equals`,
`is_true`, `is_false`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `empty`,
`not_empty`. Control codes referenced by a rule must exist in
[`audit_report/catalog.py`](audit_report/catalog.py).

## Development

```bash
pip install -e ".[dev]"
pytest        # run from the project root
ruff check .
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
