# Running audit-report in CI

The pattern is always the same three steps:

1. **Collect** an evidence package with `audit-tools` (per-platform CLI).
2. **Report** on it with `audit-report`, writing `md`/`html`/`json` artifacts.
3. **Gate** the pipeline with `--fail-on` so a control regression can block a
   merge or page a scheduled run.

Ready-to-copy starting points:

- [`examples/github-actions-audit.yml`](../examples/github-actions-audit.yml)
- [`examples/gitlab-ci-audit.yml`](../examples/gitlab-ci-audit.yml)

> `audit-tools` is not on PyPI — it is a set of per-platform scripts. Check the
> repo out (or clone it) and run `applications/<platform>/audit.py` directly;
> Python puts the script's own directory on `sys.path`, so no `cd` is needed.
> Pass an absolute `--out` so every platform's package lands in one folder.
> Everything downstream only needs the
> `<out>/<platform>_audit_<subject>_<date>/` directory it writes.

## Exact collection commands

Install `audit-tools`' dependencies once (`pip install -r audit-tools/requirements.txt`),
export the platform's credentials, then:

```bash
# AWS — credentials come from the standard AWS chain (env vars, profile, OIDC role)
python audit-tools/applications/aws/audit.py --out "$PWD/output"

# GitHub — needs GITHUB_TOKEN (read-only) in the environment
python audit-tools/applications/github/audit.py --org "$ORG" --out "$PWD/output"

# GitLab — needs GITLAB_TOKEN (read_api) in the environment
python audit-tools/applications/gitlab/audit.py \
  --group "$GROUP" --url "$API_V4_URL" --out "$PWD/output"
```

## Gating strategies

**Snapshot gate — the current state must be clean.**

```bash
audit-report "$PKG" --fail-on high
```

Exits non-zero if any high-severity control is unsupported in the newest
package. Simple and strict; good for a scheduled run that should stay green.

**Regression gate — this change must not make things worse.**

Keep the previous package in the repo (or restore it from an artifact) and diff
against it. The build fails only when a control that used to pass now fails,
which avoids blocking on pre-existing debt.

```bash
audit-report "$PKG" --baseline ./baseline/"$LAST_PKG" --fail-on high
```

**Trend artifact — show direction over time.**

Point trend mode at a folder of retained packages to publish a heatmap of every
control across dates. Its `--fail-on` reflects the latest package, so it can
double as a snapshot gate while producing the timeline artifact.

```bash
audit-report ./history --trend --format html,json --out ./trend
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran successfully; no `--fail-on` threshold was breached. |
| `1` | A finding (or, in diff mode, a regression) met the `--fail-on` severity. |
| `2` | Usage or input error (missing package, unknown format, mismatched platforms). |

Distinguishing `1` from `2` lets a workflow tell "the audit found a problem"
(expected, actionable) from "the job is misconfigured" (fix the pipeline).

## Retaining history

`audit-report` never writes back to the package — it only reads. To build a
trend or a regression baseline, archive each run's package directory (a CI
artifact, a committed `history/` folder, or object storage) and feed the
collection back in on the next run.
