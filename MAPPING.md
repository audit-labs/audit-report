# Rulesets — provenance and control-mapping rationale

An `audit-report` **ruleset** (`audit_report/rulesets/*.yaml`) turns collected
evidence into control-relevant findings: each rule names a table, a check, and the
control identifiers the signal is offered as evidence *for*. This document records
where those mappings come from and their limits.

## What a mapping claims — and does not

- A rule's `controls` list says: "this signal is relevant to these controls."
- A **fail** means a setting is in a state that does **not** support the control.
  It is not a compliance verdict — the auditor still owns the conclusion.
- The control identifiers (`SOC2:CC6.1`, `ISO:A.5.17`, `NIST:IA-2`, …) are
  reproduced; the frameworks' normative control text is not. See the catalog
  provenance in [control-coverage `MAPPING.md`](https://github.com/audit-labs/control-coverage/blob/main/MAPPING.md).
- The mappings are the **maintainers' interpretation**, not reviewed or endorsed
  by the AICPA, ISO/IEC, or NIST.

## Framework revisions referenced

- **SOC 2** — Trust Services Criteria 2017 (2022 revised points of focus).
- **ISO/IEC 27001** — 27001:2022 Annex A.
- **NIST SP 800-53** — Rev. 5.

## Versioning and traceability

- Each ruleset carries `name` and `version` fields.
- Every report stamps the tool name + version and the ruleset `name`, `version`,
  and a **SHA-256 of the ruleset file** into its output (`tool` / `ruleset` in
  JSON; the header line in Markdown/HTML).
- An auditor can therefore tie any finding back to the exact ruleset that produced
  it, and re-perform against it. Bump `version` on any change to a rule's
  controls, checks, or thresholds.

## Authorship and review

- **Author:** the audit-labs maintainer.
- **Review status:** maintainer self-review; no independent professional review.
  Validate a ruleset against your own control set before relying on it.
- **Effective date:** 2026-08.
