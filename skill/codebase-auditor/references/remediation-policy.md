# Remediation Policy

Use this reference before editing files in response to an audit finding.

## Rules

- Do not edit files during report-only audit requests.
- Require explicit user intent for fixes, optimization, security hardening, refactoring, or remediation.
- Require a concrete finding ID for CLI-driven fixes.
- Fix one finding, or one tightly related group, per patch.
- Preserve public APIs, data shape, auth checks, tenancy boundaries, ordering, pagination, and error behavior.
- Add or update focused tests when feasible.
- Run the narrowest relevant verification first, then broader build, lint, or test commands if available.

## Patch Selection

Prefer findings with:

- High confidence.
- Small estimated effort.
- Clear local behavior.
- Existing tests or an easy focused test path.

Avoid autonomous fixes when:

- The change affects security policy, authorization, persistence semantics, distributed ordering, or public contracts.
- The scanner cannot prove equivalence.
- The optimization depends on production data characteristics that are not visible in the repository.

## Mechanical Autofix Boundaries

The CLI may apply only explicitly supported low-risk mechanical fixes. In the current release, that means a Python loop membership check against a single-line literal list or tuple of unique string constants. The fix may hoist the literal to a set before the loop because string membership semantics are preserved and lookup becomes average O(1).

Do not mechanically rewrite:

- Duplicate-sensitive, order-sensitive, or mutation-sensitive code.
- Membership lists containing non-string values, variables, calls, dicts, lists, or sets.
- Multi-line literals, comments inside literals, or code with an existing generated variable name collision.
- Findings outside the supported fix kind; report a remediation plan instead.

## Closeout

Report changed files, commands run, before/after evidence when available, and residual risk.
