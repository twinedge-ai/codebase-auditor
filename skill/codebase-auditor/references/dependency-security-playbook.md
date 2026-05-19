# Dependency And Security Playbook

Use this reference for dependency inventory, vulnerability review, secret leads, and static security leads.

## Dependency Review

- Treat OSV and external tool findings as actionable leads; verify exploitability against the app's runtime path before recommending emergency remediation.
- Prefer exact lockfile versions over manifest ranges when both are available.
- In offline mode, report inventory with `not_checked_offline` status instead of implying packages are safe.
- Rank dependency findings by reachable surface area, severity, exploit maturity, and upgrade blast radius.
- Recommend the smallest safe upgrade path first: patch release, transitive override/resolution, direct dependency upgrade, then broader migration.

## Secret Review

- Never print raw secret values.
- Evidence should name the secret type and location, with the value redacted.
- Treat scanner hits as leads because fixtures, examples, and placeholder values can look secret-like.
- Prioritize live cloud keys, private keys, production database URLs, and tokens committed outside test fixtures.

## Static Security Review

- Built-in static checks are heuristics. Use confidence levels and inspect source context before claiming a vulnerability.
- For injection, SSRF, shell execution, path traversal, and XSS sinks, verify whether user-controlled input reaches the sink unsanitized.
- For weak crypto, distinguish insecure hashing for security-sensitive use from harmless checksums.
- Prefer semgrep, npm audit, pip-audit, cargo audit, trivy, and gitleaks output when available and explicitly enabled.
