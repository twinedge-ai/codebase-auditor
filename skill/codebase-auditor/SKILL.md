---
name: codebase-auditor
description: Audit software repositories for complexity, performance, dependency risk, security, architecture, and scalability findings. Use when Codex is asked to analyze, scan, review, secure, optimize, profile, map architecture, generate an engineering audit report, or safely remediate selected findings across frontend, backend, infrastructure, or multi-service systems.
---

# Codebase Auditor

## Core Rule

Preserve behavior and never modify files during report-only audit requests.

## Default Workflow

1. Discover the repository stack, manifests, test commands, services, and likely hot paths.
2. Run the bundled auditor CLI for deterministic first-pass findings.
3. Treat scanner output as leads, not proof; inspect high-impact findings before presenting conclusions.
4. Produce a report with `references/report-template.md`.
5. If remediation is explicitly requested, read `references/remediation-policy.md`, fix one selected finding with `scripts/auditor/cli.py fix <repo> --finding <id>` when supported, and verify.

## CLI Usage

From this skill directory, run:

```bash
python scripts/auditor/cli.py scan <repo> --profile quick-static --format markdown,json,html --out codebase-audit-report.html
```

Use `--profile complexity` when the user specifically asks for algorithmic or static performance analysis. Use `--profile security` for dependency, secret, and static security review. Use `--profile architecture` for module graph, service topology, circular dependency, and Mermaid diagram review. Use `--profile performance` for runtime frontend probes, Lighthouse, load tests, and benchmark timing. Use `--profile full` for a broad static audit. Use `.html` output when the user wants a navigable HTML report with in-report source references. Add `--allow-network` only when the user permits online vulnerability lookup. Add `--allow-perf` only when the user permits runtime checks. Add `--allow-private-network` only when the user approves probing local or private addresses. Add `--confirm-benchmarks` only when the user explicitly approves running discovered test or benchmark commands. Add `--allow-mocks` only for local test fixtures that intentionally use `CODEX_AUDITOR_*` mock response files.

For remediation, require an explicit finding ID:

```bash
python scripts/auditor/cli.py fix <repo> --finding <finding-id>
```

Use `--dry-run` to preview supported changes without editing files.

## Audit Guidance

- Prefer deterministic facts from the CLI over guesswork.
- Rank findings by severity, confidence, effort, and likely ROI.
- Avoid overclaiming Big-O or vulnerability certainty from heuristics.
- Explain the smallest behavior-preserving remediation path when fixes are requested.
- Prefer the simplest behavior-preserving algorithm or data structure that improves asymptotic complexity, memory use, or I/O fan-out.
- Cite the Complexity Rule in `references/complexity-playbook.md` when recommending `Map`, dictionary, `Set`, batching, memoization, or indexing changes.
- Do not apply lookup rewrites blindly; first verify key uniqueness, duplicate handling, ordering, equality semantics, mutation timing, and error behavior.

## References

- Read `references/complexity-playbook.md` for algorithmic and frontend/backend performance patterns.
- Read `references/dependency-security-playbook.md` for dependency, OSV, secret, and static security review.
- Read `references/architecture-playbook.md` for module graph, service topology, circular dependency, and boundary review.
- Read `references/performance-playbook.md` before running or interpreting runtime performance checks.
- Read `references/remediation-policy.md` before editing files.
- Read `references/report-template.md` before final audit output.
