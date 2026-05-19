# codebase-auditor

Installable Codex skill and standalone `codex-codebase-auditor` CLI for codebase complexity, security, dependency, architecture, performance, and remediation audits.

This skill is built for Codex using Codex.

The package ships:

- A Codex skill installed as `$codebase-auditor`.
- A standalone CLI for deterministic scans.
- Markdown, JSON, and HTML report output.
- Navigable HTML source references for line-level findings.
- Source-file and source-line totals by language.
- Executive summary with scanned LOC and scan duration.
- Conservative, explicit remediation for selected low-risk findings.

## Install

```bash
npm install -g codex-codebase-auditor
codex-codebase-auditor install
```

Direct use without global install:

```bash
npx codex-codebase-auditor install
npx codex-codebase-auditor scan . --profile quick-static --out codebase-audit-report.md
```

Local development from this repository:

```bash
npx . install
npx . scan . --profile full --offline --out codebase-audit-report.html
```

## Codex Usage

After install, prompt Codex with:

```text
Use $codebase-auditor to audit this repository and generate a full engineering report.
```

For remediation:

```text
Use $codebase-auditor to implement the lowest-risk supported fix from the audit and run relevant tests.
```

## CLI Usage

```bash
codex-codebase-auditor init
codex-codebase-auditor scan . --profile quick-static --out audit.md
codex-codebase-auditor scan . --profile full --offline --out audit.html
codex-codebase-auditor scan . --profile complexity --out complexity.md
codex-codebase-auditor scan . --profile security --allow-network --out security.md
codex-codebase-auditor scan . --profile architecture --include-diagrams --out architecture.md
codex-codebase-auditor scan . --profile performance --allow-perf --allow-private-network --frontend-url http://localhost:3000 --out perf.md
codex-codebase-auditor fix . --finding complexity-py-membership-literal-abc12345 --json
```

Profiles:

- `quick-static`: discovery, dependency inventory, secret checks, static security leads, and obvious complexity leads.
- `complexity`: algorithmic and static performance leads.
- `security`: dependency, secret, and static security leads.
- `architecture`: module graph, service topology, circular dependency, and god-module leads.
- `performance`: opt-in runtime probes, Lighthouse, load tests, and benchmark timing.
- `full`: all static scanners plus runtime checks only when explicitly enabled.

`scan` never edits files. `fix` requires an explicit finding ID and only applies supported low-risk mechanical fixes.

## What It Checks

### Complexity

The complexity scanner looks for code paths where runtime can grow unexpectedly as input size increases. It flags nested loops, repeated linear lookups inside transforms, sort work inside loops, query-like calls inside loops, render-path collection transforms, and selected Python AST patterns such as repeated list membership checks inside a loop.

These findings are intentionally conservative leads. A `Map`, dictionary, `Set`, batching, caching, or pre-indexing change is only recommended after checking ordering, duplicate handling, equality semantics, mutation timing, and error behavior.

### Static Security

The static security scanner looks for source-level risk patterns without executing the target repository. Built-in checks cover common sinks such as command execution from request data, dynamic evaluation, weak randomness for sensitive values, unsafe deserialization, path traversal candidates, permissive CORS, and SQL construction patterns.

Secret scanning is also built in. Reports redact matched secret values before rendering source snippets in Markdown, JSON, or HTML output.

### Dependency Security

The dependency scanner inventories package manifests and lockfiles across common ecosystems. Offline scans report dependency inventory only. With `--allow-network`, the scanner can query OSV for vulnerability matches, and operator-owned config can opt into external tools such as `npm audit`, `pip-audit`, `cargo audit`, `trivy`, or `gitleaks`.

Network access and external executables are disabled by default because they belong to the operator's trust boundary, not the scanned repository's trust boundary.

### Architecture

The architecture scanner maps local import edges, service topology, route hints, circular dependency candidates, and large module candidates. With diagrams enabled, it emits Mermaid diagrams for the module graph and service topology when the result is small enough to read.

Use this profile to find coupling, package-boundary drift, cross-service dependencies, and files that are becoming coordination points for too many responsibilities.

### Performance

The performance profile is opt-in for runtime work. It can run frontend HTTP probes, Lighthouse when available, built-in HTTP load tests, optional `autocannon` or `k6`, and benchmark command timing.

Runtime probes, private-network access, and benchmark execution are gated separately. This prevents a scanned repository from silently causing network traffic, load generation, or arbitrary script execution.

## Configuration

Create `.codebase-auditor.json` for repo-local presentation settings:

```bash
codex-codebase-auditor init
```

Repo-local fields are intentionally limited because this file is loaded from the scanned repository:

```json
{
  "report": {
    "includeMermaidDiagrams": false,
    "includeRemediationPlan": true
  }
}
```

Scanning controls, excludes, finding caps, network targets, external tools, and runtime limits are operator-owned. Put those in a separate JSON file and pass it with `--config` when you trust that policy.

Default excludes skip dependency folders, build outputs, caches, VCS metadata, and conventional test fixture directories such as `test/fixtures`, `tests/fixtures`, and `__fixtures__`. Those fixture paths are commonly used to keep intentionally vulnerable or intentionally inefficient samples for scanner tests. If you want to audit fixtures, pass an explicit operator config with your own `exclude` list.

Network and runtime checks are off by default. Use `--allow-network` for OSV vulnerability lookups and `--allow-perf` for runtime probes or load tests. Runtime probes block private, loopback, reserved, and link-local hosts unless `--allow-private-network` is set. Benchmark command timing also requires `--confirm-benchmarks` because discovered repository scripts can execute arbitrary code. Mock response files from `CODEX_AUDITOR_*` env vars require `--allow-mocks`. External tools are only run from absolute paths configured in an explicit operator config. Lighthouse runs Chrome without `--no-sandbox` unless `--lighthouse-no-sandbox` is supplied for a trusted CI environment.

The Python scanner requires Python 3.11 or newer for full lockfile support.

## Scanner Scope

Phase-complete scanner set:

- Repository discovery: languages, source-line totals, manifests, package managers, frameworks, infrastructure hints, commands.
- Complexity: nested loops, repeated lookups, sort/query/API-in-loop, render-path transforms, selected Python AST checks.
- Dependency/security: lockfile inventory, OSV lookup, optional external audit tools, redacted secrets, static security sinks.
- Architecture: import graph, service topology, circular dependency candidates, god-module candidates, Mermaid diagrams.
- Runtime performance: frontend HTTP probe, Lighthouse adapter, built-in HTTP load test, optional `autocannon`/`k6`, benchmark timing.
- Remediation: selected low-risk Python membership literal fix with verification.

Scanner findings are leads, not proof. Inspect high-impact findings before remediation. HTML source snippets redact values matched by the built-in secret scanner before rendering.

## Examples

Example reports live in [examples/reports](examples/reports):

- [quick-audit.md](examples/reports/quick-audit.md)
- [architecture-audit.md](examples/reports/architecture-audit.md)
- [performance-audit.md](examples/reports/performance-audit.md)

## Contributing

Run the validation suite:

```bash
npm test
npm run pack:check
npm audit --omit=dev --audit-level=moderate
```

To add a scanner:

1. Add a module under `skill/codebase-auditor/scripts/auditor/`.
2. Emit normalized findings with `id`, `category`, `severity`, `confidence`, `title`, `location`, `evidence`, `impact`, `recommendation`, `estimatedEffort`, `estimatedRoi`, `verification`, and `source`.
3. Wire the scanner into `cli.py`.
4. Render any new structured output in `render_report.py`.
5. Add a focused fixture and test.

Keep report-only flows read-only. Put detailed guidance in `skill/codebase-auditor/references/` and keep `SKILL.md` concise.
