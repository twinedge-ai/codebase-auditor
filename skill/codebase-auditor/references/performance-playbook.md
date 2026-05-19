# Performance Playbook

Use this reference for runtime frontend probes, Lighthouse runs, HTTP load tests, and benchmark timing.

## Runtime Safety

- Runtime checks are opt-in. Do not run them unless the user passes `--allow-perf`, config sets `allowPerfTests: true`, or the user explicitly requests profiling/load testing.
- Benchmark timing is separately gated. Do not run discovered repository commands unless the user passes `--confirm-benchmarks` or otherwise explicitly approves command execution.
- Prefer local or staging URLs. Do not load test production systems without explicit permission.
- Keep default request counts and durations small; increase only when the user asks for deeper measurement.

## Interpreting Metrics

- Treat one-off timings as directional. Repeat before claiming a regression or improvement.
- Report P50, P95, P99, throughput, and error rate for load tests when available.
- For frontend checks, separate built-in HTTP timing from Lighthouse lab metrics.
- A high P95/P99 with low median usually points to queueing, cold paths, contention, or external dependency variance.
- Any nonzero error rate during a small local load test deserves source review before tuning throughput.

## Remediation Guidance

- Verify correctness and baseline metrics before optimizing.
- Prefer low-risk changes first: remove unnecessary synchronous work, add pagination, batch I/O, cache stable reads, avoid oversized payloads, and reduce render-blocking assets.
- Do not hide latency with caching if data freshness, authorization, or tenant isolation is unclear.
