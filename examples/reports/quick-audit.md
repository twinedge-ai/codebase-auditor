# Codebase Audit Report

Generated: 2026-05-18T00:00:00Z
Profile: `quick`
Network lookup: disabled
Repository: `examples/js-service`

## Executive Summary

- Files scanned: 24
- Source files scanned: 12
- Primary language: JavaScript
- Findings: 3
- Severity counts: high: 1, medium: 2

## Highest-Risk Findings

- high: Repeated linear lookup inside collection transform (`complexity-map-find-example`)

## Complexity And Performance Findings

### Repeated linear lookup inside collection transform (`complexity-map-find-example`)

- Severity: high
- Confidence: medium
- Location: `src/users.js:42`
- Evidence: `users.map(... orders.find(...))`
- Why it matters: Likely O(n*m) lookup pattern
- Recommended fix: Build a Map once when key uniqueness and duplicate behavior are clear.
- Estimated effort: small
- Estimated ROI: high
- Verification: unit test, benchmark if input size is large

## Security And Dependency Findings

No dependency, secret, or static security findings met the scanner threshold.

## Appendix

- Scanner sources: scan_complexity
