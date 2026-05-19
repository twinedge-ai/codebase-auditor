# Report Template

Use this shape for audit reports.

```markdown
# Codebase Audit Report

## Executive Summary

- Scope:
- Primary stack:
- Highest risk:
- Recommended next step:

## Scope And Stack

Summarize languages, frameworks, package managers, manifests, infrastructure hints, and discovered commands.

## Highest-Risk Findings

List the top findings by severity, confidence, effort, and ROI.

## Complexity And Performance Findings

For each finding:

- Severity:
- Confidence:
- Location:
- Evidence:
- Why it matters:
- Recommended fix:
- Estimated effort:
- Estimated ROI:
- Verification:

## Security And Dependency Findings

For each dependency, secret, or static security finding:

- Severity:
- Confidence:
- Location:
- Evidence:
- Security impact:
- Recommended fix:
- Estimated effort:
- Estimated ROI:
- Verification:

## Architecture Findings

Summarize module graph size, service topology, circular dependencies, god-module candidates, and diagrams if enabled.

For each architecture finding:

- Severity:
- Confidence:
- Location:
- Evidence:
- Architecture impact:
- Recommended fix:
- Estimated effort:
- Estimated ROI:
- Verification:

## Runtime Performance Results

Summarize whether runtime checks were skipped or executed. Include frontend URL probe metrics, Lighthouse metrics, load-test latency percentiles, throughput, error rate, and benchmark command timing when available.

For each performance finding:

- Severity:
- Confidence:
- Location:
- Evidence:
- Performance impact:
- Recommended fix:
- Estimated effort:
- Estimated ROI:
- Verification:

## Verification Commands

List discovered test, build, lint, typecheck, or benchmark commands relevant to validation.

## Appendix

Include raw scanner summaries and notes about skipped checks.
```
