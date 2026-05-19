# Codebase Audit Report

Generated: 2026-05-18T00:00:00Z
Profile: `performance`
Repository: `examples/frontend`

## Runtime Performance Results

- Status: completed
- Enabled: true

### Frontend Probe

- URL: `http://localhost:3000`
- Metrics: requests=3, errors=0, errorRate=0, p50=42.1ms, p95=48.7ms, p99=49.4ms, throughput=n/a rps

### Lighthouse

- Performance score: 87
- FCP: 710ms
- LCP: 1210ms
- TBT: 24ms
- Speed index: 980ms
- CLS: 0.01

### Load Tests

- built-in: `http://localhost:3000/api/health` - requests=20, errors=0, errorRate=0, p50=18.4ms, p95=33.2ms, p99=38.8ms, throughput=164.2 rps

## Runtime Performance Findings

No runtime performance findings met the scanner threshold.
