# Contributing

## Development

```bash
npm test
npm run pack:check
```

The test suite is intentionally dependency-light: Node.js and Python are enough for the default checks.

## Adding A Scanner

1. Add a module in `skill/codebase-auditor/scripts/auditor/`.
2. Emit the normalized finding schema:

```json
{
  "id": "category-stable-id",
  "category": "complexity",
  "severity": "medium",
  "confidence": "high",
  "title": "Short finding title",
  "location": {
    "path": "src/example.py",
    "line": 10,
    "symbol": "optional-symbol"
  },
  "evidence": "Short redacted evidence",
  "impact": {
    "performance": null,
    "security": null,
    "architecture": null
  },
  "recommendation": "Actionable recommendation.",
  "estimatedEffort": "small",
  "estimatedRoi": "medium",
  "verification": ["focused test"],
  "source": "scan_new_area"
}
```

3. Wire the scanner into `skill/codebase-auditor/scripts/auditor/cli.py`.
4. Add report rendering only when the scanner returns new structured non-finding data.
5. Add a fixture and a focused test.

## Remediation Rules

Report-only scans must remain read-only. Fixes must require explicit user intent and a concrete finding ID. Mechanical fixes must preserve behavior and run focused verification.
