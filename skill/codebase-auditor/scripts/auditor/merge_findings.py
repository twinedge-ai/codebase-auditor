from __future__ import annotations

from collections import Counter
from typing import Any


SEVERITY_SCORE = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

CONFIDENCE_SCORE = {
    "high": 3,
    "medium": 2,
    "low": 1,
}

ROI_SCORE = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


def finding_score(finding: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        SEVERITY_SCORE.get(finding.get("severity"), 0),
        CONFIDENCE_SCORE.get(finding.get("confidence"), 0),
        ROI_SCORE.get(finding.get("estimatedRoi"), 0),
        finding.get("id", ""),
    )


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=finding_score, reverse=True)


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_severity = Counter(finding["severity"] for finding in findings)
    by_category = Counter(finding["category"] for finding in findings)
    return {
        "totalFindings": len(findings),
        "bySeverity": {severity: by_severity.get(severity, 0) for severity in ["critical", "high", "medium", "low", "info"]},
        "byCategory": dict(sorted(by_category.items())),
        "topFindingIds": [finding["id"] for finding in sort_findings(findings)[:5]],
    }
