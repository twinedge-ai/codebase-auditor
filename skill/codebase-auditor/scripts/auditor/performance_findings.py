from __future__ import annotations

import hashlib
from typing import Any


def finding_id(*parts: object) -> str:
    digest = hashlib.sha256(":".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:10]
    return f"performance-{digest}"


def performance_finding(
    *,
    tag: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: str,
    impact: str,
    recommendation: str,
    effort: str = "medium",
    roi: str = "medium",
    path: str = "runtime",
) -> dict[str, Any]:
    return {
        "id": finding_id(tag, evidence),
        "category": "performance",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "location": {"path": path, "line": None, "symbol": tag},
        "evidence": evidence,
        "impact": {"performance": impact, "security": None, "architecture": None},
        "recommendation": recommendation,
        "estimatedEffort": effort,
        "estimatedRoi": roi,
        "verification": ["repeat benchmark", "focused performance test"],
        "source": "run_perf_checks",
    }


def performance_findings(perf: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    probe_metrics = perf.get("frontend", {}).get("probe", {}).get("metrics")
    if probe_metrics:
        p95 = probe_metrics.get("totalMs", {}).get("p95")
        error_rate = probe_metrics.get("errorRate") or 0
        if error_rate > 0:
            findings.append(
                performance_finding(
                    tag="frontend-probe-errors",
                    severity="high",
                    confidence="medium",
                    title="Frontend URL probe returned errors",
                    evidence=f"errorRate={error_rate}, statusCodes={probe_metrics.get('statusCodes')}",
                    impact="Frontend requests failed during the runtime probe.",
                    recommendation="Check server logs, route health, and dependency availability before tuning latency.",
                    effort="small",
                    roi="high",
                )
            )
        elif p95 and p95 > 1000:
            findings.append(
                performance_finding(
                    tag="frontend-probe-latency",
                    severity="medium",
                    confidence="medium",
                    title="Frontend URL probe has high P95 latency",
                    evidence=f"p95={p95}ms",
                    impact="Slow frontend response can delay first paint and user interactions.",
                    recommendation="Profile server render/static asset path and remove blocking work from the request path.",
                )
            )

    lighthouse_metrics = perf.get("frontend", {}).get("lighthouse", {}).get("metrics")
    if lighthouse_metrics and lighthouse_metrics.get("performanceScore") is not None:
        score = lighthouse_metrics["performanceScore"]
        if score < 50:
            severity = "high"
        elif score < 80:
            severity = "medium"
        else:
            severity = None
        if severity:
            findings.append(
                performance_finding(
                    tag="lighthouse-score",
                    severity=severity,
                    confidence="high",
                    title="Lighthouse performance score is low",
                    evidence=f"performanceScore={score}",
                    impact="Lab metrics indicate user-visible frontend performance risk.",
                    recommendation="Review Lighthouse audits for render-blocking resources, JavaScript cost, image sizing, and cache policy.",
                    roi="high",
                )
            )

    for load_result in perf.get("loadTests", []):
        metrics = load_result.get("metrics") or {}
        error_rate = metrics.get("errorRate") or 0
        p95 = (metrics.get("totalMs") or {}).get("p95")
        if error_rate > 0:
            findings.append(
                performance_finding(
                    tag="load-test-errors",
                    severity="high",
                    confidence="high",
                    title="Load test produced errors",
                    evidence=f"url={load_result.get('url')}, errorRate={error_rate}",
                    impact="The endpoint failed under the configured load.",
                    recommendation="Inspect error logs and dependency saturation before increasing throughput.",
                    roi="high",
                )
            )
        elif p95 and p95 > 1000:
            findings.append(
                performance_finding(
                    tag="load-test-tail-latency",
                    severity="medium",
                    confidence="medium",
                    title="Load test P95 latency is high",
                    evidence=f"url={load_result.get('url')}, p95={p95}ms",
                    impact="Tail latency can degrade user experience and service SLOs.",
                    recommendation="Profile request handlers, database calls, serialization, and queueing under concurrent load.",
                )
            )
    return findings
