from __future__ import annotations

from typing import Any

def render_duration_ms(value: object) -> str:
    try:
        milliseconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "not recorded"
    if milliseconds < 1000:
        return f"{milliseconds:.0f} ms"
    return f"{milliseconds / 1000:.2f} s"

def render_impact(finding: dict[str, Any]) -> str:
    impact = finding.get("impact", {})
    return impact.get("performance") or impact.get("security") or impact.get("architecture") or "Potential maintainability or runtime risk"

def render_latency(metrics: dict[str, Any] | None) -> str:
    if not metrics:
        return "Not available"
    total = metrics.get("totalMs") or {}
    return (
        f"requests={metrics.get('requests')}, errors={metrics.get('errors')}, "
        f"errorRate={metrics.get('errorRate')}, p50={total.get('p50')}ms, "
        f"p95={total.get('p95')}ms, p99={total.get('p99')}ms, "
        f"throughput={metrics.get('throughputRps', 'n/a')} rps"
    )

