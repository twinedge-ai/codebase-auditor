from __future__ import annotations

from typing import Any

from .render_common import render_duration_ms, render_impact, render_latency
from .render_html_report import render_html


def md_text(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "\\`")
        .replace("|", "\\|")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def max_backtick_run(value: str) -> int:
    longest = 0
    current = 0
    for char in value:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def code_span(value: object) -> str:
    text = (
        str(value)
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    fence = "`" * (max_backtick_run(text) + 1)
    if text.startswith("`") or text.endswith("`"):
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"


def table_cell(value: object) -> str:
    return md_text(value)


def render_list(values: list[str]) -> str:
    return ", ".join(md_text(value) for value in values) if values else "None detected"


def render_commands(commands: dict[str, str]) -> str:
    if not commands:
        return "- No test, build, lint, or typecheck commands detected."
    return "\n".join(f"- {code_span(name)}: {code_span(command)}" for name, command in sorted(commands.items()))


def render_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "None"
    return ", ".join(f"{md_text(name)}: {count}" for name, count in sorted(counts.items()))


def render_findings(findings: list[dict[str, Any]], empty_message: str = "No findings met the scanner threshold.") -> str:
    if not findings:
        return empty_message

    blocks = []
    for finding in findings:
        location = finding["location"]
        line = location.get("line")
        loc = location["path"] if line is None else f"{location['path']}:{line}"
        verification = ", ".join(md_text(item) for item in finding.get("verification", [])) or "Not specified"
        blocks.append(
            "\n".join(
                [
                    f"### {md_text(finding['title'])} ({code_span(finding['id'])})",
                    "",
                    f"- Severity: {md_text(finding['severity'])}",
                    f"- Confidence: {md_text(finding['confidence'])}",
                    f"- Location: {code_span(loc)}",
                    f"- Evidence: {md_text(finding['evidence'])}",
                    f"- Why it matters: {md_text(render_impact(finding))}",
                    f"- Recommended fix: {md_text(finding['recommendation'])}",
                    f"- Estimated effort: {md_text(finding['estimatedEffort'])}",
                    f"- Estimated ROI: {md_text(finding['estimatedRoi'])}",
                    f"- Verification: {verification}",
                ]
            )
        )
    return "\n\n".join(blocks)


def render_language_table(languages: list[dict[str, Any]]) -> str:
    if not languages:
        return "No languages detected."
    rows = ["| Language | Files | Lines | Bytes |", "| --- | ---: | ---: | ---: |"]
    for language in languages:
        rows.append(f"| {table_cell(language['name'])} | {language['files']} | {language.get('lines', 0)} | {language['bytes']} |")
    return "\n".join(rows)


def render_dependency_inventory(dependencies: list[dict[str, Any]]) -> str:
    if not dependencies:
        return "No dependencies detected by dependency parsers."
    rows = ["| Package | Version | Ecosystem | Manager | Status | Source |", "| --- | --- | --- | --- | --- | --- |"]
    for dep in dependencies[:50]:
        rows.append(
            f"| {table_cell(dep['name'])} | {table_cell(dep.get('version') or 'unknown')} | {table_cell(dep['ecosystem'])} | {table_cell(dep['manager'])} | {table_cell(dep['vulnerabilityStatus'])} | {code_span(dep['path'])} |"
        )
    if len(dependencies) > 50:
        rows.append(f"| ... | ... | ... | ... | {len(dependencies) - 50} more omitted | ... |")
    return "\n".join(rows)


def render_services(services: list[dict[str, Any]]) -> str:
    if not services:
        return "No services detected by topology discovery."
    rows = ["| Service | Type | Source | Ports | Depends on | Routes |", "| --- | --- | --- | --- | --- | ---: |"]
    for service in services[:40]:
        rows.append(
            f"| {table_cell(service['name'])} | {table_cell(service['type'])} | {code_span(service['path'])} | {render_list(service.get('ports', []))} | {render_list(service.get('dependsOn', []))} | {len(service.get('routes', []))} |"
        )
    if len(services) > 40:
        rows.append(f"| ... | ... | ... | ... | ... | {len(services) - 40} more omitted |")
    return "\n".join(rows)


def render_cycles(cycles: list[list[str]]) -> str:
    if not cycles:
        return "No circular module dependencies detected."
    return "\n".join(f"- {' -> '.join(md_text(node) for node in cycle)}" for cycle in cycles[:20])


def render_diagram(title: str, diagram: str | None) -> str:
    if not diagram:
        return ""
    return "\n".join([f"### {title}", "", "```mermaid", diagram, "```", ""])


def render_performance(performance: dict[str, Any]) -> str:
    summary = performance.get("summary", {})
    rows = [
        f"- Status: {summary.get('status', 'skipped')}",
        f"- Enabled: {performance.get('enabled', False)}",
    ]
    if performance.get("skippedReason"):
        rows.append(f"- Skipped reason: {performance['skippedReason']}")

    probe = performance.get("frontend", {}).get("probe", {})
    rows.extend(["", "### Frontend Probe", ""])
    if probe.get("status") == "completed":
        rows.append(f"- URL: {md_text(probe.get('url'))}")
        rows.append(f"- Metrics: {render_latency(probe.get('metrics'))}")
    else:
        rows.append(f"- Status: {probe.get('status', 'skipped')}")
        if probe.get("reason"):
            rows.append(f"- Reason: {md_text(probe['reason'])}")

    lighthouse = performance.get("frontend", {}).get("lighthouse", {})
    rows.extend(["", "### Lighthouse", ""])
    if lighthouse.get("status") == "completed":
        metrics = lighthouse.get("metrics") or {}
        rows.extend(
            [
                f"- URL: {md_text(lighthouse.get('url'))}",
                f"- Performance score: {metrics.get('performanceScore')}",
                f"- FCP: {metrics.get('firstContentfulPaintMs')}ms",
                f"- LCP: {metrics.get('largestContentfulPaintMs')}ms",
                f"- TBT: {metrics.get('totalBlockingTimeMs')}ms",
                f"- Speed index: {metrics.get('speedIndexMs')}ms",
                f"- CLS: {metrics.get('cumulativeLayoutShift')}",
            ]
        )
    else:
        rows.append(f"- Status: {lighthouse.get('status', 'skipped')}")
        if lighthouse.get("reason"):
            rows.append(f"- Reason: {md_text(lighthouse['reason'])}")

    rows.extend(["", "### Load Tests", ""])
    load_tests = performance.get("loadTests", [])
    if load_tests:
        for item in load_tests:
            rows.append(f"- {md_text(item.get('adapter'))}: {code_span(item.get('url', 'configured target'))} - {render_latency(item.get('metrics'))}")
    else:
        rows.append("No load tests executed.")

    rows.extend(["", "### Benchmark Timings", ""])
    benchmarks = performance.get("benchmarks", [])
    if benchmarks:
        for item in benchmarks:
            duration = f"{item['durationMs']}ms" if item.get("durationMs") is not None else "not run"
            suffix = f" ({md_text(item['reason'])})" if item.get("reason") else ""
            rows.append(f"- {code_span(item['command'])}: {md_text(item['status'])} in {duration}{suffix}")
    else:
        rows.append("No benchmark commands executed.")
    return "\n".join(rows)


def render_markdown(result: dict[str, Any]) -> str:
    discovery = result["discovery"]
    findings = result["findings"]
    complexity_findings = [finding for finding in findings if finding["category"] == "complexity"]
    security_findings = [finding for finding in findings if finding["category"] in {"dependency", "secret", "security"}]
    architecture_findings = [finding for finding in findings if finding["category"] == "architecture"]
    performance_findings = [finding for finding in findings if finding["category"] == "performance"]
    architecture = result.get("architecture", {})
    architecture_summary = architecture.get("summary", {})
    diagrams = architecture.get("diagrams", {})
    performance = result.get("performance", {})
    summary = result["summary"]
    top_findings = findings[:5]
    top_summary = (
        "\n".join(f"- {md_text(finding['severity'])}: {md_text(finding['title'])} ({code_span(finding['id'])})" for finding in top_findings)
        if top_findings
        else "- No high-risk findings detected by enabled scanners."
    )

    return "\n".join(
        [
            "# Codebase Audit Report",
            "",
            f"Generated: {result['generatedAt']}",
            f"Profile: {code_span(result['profile'])}",
            f"Network lookup: {'enabled' if result.get('allowNetwork') else 'disabled'}",
            f"Repository: {code_span(discovery['root'])}",
            "",
            "## Executive Summary",
            "",
            f"- Files scanned: {discovery['totals']['files']}",
            f"- Source files scanned: {discovery['totals']['sourceFiles']}",
            f"- Lines of code scanned: {discovery['totals'].get('sourceLines', 0)}",
            f"- Scan duration: {render_duration_ms(result.get('scanDurationMs'))}",
            f"- Findings: {summary['totalFindings']}",
            f"- Severity counts: {render_counts(summary['bySeverity'])}",
            "",
            "## Scope And Stack",
            "",
            render_language_table(discovery["languages"]),
            "",
            f"- Package managers: {render_list(discovery['packageManagers'])}",
            f"- Frameworks: {render_list(discovery['frameworks'])}",
            f"- Infrastructure hints: {render_list(discovery['infrastructure'])}",
            "",
            "## Highest-Risk Findings",
            "",
            top_summary,
            "",
            "## Complexity And Performance Findings",
            "",
            render_findings(complexity_findings, "No complexity findings met the scanner threshold."),
            "",
            "## Security And Dependency Findings",
            "",
            render_findings(security_findings, "No dependency, secret, or static security findings met the scanner threshold."),
            "",
            "## Dependency Inventory",
            "",
            f"- Dependencies detected: {result.get('dependencySummary', {}).get('totalDependencies', 0)}",
            f"- OSV status: {result.get('dependencySummary', {}).get('osvStatus', 'not_run')}",
            "",
            render_dependency_inventory(result.get("dependencies", [])),
            "",
            "## Architecture Findings",
            "",
            render_findings(architecture_findings, "No architecture findings met the scanner threshold."),
            "",
            "## Architecture Map",
            "",
            f"- Modules mapped: {architecture_summary.get('moduleCount', 0)}",
            f"- Local dependency edges: {architecture_summary.get('edgeCount', 0)}",
            f"- Circular dependency candidates: {architecture_summary.get('cycleCount', 0)}",
            f"- Services detected: {architecture_summary.get('serviceCount', 0)}",
            f"- Routes detected: {architecture_summary.get('routeCount', 0)}",
            "",
            "### Service Topology",
            "",
            render_services(architecture.get("services", [])),
            "",
            "### Circular Dependencies",
            "",
            render_cycles(architecture.get("cycles", [])),
            "",
            render_diagram("Service Topology Diagram", diagrams.get("serviceTopology")),
            render_diagram("Module Dependency Diagram", diagrams.get("moduleGraph")),
            "## Runtime Performance Results",
            "",
            render_performance(performance),
            "",
            "## Runtime Performance Findings",
            "",
            render_findings(performance_findings, "No runtime performance findings met the scanner threshold."),
            "",
            "## Verification Commands",
            "",
            render_commands(discovery["commands"]),
            "",
            "## Appendix",
            "",
            f"- Manifests detected: {len(discovery['manifests'])}",
            f"- Scanner sources: {render_list(sorted(set(finding['source'] for finding in findings)))}",
            "- Scanner findings are leads; inspect high-impact items before remediation.",
            "",
        ]
    )
