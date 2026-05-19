from __future__ import annotations

import hashlib
import html
from pathlib import Path
from typing import Any

from .discover_repo import read_text
from .render_common import render_duration_ms, render_impact, render_latency
from .scan_secrets import is_external_secret, redact_secret_text

def html_text(value: object) -> str:
    return html.escape(str(value), quote=True)


def html_code(value: object) -> str:
    return f"<code>{html_text(value)}</code>"


def html_list(values: list[str]) -> str:
    if not values:
        return "None detected"
    return ", ".join(html_text(value) for value in values)


def html_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "None"
    return ", ".join(f"{html_text(name)}: {count}" for name, count in sorted(counts.items()))


def finding_dom_id(finding: dict[str, Any]) -> str:
    return "finding-" + hashlib.sha256(str(finding.get("id", "")).encode("utf-8")).hexdigest()[:12]


def source_line_dom_id(path: str, line: int) -> str:
    return "src-" + hashlib.sha256(f"{path}:{line}".encode("utf-8")).hexdigest()[:12]


def int_line(value: object) -> int | None:
    try:
        line = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def is_external_secret_finding(finding: dict[str, Any]) -> bool:
    return is_external_secret(finding)


def resolve_source_path(repo: Path, path_value: object) -> Path | None:
    if not isinstance(path_value, str) or not path_value or path_value == "unknown":
        return None
    path = Path(path_value)
    candidate = path.resolve() if path.is_absolute() else (repo / path).resolve()
    try:
        candidate.relative_to(repo)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def source_link_for_finding(result: dict[str, Any], finding: dict[str, Any], rendered_anchors: set[str] | None = None) -> str | None:
    if is_external_secret_finding(finding):
        return None
    location = finding.get("location", {})
    if not isinstance(location, dict):
        return None
    line = int_line(location.get("line"))
    path = location.get("path")
    if line is None or not isinstance(path, str):
        return None
    repo = Path(str(result.get("repository") or result.get("discovery", {}).get("root", ""))).resolve()
    source = resolve_source_path(repo, path)
    if not source:
        return None
    total_lines = len(read_text(source).splitlines())
    if line > total_lines:
        return None
    anchor = source_line_dom_id(path, line)
    if rendered_anchors is not None and anchor not in rendered_anchors:
        return None
    return anchor


def render_html_location(result: dict[str, Any], finding: dict[str, Any], rendered_anchors: set[str] | None = None) -> str:
    location = finding.get("location", {})
    if not isinstance(location, dict):
        return html_code("unknown")
    line = int_line(location.get("line"))
    path = str(location.get("path", "unknown"))
    loc = path if line is None else f"{path}:{line}"
    anchor = source_link_for_finding(result, finding, rendered_anchors)
    if not anchor:
        return html_code(loc)
    return f'<a class="source-link" href="#{anchor}">{html_code(loc)}</a>'


def render_html_table(headers: list[str], rows: list[list[object]], omitted_count: int = 0) -> str:
    if not rows:
        return "<p>None detected.</p>"
    head = "".join(f"<th>{html_text(header)}</th>" for header in headers)
    body_rows = []
    for row in rows:
        body_rows.append("<tr>" + "".join(f"<td>{html_text(cell)}</td>" for cell in row) + "</tr>")
    if omitted_count > 0:
        body_rows.append(f'<tr><td colspan="{len(headers)}">... {omitted_count} more omitted</td></tr>')
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def render_html_findings(result: dict[str, Any], findings: list[dict[str, Any]], empty_message: str, rendered_anchors: set[str] | None = None) -> str:
    if not findings:
        return f"<p>{html_text(empty_message)}</p>"
    cards = []
    for finding in findings:
        verification = ", ".join(html_text(item) for item in finding.get("verification", [])) or "Not specified"
        severity = html_text(finding.get("severity", "info"))
        cards.append(
            "\n".join(
                [
                    f'<article class="finding severity-{severity}" id="{finding_dom_id(finding)}">',
                    f"<h3>{html_text(finding.get('title', 'Finding'))} {html_code(finding.get('id', 'unknown'))}</h3>",
                    "<dl>",
                    f"<dt>Severity</dt><dd>{severity}</dd>",
                    f"<dt>Confidence</dt><dd>{html_text(finding.get('confidence', 'unknown'))}</dd>",
                    f"<dt>Location</dt><dd>{render_html_location(result, finding, rendered_anchors)}</dd>",
                    f"<dt>Evidence</dt><dd>{html_text(finding.get('evidence', ''))}</dd>",
                    f"<dt>Why it matters</dt><dd>{html_text(render_impact(finding))}</dd>",
                    f"<dt>Recommended fix</dt><dd>{html_text(finding.get('recommendation', ''))}</dd>",
                    f"<dt>Estimated effort</dt><dd>{html_text(finding.get('estimatedEffort', 'unknown'))}</dd>",
                    f"<dt>Estimated ROI</dt><dd>{html_text(finding.get('estimatedRoi', 'unknown'))}</dd>",
                    f"<dt>Verification</dt><dd>{verification}</dd>",
                    "</dl>",
                    "</article>",
                ]
            )
        )
    return "\n".join(cards)


def redact_sensitive_snippet_lines(lines: list[str]) -> list[str]:
    redacted = []
    in_private_key = False
    for line in lines:
        has_begin = "-----BEGIN " in line and "PRIVATE KEY-----" in line
        has_end = "-----END " in line and "PRIVATE KEY-----" in line
        if in_private_key:
            redacted.append("[redacted private-key]")
            if has_end:
                in_private_key = False
            continue
        if has_begin:
            redacted.append("[redacted private-key]")
            if not has_end:
                in_private_key = True
            continue
        redacted.append(redact_secret_text(line))
    return redacted


MAX_EXTERNAL_SECRET_LINE_SPAN = 10_000


def external_secret_lines_by_source(result: dict[str, Any], repo: Path) -> dict[Path, set[int]]:
    lines_by_source: dict[Path, set[int]] = {}

    def add_range(path_value: object, start_value: object, end_value: object) -> None:
        source = resolve_source_path(repo, path_value)
        start = int_line(start_value)
        end = int_line(end_value) or start
        if not source or start is None:
            return
        if end is None or end < start:
            end = start
        end = min(end, start + MAX_EXTERNAL_SECRET_LINE_SPAN - 1)
        source_lines = lines_by_source.setdefault(source.resolve(), set())
        source_lines.update(range(start, end + 1))

    source_redactions = result.get("sourceRedactions", {})
    if isinstance(source_redactions, dict):
        external_secrets = source_redactions.get("externalSecrets", [])
        if isinstance(external_secrets, list):
            for redaction in external_secrets:
                if isinstance(redaction, dict):
                    add_range(redaction.get("path"), redaction.get("startLine"), redaction.get("endLine"))

    for finding in result.get("findings", []):
        if not is_external_secret_finding(finding):
            continue
        location = finding.get("location", {})
        if not isinstance(location, dict):
            continue
        start = int_line(location.get("line"))
        metadata = finding.get("metadata", {})
        if isinstance(metadata, dict):
            start = int_line(metadata.get("startLine")) or start
            end = int_line(metadata.get("endLine")) or start
        else:
            end = start
        add_range(location.get("path"), start, end)
    return lines_by_source


def redacted_source_lines_for_file(source: Path, external_secret_lines: set[int]) -> list[str]:
    redacted_source_lines = redact_sensitive_snippet_lines(read_text(source).splitlines())
    for secret_line in external_secret_lines:
        if 1 <= secret_line <= len(redacted_source_lines):
            redacted_source_lines[secret_line - 1] = "[redacted external-secret]"
    return redacted_source_lines


def build_source_snippet(redacted_source_lines: list[str], line: int, context_lines: int) -> list[dict[str, Any]]:
    start = max(1, line - context_lines)
    end = min(len(redacted_source_lines), line + context_lines)
    snippet = []
    snippet_lines = redacted_source_lines[start - 1 : end]
    for offset, number in enumerate(range(start, end + 1)):
        text = snippet_lines[offset]
        if len(text) > 400:
            text = f"{text[:397]}..."
        snippet.append({"number": number, "text": text, "target": number == line})
    return snippet


def collect_source_references(result: dict[str, Any], context_lines: int = 3, limit: int = 80) -> list[dict[str, Any]]:
    repo = Path(str(result.get("repository") or result.get("discovery", {}).get("root", ""))).resolve()
    external_secret_lines = external_secret_lines_by_source(result, repo)
    references: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    redacted_cache: dict[Path, list[str]] = {}
    for finding in result.get("findings", []):
        if is_external_secret_finding(finding):
            continue
        location = finding.get("location", {})
        if not isinstance(location, dict):
            continue
        path = location.get("path")
        line = int_line(location.get("line"))
        if not isinstance(path, str) or line is None or (path, line) in seen:
            continue
        source = resolve_source_path(repo, path)
        if not source:
            continue
        resolved = source.resolve()
        redacted_source_lines = redacted_cache.get(resolved)
        if redacted_source_lines is None:
            redacted_source_lines = redacted_source_lines_for_file(source, external_secret_lines.get(resolved, set()))
            redacted_cache[resolved] = redacted_source_lines
        if line > len(redacted_source_lines):
            continue
        seen.add((path, line))
        references.append(
            {
                "path": path,
                "line": line,
                "findingId": finding.get("id", "unknown"),
                "title": finding.get("title", "Finding"),
                "anchor": source_line_dom_id(path, line),
                "snippet": build_source_snippet(redacted_source_lines, line, context_lines),
            }
        )
        if len(references) >= limit:
            break
    return references


def rendered_source_anchors(references: list[dict[str, Any]]) -> set[str]:
    return {str(reference["anchor"]) for reference in references}


def render_source_references(references: list[dict[str, Any]]) -> str:
    if not references:
        return "<p>No line-level source references were available for the included findings.</p>"
    blocks = []
    for reference in references:
        blocks.append(
            "\n".join(
                [
                    '<article class="source-ref">',
                    f"<h3>{html_code(reference['path'] + ':' + str(reference['line']))}</h3>",
                    f"<p>Referenced by {html_code(reference['findingId'])}: {html_text(reference['title'])}</p>",
                    "<pre><code>",
                    "\n".join(source_reference_lines(reference)),
                    "</code></pre>",
                    "</article>",
                ]
            )
        )
    return "\n".join(blocks)


def source_reference_lines(reference: dict[str, Any]) -> list[str]:
    lines = []
    for item in reference["snippet"]:
        line_id = f' id="{reference["anchor"]}"' if item["target"] else ""
        css_class = "source-line is-target" if item["target"] else "source-line"
        lines.append(
            f'<span class="{css_class}"{line_id}>'
            f'<span class="line-no">{item["number"]}</span>'
            f'<span class="line-code">{html_text(item["text"])}</span>'
            "</span>"
        )
    return lines


def render_html_performance(performance: dict[str, Any]) -> str:
    summary = performance.get("summary", {})
    probe = performance.get("frontend", {}).get("probe", {})
    lighthouse = performance.get("frontend", {}).get("lighthouse", {})
    rows = [
        f"<p>Status: {html_text(summary.get('status', 'skipped'))}. Enabled: {html_text(performance.get('enabled', False))}.</p>",
        "<h3>Frontend Probe</h3>",
    ]
    if probe.get("status") == "completed":
        rows.append(f"<p>{html_code(probe.get('url'))}: {html_text(render_latency(probe.get('metrics')))}</p>")
    else:
        reason = f" Reason: {html_text(probe['reason'])}." if probe.get("reason") else ""
        rows.append(f"<p>Status: {html_text(probe.get('status', 'skipped'))}.{reason}</p>")

    rows.append("<h3>Lighthouse</h3>")
    if lighthouse.get("status") == "completed":
        metrics = lighthouse.get("metrics") or {}
        rows.append(
            "<p>"
            f"Score: {html_text(metrics.get('performanceScore'))}; "
            f"FCP: {html_text(metrics.get('firstContentfulPaintMs'))}ms; "
            f"LCP: {html_text(metrics.get('largestContentfulPaintMs'))}ms; "
            f"TBT: {html_text(metrics.get('totalBlockingTimeMs'))}ms; "
            f"Speed index: {html_text(metrics.get('speedIndexMs'))}ms; "
            f"CLS: {html_text(metrics.get('cumulativeLayoutShift'))}"
            "</p>"
        )
    else:
        reason = f" Reason: {html_text(lighthouse['reason'])}." if lighthouse.get("reason") else ""
        rows.append(f"<p>Status: {html_text(lighthouse.get('status', 'skipped'))}.{reason}</p>")

    rows.append("<h3>Load Tests</h3>")
    load_tests = performance.get("loadTests", [])
    if load_tests:
        rows.append("<ul>")
        for item in load_tests:
            rows.append(f"<li>{html_text(item.get('adapter'))}: {html_code(item.get('url', 'configured target'))} - {html_text(render_latency(item.get('metrics')))}</li>")
        rows.append("</ul>")
    else:
        rows.append("<p>No load tests executed.</p>")

    rows.append("<h3>Benchmark Timings</h3>")
    benchmarks = performance.get("benchmarks", [])
    if benchmarks:
        rows.append("<ul>")
        for item in benchmarks:
            duration = f"{item['durationMs']}ms" if item.get("durationMs") is not None else "not run"
            rows.append(f"<li>{html_code(item['command'])}: {html_text(item['status'])} in {html_text(duration)}</li>")
        rows.append("</ul>")
    else:
        rows.append("<p>No benchmark commands executed.</p>")
    return "\n".join(rows)


def render_html(result: dict[str, Any]) -> str:
    discovery = result["discovery"]
    findings = result["findings"]
    complexity_findings = [finding for finding in findings if finding["category"] == "complexity"]
    security_findings = [finding for finding in findings if finding["category"] in {"dependency", "secret", "security"}]
    architecture_findings = [finding for finding in findings if finding["category"] == "architecture"]
    performance_findings = [finding for finding in findings if finding["category"] == "performance"]
    architecture = result.get("architecture", {})
    architecture_summary = architecture.get("summary", {})
    performance = result.get("performance", {})
    summary = result["summary"]
    top_findings = findings[:5]
    source_references = collect_source_references(result)
    source_anchors = rendered_source_anchors(source_references)

    language_rows = [[row["name"], row["files"], row.get("lines", 0), row["bytes"]] for row in discovery["languages"]]
    dependencies = result.get("dependencies", [])
    services = architecture.get("services", [])
    dependency_rows = [
        [dep["name"], dep.get("version") or "unknown", dep["ecosystem"], dep["manager"], dep["vulnerabilityStatus"], dep["path"]]
        for dep in dependencies[:50]
    ]
    service_rows = [
        [service["name"], service["type"], service["path"], ", ".join(service.get("ports", [])) or "None", ", ".join(service.get("dependsOn", [])) or "None", len(service.get("routes", []))]
        for service in services[:40]
    ]
    dependency_omitted = max(0, len(dependencies) - len(dependency_rows))
    service_omitted = max(0, len(services) - len(service_rows))
    top_html = (
        "<ul>"
        + "".join(
            f'<li><a href="#{finding_dom_id(finding)}">{html_text(finding["severity"])}: {html_text(finding["title"])} {html_code(finding["id"])}</a></li>'
            for finding in top_findings
        )
        + "</ul>"
        if top_findings
        else "<p>No high-risk findings detected by enabled scanners.</p>"
    )
    scanner_sources = sorted(set(finding["source"] for finding in findings))

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'self\' data:">',
            "<title>Codebase Audit Report</title>",
            "<style>",
            "body{margin:0;font-family:Arial,Helvetica,sans-serif;line-height:1.5;color:#17202a;background:#f6f8fa}",
            "main{max-width:1180px;margin:0 auto;padding:28px}",
            "header{background:#17202a;color:white;padding:28px;border-bottom:4px solid #1f8f6f}",
            "header h1{margin:0 0 8px;font-size:30px}",
            "header code{color:#17202a;background:#f8fafc;border-color:#cbd5e1}",
            "section{margin:24px 0}",
            "h2{font-size:22px;margin:0 0 12px;border-bottom:1px solid #d8dee4;padding-bottom:6px}",
            "h3{font-size:17px;margin:0 0 10px}",
            "a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}",
            "code{background:#eef2f6;border:1px solid #d8dee4;border-radius:4px;padding:1px 4px}",
            ".summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}",
            ".metric,.finding,.source-ref{background:white;border:1px solid #d8dee4;border-radius:8px;padding:14px}",
            ".metric strong{display:block;font-size:22px;color:#17202a}",
            "table{width:100%;border-collapse:collapse;background:white;border:1px solid #d8dee4}",
            "th,td{border-bottom:1px solid #d8dee4;padding:8px;text-align:left;vertical-align:top}",
            "th{background:#eef2f6}",
            ".finding{margin:12px 0;border-left:5px solid #6b7280}",
            ".severity-critical,.severity-high{border-left-color:#cf222e}",
            ".severity-medium{border-left-color:#bf8700}",
            ".severity-low,.severity-info{border-left-color:#1f8f6f}",
            "dl{display:grid;grid-template-columns:150px 1fr;gap:6px 12px;margin:0}",
            "dt{font-weight:700;color:#57606a}dd{margin:0}",
            ".source-ref{margin:12px 0}",
            "pre{overflow:auto;background:#0f1720;color:#dbeafe;border-radius:6px;padding:10px}",
            ".source-line{display:block;white-space:pre}",
            ".source-line.is-target{background:#334155}",
            ".line-no{display:inline-block;width:4em;color:#93a4b8;user-select:none}",
            ".line-code{white-space:pre}",
            ".note{color:#57606a}",
            "</style>",
            "</head>",
            "<body>",
            "<header>",
            "<h1>Codebase Audit Report</h1>",
            f"<div>Generated: {html_text(result['generatedAt'])} | Profile: {html_code(result['profile'])} | Network lookup: {html_text('enabled' if result.get('allowNetwork') else 'disabled')}</div>",
            f"<div>Repository: {html_code(discovery['root'])}</div>",
            "</header>",
            "<main>",
            '<section id="summary">',
            "<h2>Executive Summary</h2>",
            '<div class="summary">',
            f'<div class="metric"><strong>{discovery["totals"]["files"]}</strong>Files scanned</div>',
            f'<div class="metric"><strong>{discovery["totals"]["sourceFiles"]}</strong>Source files scanned</div>',
            f'<div class="metric"><strong>{discovery["totals"].get("sourceLines", 0)}</strong>Lines of code scanned</div>',
            f'<div class="metric"><strong>{html_text(render_duration_ms(result.get("scanDurationMs")))}</strong>Scan duration</div>',
            f'<div class="metric"><strong>{summary["totalFindings"]}</strong>Findings</div>',
            f'<div class="metric"><strong>{html_counts(summary["bySeverity"])}</strong>Severity counts</div>',
            "</div>",
            "</section>",
            '<section id="scope"><h2>Scope And Stack</h2>',
            render_html_table(["Language", "Files", "Lines", "Bytes"], language_rows),
            f"<p>Package managers: {html_list(discovery['packageManagers'])}</p>",
            f"<p>Frameworks: {html_list(discovery['frameworks'])}</p>",
            f"<p>Infrastructure hints: {html_list(discovery['infrastructure'])}</p>",
            "</section>",
            '<section id="top-findings"><h2>Highest-Risk Findings</h2>',
            top_html,
            "</section>",
            '<section id="complexity"><h2>Complexity And Performance Findings</h2>',
            render_html_findings(result, complexity_findings, "No complexity findings met the scanner threshold.", source_anchors),
            "</section>",
            '<section id="security"><h2>Security And Dependency Findings</h2>',
            render_html_findings(result, security_findings, "No dependency, secret, or static security findings met the scanner threshold.", source_anchors),
            "</section>",
            '<section id="dependencies"><h2>Dependency Inventory</h2>',
            f"<p>Dependencies detected: {html_text(result.get('dependencySummary', {}).get('totalDependencies', 0))}. OSV status: {html_text(result.get('dependencySummary', {}).get('osvStatus', 'not_run'))}.</p>",
            render_html_table(["Package", "Version", "Ecosystem", "Manager", "Status", "Source"], dependency_rows, dependency_omitted),
            "</section>",
            '<section id="architecture"><h2>Architecture Findings</h2>',
            render_html_findings(result, architecture_findings, "No architecture findings met the scanner threshold.", source_anchors),
            "<h2>Architecture Map</h2>",
            f"<p>Modules mapped: {html_text(architecture_summary.get('moduleCount', 0))}; Local dependency edges: {html_text(architecture_summary.get('edgeCount', 0))}; Circular dependency candidates: {html_text(architecture_summary.get('cycleCount', 0))}; Services detected: {html_text(architecture_summary.get('serviceCount', 0))}; Routes detected: {html_text(architecture_summary.get('routeCount', 0))}.</p>",
            "<h3>Service Topology</h3>",
            render_html_table(["Service", "Type", "Source", "Ports", "Depends on", "Routes"], service_rows, service_omitted),
            "</section>",
            '<section id="runtime"><h2>Runtime Performance Results</h2>',
            render_html_performance(performance),
            "<h2>Runtime Performance Findings</h2>",
            render_html_findings(result, performance_findings, "No runtime performance findings met the scanner threshold.", source_anchors),
            "</section>",
            '<section id="source-references"><h2>Source References</h2>',
            '<p class="note">Finding locations link here when the source file and line are available. Snippets redact values matched by the built-in secret scanner; external secret findings are not linked to source snippets.</p>',
            render_source_references(source_references),
            "</section>",
            '<section id="verification"><h2>Verification Commands</h2>',
            "<ul>" + "".join(f"<li>{html_code(name)}: {html_code(command)}</li>" for name, command in sorted(discovery["commands"].items())) + "</ul>" if discovery["commands"] else "<p>No test, build, lint, or typecheck commands detected.</p>",
            "</section>",
            '<section id="appendix"><h2>Appendix</h2>',
            f"<p>Manifests detected: {len(discovery['manifests'])}</p>",
            f"<p>Scanner sources: {html_list(scanner_sources)}</p>",
            "<p>Scanner findings are leads; inspect high-impact items before remediation.</p>",
            "</section>",
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )
