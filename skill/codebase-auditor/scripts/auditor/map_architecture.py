from __future__ import annotations

import ast
import hashlib
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .discover_repo import SOURCE_EXTENSIONS, iter_repo_files, read_text, rel
from .architecture_services import detect_services


JS_IMPORT_RE = re.compile(
    r"(?:import\s+(?:[^'\"\n]+\s+from\s+)?|export\s+[^'\"\n]+\s+from\s+|require\s*\(|import\s*\()\s*['\"]([^'\"]+)['\"]"
)
GO_IMPORT_RE = re.compile(r'"([^"]+)"')


def finding_id(*parts: object) -> str:
    digest = hashlib.sha256(":".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:10]
    return f"architecture-{digest}"


def architecture_finding(
    *,
    tag: str,
    severity: str,
    confidence: str,
    title: str,
    path: str,
    line: int | None,
    evidence: str,
    impact: str,
    recommendation: str,
    effort: str,
    roi: str,
) -> dict[str, Any]:
    return {
        "id": finding_id(tag, path, line, evidence),
        "category": "architecture",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "location": {"path": path, "line": line, "symbol": tag},
        "evidence": evidence,
        "impact": {"performance": None, "security": None, "architecture": impact},
        "recommendation": recommendation,
        "estimatedEffort": effort,
        "estimatedRoi": roi,
        "verification": ["architecture review", "focused tests around affected boundary"],
        "source": "map_architecture",
    }


def language_for_path(path: Path) -> str:
    return {
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".mjs": "JavaScript",
        ".cjs": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".py": "Python",
        ".go": "Go",
    }.get(path.suffix.lower(), "Source")


def line_count(path: Path) -> int:
    return len(read_text(path).splitlines())


def source_files(repo: Path, config: dict[str, Any]) -> list[Path]:
    return [
        path
        for path in iter_repo_files(repo, config, max_bytes=1_000_000)
        if path.suffix.lower() in SOURCE_EXTENSIONS
    ]


def resolve_relative_import(repo: Path, source: Path, specifier: str, files_by_rel: dict[str, Path]) -> str | None:
    if not specifier.startswith("."):
        return None
    base = (source.parent / specifier).resolve()
    candidates = [base]
    if not base.suffix:
        for ext in [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go"]:
            candidates.append(base.with_suffix(ext))
        for ext in [".ts", ".tsx", ".js", ".jsx", ".py"]:
            candidates.append(base / f"index{ext}")
            candidates.append(base / f"__init__{ext}")
    for candidate in candidates:
        try:
            rel_candidate = candidate.relative_to(repo).as_posix()
        except ValueError:
            continue
        if rel_candidate in files_by_rel:
            return rel_candidate
    return None


def python_module_name(path: Path, repo: Path) -> str:
    rel_path = path.relative_to(repo).with_suffix("")
    parts = list(rel_path.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def build_python_module_map(files: list[Path], repo: Path) -> dict[str, str]:
    module_map: dict[str, str] = {}
    for path in files:
        if path.suffix.lower() != ".py":
            continue
        module = python_module_name(path, repo)
        if module:
            module_map[module] = rel(path, repo)
    return module_map


def resolve_python_import(source: Path, repo: Path, module: str | None, level: int, module_map: dict[str, str]) -> str | None:
    if level:
        current = python_module_name(source, repo).split(".")
        if source.name != "__init__.py":
            current = current[:-1]
        base = current[: max(0, len(current) - level + 1)]
        target = ".".join([*base, module or ""]).strip(".")
    else:
        target = module or ""
    if not target:
        return None
    if target in module_map:
        return module_map[target]
    pieces = target.split(".")
    while len(pieces) > 1:
        pieces.pop()
        prefix = ".".join(pieces)
        if prefix in module_map:
            return module_map[prefix]
    return None


def parse_python_edges(path: Path, repo: Path, module_map: dict[str, str]) -> list[dict[str, str]]:
    try:
        tree = ast.parse(read_text(path))
    except (SyntaxError, ValueError):
        return []
    edges = []
    source_rel = rel(path, repo)
    for node in ast.walk(tree):
        edges.extend(python_edges_for_node(node, path, repo, source_rel, module_map))
    return edges


def python_import_edge_for_alias(path: Path, repo: Path, source_rel: str, module_map: dict[str, str], alias: ast.alias) -> dict[str, str] | None:
    target = resolve_python_import(path, repo, alias.name, 0, module_map)
    if target and target != source_rel:
        return {"from": source_rel, "to": target, "kind": "import", "specifier": alias.name}
    return None


def python_edges_for_node(node: ast.AST, path: Path, repo: Path, source_rel: str, module_map: dict[str, str]) -> list[dict[str, str]]:
    if isinstance(node, ast.Import):
        return [
            edge
            for edge in (python_import_edge_for_alias(path, repo, source_rel, module_map, alias) for alias in node.names)
            if edge is not None
        ]
    if isinstance(node, ast.ImportFrom):
        target = resolve_python_import(path, repo, node.module, node.level, module_map)
        if target and target != source_rel:
            return [{"from": source_rel, "to": target, "kind": "import", "specifier": "." * node.level + (node.module or "")}]
    return []


def parse_text_edges(path: Path, repo: Path, files_by_rel: dict[str, Path]) -> list[dict[str, str]]:
    text = read_text(path)
    source_rel = rel(path, repo)
    edges = []
    suffix = path.suffix.lower()
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        for match in JS_IMPORT_RE.finditer(text):
            specifier = match.group(1)
            target = resolve_relative_import(repo, path, specifier, files_by_rel)
            if target and target != source_rel:
                edges.append({"from": source_rel, "to": target, "kind": "import", "specifier": specifier})
    elif suffix == ".go":
        in_block = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_block = True
                continue
            if in_block and stripped == ")":
                in_block = False
                continue
            if stripped.startswith("import "):
                edges.extend(go_import_edges(source_rel, stripped))
            elif in_block:
                edges.extend(go_import_edges(source_rel, stripped))
    return edges


def go_import_edges(source_rel: str, line: str) -> list[dict[str, str]]:
    return [{"from": source_rel, "to": match.group(1), "kind": "external", "specifier": match.group(1)} for match in GO_IMPORT_RE.finditer(line)]


def module_graph(repo: Path, config: dict[str, Any]) -> dict[str, Any]:
    files = source_files(repo, config)
    files_by_rel = {rel(path, repo): path for path in files}
    python_module_map = build_python_module_map(files, repo)
    edges: list[dict[str, str]] = []
    modules = []
    for path in files:
        source_rel = rel(path, repo)
        if path.suffix.lower() == ".py":
            edges.extend(parse_python_edges(path, repo, python_module_map))
        else:
            edges.extend(parse_text_edges(path, repo, files_by_rel))
        modules.append({"path": source_rel, "language": language_for_path(path), "lines": line_count(path)})

    local_edges = [edge for edge in edges if edge["to"] in files_by_rel]
    indegree: Counter[str] = Counter(edge["to"] for edge in local_edges)
    outdegree: Counter[str] = Counter(edge["from"] for edge in local_edges)
    for module in modules:
        module["inDegree"] = indegree[module["path"]]
        module["outDegree"] = outdegree[module["path"]]
    return {"modules": sorted(modules, key=lambda item: item["path"]), "edges": sorted(local_edges, key=lambda item: (item["from"], item["to"]))}


def canonical_cycle(cycle: list[str]) -> tuple[str, ...]:
    body = cycle[:-1] if cycle and cycle[0] == cycle[-1] else cycle
    rotations = [tuple(body[index:] + body[:index]) for index in range(len(body))]
    best = min(rotations)
    return best + (best[0],)


def find_cycles(edges: list[dict[str, str]], max_cycles: int = 20) -> list[list[str]]:
    graph: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        graph[edge["from"]].append(edge["to"])
    graph = defaultdict(list, {node: sorted(set(targets)) for node, targets in graph.items()})
    cycles: set[tuple[str, ...]] = set()

    for node in sorted(graph):
        find_cycles_from_node(graph, node, cycles, max_cycles)
        if len(cycles) >= max_cycles:
            break
    return [list(cycle) for cycle in sorted(cycles)[:max_cycles]]


def find_cycles_from_node(graph: dict[str, list[str]], node: str, cycles: set[tuple[str, ...]], max_cycles: int) -> None:
    stack: list[tuple[str, int]] = [(node, 0)]
    path: list[str] = [node]
    active = {node}
    while stack and len(cycles) < max_cycles:
        current, index = stack[-1]
        targets = graph.get(current, [])
        if index >= len(targets):
            stack.pop()
            active.remove(path.pop())
            continue
        target = targets[index]
        stack[-1] = (current, index + 1)
        if target in active:
            cycle_start = path.index(target)
            cycles.add(canonical_cycle(path[cycle_start:] + [target]))
        elif target in graph:
            active.add(target)
            path.append(target)
            stack.append((target, 0))


def mermaid_id(label: str) -> str:
    digest = hashlib.sha256(label.encode("utf-8")).hexdigest()[:8]
    return f"N{digest}"


def mermaid_label(label: str) -> str:
    return (
        label.replace("\\", "\\\\")
        .replace('"', "'")
        .replace("`", "'")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def render_module_mermaid(edges: list[dict[str, str]], max_edges: int) -> str:
    if not edges:
        return "graph TD\n  empty[\"No local module dependencies detected\"]"
    lines = ["graph TD"]
    for edge in edges[:max_edges]:
        lines.append(f"  {mermaid_id(edge['from'])}[\"{mermaid_label(edge['from'])}\"] --> {mermaid_id(edge['to'])}[\"{mermaid_label(edge['to'])}\"]")
    return "\n".join(lines)


def render_service_mermaid(services: list[dict[str, Any]]) -> str:
    if not services:
        return "graph TD\n  empty[\"No services detected\"]"
    lines = ["graph TD"]
    names = {service["name"] for service in services}
    for service in services:
        lines.extend(service_mermaid_lines(service, names))
    return "\n".join(lines)


def service_mermaid_lines(service: dict[str, Any], names: set[str]) -> list[str]:
    sid = mermaid_id(service["name"])
    label = f"{service['name']}\\n{service['type']}"
    lines = [f"  {sid}[\"{mermaid_label(label)}\"]"]
    for dep in service.get("dependsOn", []):
        did = mermaid_id(dep)
        if dep not in names:
            lines.append(f"  {did}[\"{mermaid_label(dep)}\"]")
        lines.append(f"  {sid} --> {did}")
    return lines


def route_counts_by_source(services: list[dict[str, Any]]) -> Counter[str]:
    return Counter(route["source"] for service in services for route in service.get("routes", []))


def architecture_findings(
    graph: dict[str, Any],
    cycles: list[list[str]],
    services: list[dict[str, Any]],
    detect_god_modules: bool,
) -> list[dict[str, Any]]:
    findings = []
    for cycle in cycles:
        findings.append(
            architecture_finding(
                tag="circular-dependency",
                severity="high" if len(cycle) > 3 else "medium",
                confidence="high",
                title="Circular module dependency detected",
                path=cycle[0],
                line=None,
                evidence=" -> ".join(cycle),
                impact="Circular imports increase initialization risk and make module boundaries harder to change.",
                recommendation="Break the cycle by moving shared contracts to a neutral module or inverting one dependency.",
                effort="medium",
                roi="high",
            )
        )

    if not detect_god_modules:
        return findings

    route_counts = route_counts_by_source(services)
    for module in graph["modules"]:
        route_count = route_counts[module["path"]]
        if module["lines"] >= 800 or module["inDegree"] >= 12 or module["outDegree"] >= 12 or route_count >= 10:
            findings.append(
                architecture_finding(
                    tag="god-module",
                    severity="medium",
                    confidence="medium",
                    title="God module candidate",
                    path=module["path"],
                    line=None,
                    evidence=f"lines={module['lines']}, fan-in={module['inDegree']}, fan-out={module['outDegree']}, routes={route_count}",
                    impact="High responsibility concentration raises change risk and test blast radius.",
                    recommendation="Confirm responsibilities, then extract cohesive submodules behind stable interfaces.",
                    effort="medium",
                    roi="medium",
                )
            )
    return findings


def map_architecture(repo: Path, config: dict[str, Any]) -> dict[str, Any]:
    architecture_config = config.get("architecture", {})
    report_config = config.get("report", {})
    graph = module_graph(repo, config) if architecture_config.get("mapImports", True) else {"modules": [], "edges": []}
    files = [repo / module["path"] for module in graph["modules"]]
    services = detect_services(repo, config, files) if architecture_config.get("mapServices", True) else []
    cycles = find_cycles(graph["edges"]) if architecture_config.get("detectCycles", True) else []
    findings = architecture_findings(graph, cycles, services, bool(architecture_config.get("detectGodModules", True)))
    include_diagrams = bool(report_config.get("includeMermaidDiagrams", False))
    max_edges = int(architecture_config.get("maxGraphEdges", 160))

    return {
        "modules": graph["modules"],
        "edges": graph["edges"],
        "cycles": cycles,
        "services": services,
        "diagrams": {
            "moduleGraph": render_module_mermaid(graph["edges"], max_edges) if include_diagrams else None,
            "serviceTopology": render_service_mermaid(services) if include_diagrams else None,
        },
        "summary": {
            "moduleCount": len(graph["modules"]),
            "edgeCount": len(graph["edges"]),
            "cycleCount": len(cycles),
            "serviceCount": len(services),
            "routeCount": sum(len(service.get("routes", [])) for service in services),
        },
        "findings": findings,
    }
