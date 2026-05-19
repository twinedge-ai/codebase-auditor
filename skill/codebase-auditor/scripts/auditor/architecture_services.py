from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .discover_repo import iter_repo_files, read_text, rel


ROUTE_PATTERNS = [
    re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete|all)\s*\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"@\w+\.(get|post|put|patch|delete|route)\s*\(\s*['\"]([^'\"]+)['\"]"),
]


def route_match(line: str) -> re.Match[str] | None:
    for pattern in ROUTE_PATTERNS:
        match = pattern.search(line)
        if match:
            return match
    return None


def collect_file_routes(repo: Path, path: Path) -> list[dict[str, Any]]:
    routes = []
    source = rel(path, repo)
    for index, line in enumerate(read_text(path).splitlines(), start=1):
        match = route_match(line)
        if match:
            routes.append({"method": match.group(1).upper(), "path": match.group(2), "source": source, "line": index})
    return routes


def collect_routes(repo: Path, files: list[Path], service_root: Path | None = None) -> list[dict[str, Any]]:
    routes = []
    for path in files:
        if service_root:
            try:
                path.relative_to(service_root)
            except ValueError:
                continue
        if path.suffix.lower() not in {".js", ".jsx", ".ts", ".tsx", ".py"}:
            continue
        routes.extend(collect_file_routes(repo, path))
    return routes


def service_name_from_package(path: Path) -> str | None:
    try:
        payload = json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return None
    name = payload.get("name")
    return str(name) if isinstance(name, str) and name else None


def parse_compose_services(repo: Path, path: Path) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_services = False
    in_ports = False
    in_depends = False
    for line in read_text(path).splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if not in_services:
            continue
        service_match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if service_match:
            current = {"name": service_match.group(1), "type": "docker-compose", "path": rel(path, repo), "ports": [], "dependsOn": [], "routes": []}
            services.append(current)
            in_ports = False
            in_depends = False
            continue
        if not current:
            continue
        stripped = line.strip()
        if re.match(r"^[A-Za-z0-9_.-]+:\s*$", stripped) and not line.startswith("    "):
            break
        if stripped == "ports:":
            in_ports = True
            in_depends = False
            continue
        if stripped == "depends_on:":
            in_depends = True
            in_ports = False
            continue
        if stripped.endswith(":") and not stripped.startswith("-"):
            in_ports = False
            in_depends = False
        item = re.match(r"^-\s*['\"]?([^'\"]+)['\"]?\s*$", stripped)
        if item and in_ports:
            current["ports"].append(item.group(1))
        elif item and in_depends:
            current["dependsOn"].append(item.group(1))
    return services


def _parse_kubernetes_document(repo: Path, path: Path, text: str) -> dict[str, Any] | None:
    kind_match = re.search(r"(?m)^kind:\s*(Service|Deployment)\s*$", text)
    if not kind_match:
        return None
    name = _extract_top_level_metadata_name(text)
    if not name:
        return None
    ports = re.findall(r"(?m)^\s*-?\s*(?:containerPort|port):\s*(\d+)\s*$", text)
    return {"name": name, "type": f"kubernetes-{kind_match.group(1).lower()}", "path": rel(path, repo), "ports": ports, "dependsOn": [], "routes": []}


def parse_kubernetes_services(repo: Path, path: Path) -> list[dict[str, Any]]:
    documents = re.split(r"(?m)^---\s*$", read_text(path))
    services = []
    for document in documents:
        service = _parse_kubernetes_document(repo, path, document)
        if service:
            services.append(service)
    return services


def parse_kubernetes_service(repo: Path, path: Path) -> dict[str, Any] | None:
    services = parse_kubernetes_services(repo, path)
    return services[0] if services else None


def _extract_top_level_metadata_name(text: str) -> str | None:
    lines = text.splitlines()
    in_metadata = False
    metadata_indent = -1
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        meta_match = re.match(r"^(\s*)metadata:\s*$", line)
        if meta_match and len(meta_match.group(1)) == 0:
            in_metadata = True
            metadata_indent = 0
            continue
        if not in_metadata:
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= metadata_indent:
            return None
        if current_indent != metadata_indent + 2:
            continue
        name_match = re.match(r"^\s+name:\s*([A-Za-z0-9_.-]+)\s*$", line)
        if name_match:
            return name_match.group(1)
    return None


def detect_services(repo: Path, config: dict[str, Any], files: list[Path]) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for path in iter_repo_files(repo, config, max_bytes=2_000_000):
        if path.name in {"docker-compose.yml", "docker-compose.yaml"}:
            services.extend(parse_compose_services(repo, path))
        elif path.name == "package.json":
            name = service_name_from_package(path)
            if name:
                root = path.parent
                services.append({"name": name, "type": "package", "path": rel(path, repo), "ports": [], "dependsOn": [], "routes": collect_routes(repo, files, root)})
        elif path.name == "Dockerfile":
            service_name = path.parent.name if path.parent != repo else "dockerfile"
            services.append({"name": service_name, "type": "dockerfile", "path": rel(path, repo), "ports": [], "dependsOn": [], "routes": collect_routes(repo, files, path.parent)})
        elif path.suffix.lower() in {".yml", ".yaml"}:
            services.extend(parse_kubernetes_services(repo, path))

    if not services:
        routes = collect_routes(repo, files)
        if routes:
            services.append({"name": "application", "type": "routes", "path": routes[0]["source"], "ports": [], "dependsOn": [], "routes": routes})

    unique = []
    for service in services:
        key = (service["type"], service["name"], service["path"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(service)
    return sorted(unique, key=lambda item: (item["type"], item["name"], item["path"]))
