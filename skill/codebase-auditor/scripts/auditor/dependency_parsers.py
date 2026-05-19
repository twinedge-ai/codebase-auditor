from __future__ import annotations

import json
import re
import stat
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .discover_repo import iter_repo_files, read_text, rel


MAX_XML_BYTES = 5_000_000


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str
    manager: str
    path: str
    line: int | None = None
    scope: str | None = None

    def key(self) -> tuple[str, str, str | None, str]:
        return (self.ecosystem, self.name.lower(), self.version, self.path)


def split_name_version(value: str) -> tuple[str, str | None]:
    value = value.strip().strip('"').strip("'").lstrip("/")
    if value.startswith("@"):
        idx = value.rfind("@")
        return (value[:idx], value[idx + 1 :]) if idx > 0 else (value, None)
    if "@" in value:
        return value.rsplit("@", 1)
    return value, None


def package_name_from_selector(selector: str) -> str:
    selector = selector.strip().strip('"').strip("'")
    if selector.startswith("@"):
        parts = selector.split("@")
        return "@".join(parts[:2])
    return selector.split("@", 1)[0]


def safe_xml_root(path: Path) -> ET.Element | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    if metadata.st_size > MAX_XML_BYTES:
        return None
    try:
        payload = path.read_bytes()
    except OSError:
        return None
    if len(payload) > MAX_XML_BYTES:
        return None
    lowered = payload.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        return None
    try:
        return ET.fromstring(payload)
    except ET.ParseError:
        return None


def parse_package_json(repo: Path, path: Path) -> list[Dependency]:
    try:
        payload = json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return []

    deps: list[Dependency] = []
    rel_path = rel(path, repo)
    for scope in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        deps.extend(package_json_dependencies(payload.get(scope, {}), rel_path, scope))
    return deps


def package_json_dependencies(values: object, rel_path: str, scope: str) -> list[Dependency]:
    if not isinstance(values, dict):
        return []
    return [
        Dependency(str(name), str(version) if isinstance(version, str) else None, "npm", "npm", rel_path, scope=scope)
        for name, version in values.items()
    ]


def parse_package_lock(repo: Path, path: Path) -> list[Dependency]:
    try:
        payload = json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return []

    rel_path = rel(path, repo)
    deps: list[Dependency] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for package_path, meta in packages.items():
            if not package_path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or package_path.split("node_modules/")[-1]
            version = meta.get("version")
            if name and version:
                deps.append(Dependency(str(name), str(version), "npm", "npm", rel_path, scope="lockfile"))

    def walk(values: dict[str, Any]) -> None:
        for name, meta in values.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version:
                deps.append(Dependency(str(name), str(version), "npm", "npm", rel_path, scope="lockfile"))
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                walk(nested)

    root_deps = payload.get("dependencies")
    if isinstance(root_deps, dict):
        walk(root_deps)
    return deps


def parse_pnpm_lock(repo: Path, path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    rel_path = rel(path, repo)
    in_packages = False
    for index, line in enumerate(read_text(path).splitlines(), start=1):
        if re.match(r"^\S", line):
            in_packages = line.strip() == "packages:"
            continue
        if not in_packages:
            continue
        match = re.match(r"\s{2}['\"]?/?([^'\"\s:]+(?:/[^'\"\s:]+)?@[^'\"\s:()]+)(?:\([^'\"]*\))?['\"]?:\s*$", line)
        if not match:
            continue
        name, version = split_name_version(match.group(1))
        if version:
            deps.append(Dependency(name, version, "npm", "pnpm", rel_path, index, "lockfile"))
    return deps


def parse_yarn_lock(repo: Path, path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    rel_path = rel(path, repo)
    current_name: str | None = None
    current_line: int | None = None
    for index, line in enumerate(read_text(path).splitlines(), start=1):
        if line and not line.startswith((" ", "\t")) and line.endswith(":"):
            selector = line[:-1].split(",", 1)[0].strip().strip('"').strip("'")
            if selector == "__metadata":
                current_name = None
                continue
            current_name = package_name_from_selector(selector)
            current_line = index
        elif current_name:
            match = re.match(r'''\s+version(?::\s*|\s+)["']?([^"'\s]+)["']?''', line)
            if match:
                deps.append(Dependency(current_name, match.group(1), "npm", "yarn", rel_path, current_line, "lockfile"))
                current_name = None
    return deps


def parse_requirements(repo: Path, path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    rel_path = rel(path, repo)
    pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(==|~=|>=|<=|>|<)?\s*([A-Za-z0-9_.!*+-]+)?")
    for index, raw_line in enumerate(read_text(path).splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "http:", "https:", "git+")):
            continue
        match = pattern.match(line)
        if match:
            version = match.group(3) if match.group(2) == "==" else None
            deps.append(Dependency(match.group(1), version, "PyPI", "pip", rel_path, index))
    return deps


def parse_poetry_lock(repo: Path, path: Path) -> list[Dependency]:
    try:
        payload = tomllib.loads(read_text(path))
    except Exception:
        return []
    rel_path = rel(path, repo)
    deps = []
    for package in payload.get("package", []):
        if isinstance(package, dict) and package.get("name") and package.get("version"):
            deps.append(Dependency(str(package["name"]), str(package["version"]), "PyPI", "poetry", rel_path, scope="lockfile"))
    return deps


def parse_pipfile_lock(repo: Path, path: Path) -> list[Dependency]:
    try:
        payload = json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return []
    deps: list[Dependency] = []
    rel_path = rel(path, repo)
    for scope in ["default", "develop"]:
        deps.extend(pipfile_scope_dependencies(payload.get(scope, {}), rel_path, scope))
    return deps


def pipfile_scope_dependencies(values: object, rel_path: str, scope: str) -> list[Dependency]:
    if not isinstance(values, dict):
        return []
    return [
        Dependency(str(name), pipfile_dependency_version(meta), "PyPI", "pipenv", rel_path, scope=scope)
        for name, meta in values.items()
    ]


def pipfile_dependency_version(meta: object) -> str | None:
    if not isinstance(meta, dict):
        return None
    return str(meta.get("version", "")).lstrip("=") or None


def parse_cargo_lock(repo: Path, path: Path) -> list[Dependency]:
    try:
        payload = tomllib.loads(read_text(path))
    except Exception:
        return []
    rel_path = rel(path, repo)
    deps = []
    for package in payload.get("package", []):
        if isinstance(package, dict) and package.get("name") and package.get("version"):
            deps.append(Dependency(str(package["name"]), str(package["version"]), "crates.io", "cargo", rel_path, scope="lockfile"))
    return deps


def parse_pom(repo: Path, path: Path) -> list[Dependency]:
    root = safe_xml_root(path)
    if root is None:
        return []
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    rel_path = rel(path, repo)
    deps: list[Dependency] = []
    for dep in root_dependencies(root, ns):
        group = dep.findtext("m:groupId", namespaces=ns) or dep.findtext("groupId")
        artifact = dep.findtext("m:artifactId", namespaces=ns) or dep.findtext("artifactId")
        version = dep.findtext("m:version", namespaces=ns) or dep.findtext("version")
        if group and artifact:
            deps.append(Dependency(f"{group}:{artifact}", version, "Maven", "maven", rel_path))
    return deps


def root_dependencies(root: ET.Element, ns: dict[str, str]) -> list[ET.Element]:
    namespaced = list(root.findall(".//m:dependency", ns))
    plain = list(root.findall(".//dependency"))
    return namespaced + [dep for dep in plain if dep not in namespaced]


def parse_gradle(repo: Path, path: Path) -> list[Dependency]:
    deps: list[Dependency] = []
    rel_path = rel(path, repo)
    pattern = re.compile(r"['\"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^'\"]+)['\"]")
    for index, line in enumerate(read_text(path).splitlines(), start=1):
        deps.extend(gradle_line_dependencies(pattern, line, rel_path, index))
    return deps


def gradle_line_dependencies(pattern: re.Pattern[str], line: str, rel_path: str, index: int) -> list[Dependency]:
    return [
        Dependency(f"{match.group(1)}:{match.group(2)}", match.group(3), "Maven", "gradle", rel_path, index)
        for match in pattern.finditer(line)
    ]


def parse_dotnet_lock(repo: Path, path: Path) -> list[Dependency]:
    try:
        payload = json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return []
    deps = []
    rel_path = rel(path, repo)
    libraries = payload.get("libraries", {})
    if isinstance(libraries, dict):
        for key in libraries:
            name, version = split_name_version(key)
            if name and version:
                deps.append(Dependency(name, version, "NuGet", "nuget", rel_path, scope="lockfile"))
    return deps


def parse_csproj(repo: Path, path: Path) -> list[Dependency]:
    root = safe_xml_root(path)
    if root is None:
        return []
    deps = []
    rel_path = rel(path, repo)
    for item in root.iter():
        if item.tag.endswith("PackageReference"):
            name = item.attrib.get("Include") or item.attrib.get("Update")
            version = package_reference_version(item)
            if name:
                deps.append(Dependency(name, version, "NuGet", "nuget", rel_path))
    return deps


def package_reference_version(item: ET.Element) -> str | None:
    version = item.attrib.get("Version")
    if version:
        return version
    for child in item:
        if child.tag.endswith("Version") and child.text:
            return child.text.strip()
    return None


def collect_dependencies(repo: Path, config: dict[str, Any]) -> list[Dependency]:
    parsers = {
        "package.json": parse_package_json,
        "package-lock.json": parse_package_lock,
        "pnpm-lock.yaml": parse_pnpm_lock,
        "yarn.lock": parse_yarn_lock,
        "requirements.txt": parse_requirements,
        "poetry.lock": parse_poetry_lock,
        "Pipfile.lock": parse_pipfile_lock,
        "Cargo.lock": parse_cargo_lock,
        "pom.xml": parse_pom,
        "build.gradle": parse_gradle,
        "build.gradle.kts": parse_gradle,
        "packages.lock.json": parse_dotnet_lock,
    }
    deps: list[Dependency] = []
    for path in iter_repo_files(repo, config, max_bytes=5_000_000):
        parser = parsers.get(path.name)
        if parser:
            deps.extend(parser(repo, path))
        elif path.suffix.lower() in {".csproj", ".fsproj", ".vbproj"}:
            deps.extend(parse_csproj(repo, path))

    seen: set[tuple[str, str, str | None, str]] = set()
    unique: list[Dependency] = []
    for dep in deps:
        if dep.key() in seen:
            continue
        seen.add(dep.key())
        unique.append(dep)
    return unique
