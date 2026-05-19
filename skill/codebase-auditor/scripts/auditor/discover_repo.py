from __future__ import annotations

import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


LANGUAGE_BY_EXT = {
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".py": "Python",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".scala": "Scala",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".c": "C",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".sql": "SQL",
    ".tf": "Terraform",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
}

MANIFESTS = {
    "package.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "package-lock.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "python",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pipenv",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "go.mod": "go",
    "go.sum": "go",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "composer.json": "composer",
    "composer.lock": "composer",
    "Dockerfile": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "Makefile": "make",
}

SOURCE_EXTENSIONS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".cs",
    ".rb",
    ".php",
    ".swift",
    ".scala",
    ".cpp",
    ".cc",
    ".cxx",
    ".c",
    ".h",
    ".hpp",
}

SOURCE_LANGUAGES = {
    "JavaScript",
    "TypeScript",
    "Python",
    "Go",
    "Rust",
    "Java",
    "Kotlin",
    "C#",
    "Ruby",
    "PHP",
    "Swift",
    "Scala",
    "C++",
    "C",
    "C/C++ Header",
    "C++ Header",
    "SQL",
}

_TEXT_CACHE: dict[tuple[str, int, int], str] = {}


def normalize_excludes(excludes: Iterable[str]) -> set[str]:
    return {str(part).replace("\\", "/").strip("/") for part in excludes if str(part).strip("/\\")}


def is_excluded(path: Path, repo: Path, excludes: set[str]) -> bool:
    try:
        rel_parts = path.relative_to(repo).parts
    except ValueError:
        rel_parts = path.parts
    rel_path = Path(*rel_parts).as_posix() if rel_parts else ""
    for excluded in excludes:
        if "/" in excluded:
            if rel_path == excluded or rel_path.startswith(f"{excluded}/"):
                return True
        elif excluded in rel_parts:
            return True
    return False


def regular_file_size(path: Path) -> int | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    return metadata.st_size


def repo_files_in_directory(root_path: Path, file_names: list[str], repo: Path, exclude_set: set[str], max_bytes: int | None = None) -> list[tuple[Path, int]]:
    files = []
    for file_name in file_names:
        path = root_path / file_name
        if is_excluded(path, repo, exclude_set):
            continue
        size = regular_file_size(path)
        if size is None or (max_bytes is not None and size > max_bytes):
            continue
        files.append((path, size))
    return files


def prime_repo_cache(repo: Path, config: dict[str, Any]) -> None:
    _TEXT_CACHE.clear()
    repo = repo.resolve()
    exclude_set = normalize_excludes(config.get("exclude", []))
    cache_files: list[tuple[Path, int]] = []
    for root, dirs, file_names in os.walk(repo):
        root_path = Path(root)
        dirs[:] = [directory for directory in dirs if not is_excluded(root_path / directory, repo, exclude_set)]
        if is_excluded(root_path, repo, exclude_set):
            continue
        cache_files.extend(repo_files_in_directory(root_path, file_names, repo, exclude_set))
    config["_repoFileCache"] = cache_files


def iter_repo_files(repo: Path, excludes: Iterable[str] | dict[str, Any], max_bytes: int = 1_000_000) -> Iterable[Path]:
    if isinstance(excludes, dict):
        if "_repoFileCache" not in excludes:
            prime_repo_cache(repo, excludes)
        for path, size in excludes.get("_repoFileCache", []):
            if size <= max_bytes:
                yield path
        return

    exclude_set = normalize_excludes(excludes)
    for root, dirs, file_names in os.walk(repo):
        root_path = Path(root)
        dirs[:] = [directory for directory in dirs if not is_excluded(root_path / directory, repo, exclude_set)]
        if is_excluded(root_path, repo, exclude_set):
            continue
        yield from (path for path, _size in repo_files_in_directory(root_path, file_names, repo, exclude_set, max_bytes))


def rel(path: Path, repo: Path) -> str:
    return path.relative_to(repo).as_posix()


def read_text(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError:
        return ""
    if not stat.S_ISREG(metadata.st_mode):
        return ""
    try:
        key = (path.resolve().as_posix(), metadata.st_mtime_ns, metadata.st_size)
    except OSError:
        return ""
    if key in _TEXT_CACHE:
        return _TEXT_CACHE[key]
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    _TEXT_CACHE[key] = text
    return text


def detect_package_json(path: Path) -> tuple[set[str], dict[str, str]]:
    frameworks: set[str] = set()
    commands: dict[str, str] = {}
    try:
        payload = json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return frameworks, commands

    scripts = payload.get("scripts", {})
    if isinstance(scripts, dict):
        for key in ["test", "build", "lint", "typecheck", "check", "bench"]:
            if key in scripts and isinstance(scripts[key], str):
                commands[key] = f"npm run {key}"

    deps = {}
    for field in ["dependencies", "devDependencies", "peerDependencies"]:
        value = payload.get(field, {})
        if isinstance(value, dict):
            deps.update(value)

    framework_map = {
        "react": "React",
        "next": "Next.js",
        "vue": "Vue",
        "nuxt": "Nuxt",
        "@angular/core": "Angular",
        "svelte": "Svelte",
        "express": "Express",
        "fastify": "Fastify",
        "@nestjs/core": "NestJS",
        "prisma": "Prisma",
    }
    for dep, framework in framework_map.items():
        if dep in deps:
            frameworks.add(framework)
    return frameworks, commands


def detect_python_frameworks(path: Path) -> set[str]:
    text = read_text(path).lower()
    frameworks = set()
    for needle, name in [
        ("django", "Django"),
        ("fastapi", "FastAPI"),
        ("flask", "Flask"),
        ("sqlalchemy", "SQLAlchemy"),
        ("celery", "Celery"),
        ("pytest", "pytest"),
    ]:
        if re.search(rf"\b{re.escape(needle)}\b", text):
            frameworks.add(name)
    return frameworks


def discover_repo(repo: Path, config: dict[str, Any]) -> dict[str, Any]:
    repo = repo.resolve()
    languages: Counter[str] = Counter()
    language_bytes: Counter[str] = Counter()
    language_lines: Counter[str] = Counter()
    manifests: list[dict[str, str]] = []
    package_managers: set[str] = set()
    frameworks: set[str] = set()
    commands: dict[str, str] = {}
    infra: set[str] = set()
    total_files = 0
    source_files = 0
    source_lines = 0

    for path in iter_repo_files(repo, config):
        total_files += 1
        ext = path.suffix.lower()
        language = LANGUAGE_BY_EXT.get(ext)
        if language:
            languages[language] += 1
            line_total = len(read_text(path).splitlines())
            language_lines[language] += line_total
            try:
                language_bytes[language] += path.stat().st_size
            except OSError:
                pass
            if language in SOURCE_LANGUAGES:
                source_files += 1
                source_lines += line_total

        name = path.name
        if name in MANIFESTS:
            manager = MANIFESTS[name]
            manifests.append({"path": rel(path, repo), "type": manager})
            if manager in {"docker", "docker-compose"}:
                infra.add(manager)
            elif manager != "make":
                package_managers.add(manager)

        if name == "package.json":
            found_frameworks, found_commands = detect_package_json(path)
            frameworks.update(found_frameworks)
            commands.update(found_commands)
        elif name in {"requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock"}:
            frameworks.update(detect_python_frameworks(path))
            if "test" not in commands:
                commands["test"] = "python -m pytest"
        elif name == "Makefile":
            commands.setdefault("make", "make")

        rel_path = rel(path, repo)
        if rel_path.startswith(".github/workflows/"):
            infra.add("github-actions")
        if ext == ".tf":
            infra.add("terraform")
        if ext in {".yml", ".yaml"}:
            text = read_text(path)[:4000]
            if "kind: Deployment" in text or "apiVersion: apps/" in text:
                infra.add("kubernetes")

    language_rows = [
        {"name": name, "files": count, "lines": language_lines[name], "bytes": language_bytes[name]}
        for name, count in languages.most_common()
    ]
    source_language_rows = [row for row in language_rows if row["name"] in SOURCE_LANGUAGES]
    primary = source_language_rows[0]["name"] if source_language_rows else (language_rows[0]["name"] if language_rows else None)

    return {
        "root": repo.as_posix(),
        "totals": {
            "files": total_files,
            "sourceFiles": source_files,
            "sourceLines": source_lines,
        },
        "primaryLanguage": primary,
        "languages": language_rows,
        "packageManagers": sorted(package_managers),
        "frameworks": sorted(frameworks),
        "manifests": sorted(manifests, key=lambda item: item["path"]),
        "infrastructure": sorted(infra),
        "commands": commands,
    }
