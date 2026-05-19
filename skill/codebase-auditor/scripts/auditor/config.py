from __future__ import annotations

import copy
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


MAX_CONFIG_BYTES = 1_000_000
MAX_CONFIG_WARNING_PATHS = 20
MAX_CONFIG_WARNING_PATH_LENGTH = 180


class ConfigError(ValueError):
    pass


# Operator-only keys (dot-paths) cannot be sourced from a scanned repository's
# .codebase-auditor.json. They control which executables run, which network
# endpoints are reached, and which run-time gates are open — all of which
# belong to the operator's trust scope. An explicit --config path is still
# treated as operator-supplied.
OPERATOR_ONLY_PATHS: tuple[str, ...] = (
    "exclude",
    "externalTools",
    "maxFindings",
    "testCommands",
    "allowNetwork",
    "allowMocks",
    "allowPerfTests",
    "allowPrivateNetwork",
    "security.scanSecrets",
    "security.dependencyAudit",
    "security.staticSecurity",
    "security.runNpmAudit",
    "security.runPipAudit",
    "security.runCargoAudit",
    "security.runTrivy",
    "security.runGitleaks",
    "security.runSemgrep",
    "security.semgrepConfig",
    "frontend.url",
    "frontend.runLighthouse",
    "frontend.probeRequests",
    "performance.targets",
    "performance.runLoadTests",
    "performance.runAutocannon",
    "performance.runK6",
    "performance.runBenchmarks",
    "performance.confirmBenchmarks",
    "performance.requests",
    "performance.concurrency",
    "performance.timeoutSeconds",
    "performance.maxDurationSeconds",
    "performance.k6Script",
    "performance.lighthouseMockPath",
    "performance.lighthouseNoSandbox",
)

REPO_LOCAL_ALLOWED_TYPES: dict[str, type[Any]] = {
    "report.includeMermaidDiagrams": bool,
    "report.includeRemediationPlan": bool,
}

CONFIG_SECTION_PATHS = {"frontend", "security", "performance", "architecture", "report"}
CONFIG_BOOLEAN_PATHS = {
    "allowNetwork",
    "allowMocks",
    "allowPerfTests",
    "allowPrivateNetwork",
    "frontend.runLighthouse",
    "security.scanSecrets",
    "security.dependencyAudit",
    "security.staticSecurity",
    "security.runNpmAudit",
    "security.runPipAudit",
    "security.runCargoAudit",
    "security.runTrivy",
    "security.runGitleaks",
    "security.runSemgrep",
    "performance.runLoadTests",
    "performance.runAutocannon",
    "performance.runK6",
    "performance.runBenchmarks",
    "performance.confirmBenchmarks",
    "performance.lighthouseNoSandbox",
    "architecture.mapImports",
    "architecture.mapServices",
    "architecture.detectCycles",
    "architecture.detectGodModules",
    "report.includeMermaidDiagrams",
    "report.includeRemediationPlan",
}
CONFIG_INT_PATHS = {
    "frontend.probeRequests",
    "performance.requests",
    "performance.concurrency",
    "performance.maxDurationSeconds",
    "architecture.maxGraphNodes",
    "architecture.maxGraphEdges",
}
CONFIG_NUMBER_PATHS = {"performance.timeoutSeconds"}
CONFIG_STRING_OR_NULL_PATHS = {
    "frontend.url",
    "performance.k6Script",
    "performance.lighthouseMockPath",
}
CONFIG_STRING_PATHS = {"profile", "severityThreshold", "security.semgrepConfig"}
CONFIG_STRING_LIST_PATHS = {"exclude", "testCommands"}
CONFIG_STRING_LIST_OR_STRING_PATHS = {"performance.targets"}
CONFIG_STRING_DICT_PATHS = {"externalTools"}
VALID_PROFILES = {"quick-static", "complexity", "security", "architecture", "performance", "full"}
VALID_REPORT_FORMATS = {"markdown", "json", "html"}


def skill_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_config_path() -> Path:
    return skill_root() / "assets" / "default-config.json"


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def strip_operator_only_keys(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    sanitized = payload
    removed: list[str] = []
    for path in OPERATOR_ONLY_PATHS:
        parts = path.split(".")
        cursor = operator_path_parent(sanitized, parts)
        if isinstance(cursor, dict) and parts[-1] in cursor:
            del cursor[parts[-1]]
            removed.append(path)
    return sanitized, removed


def operator_path_parent(payload: dict[str, Any], parts: list[str]) -> Any:
    cursor: Any = payload
    for part in parts[:-1]:
        if not isinstance(cursor, dict) or part not in cursor:
            return None
        cursor = cursor[part]
    return cursor


def _has_repo_local_allowed_descendant(path: str) -> bool:
    prefix = f"{path}."
    return any(allowed_path.startswith(prefix) for allowed_path in REPO_LOCAL_ALLOWED_TYPES)


def _repo_config_leaf_paths(path: str, value: Any) -> list[str]:
    paths: list[str] = []
    stack: list[tuple[str, Any]] = [(path, value)]
    while stack:
        current_path, current_value = stack.pop()
        if isinstance(current_value, dict) and current_value:
            stack.extend((f"{current_path}.{key}", child) for key, child in reversed(list(current_value.items())))
        else:
            paths.append(current_path)
    return paths


def format_config_paths(paths: list[str]) -> str:
    unique_paths = list(dict.fromkeys(paths))
    visible = unique_paths[:MAX_CONFIG_WARNING_PATHS]

    def clipped(path: str) -> str:
        if len(path) <= MAX_CONFIG_WARNING_PATH_LENGTH:
            return path
        return f"{path[: MAX_CONFIG_WARNING_PATH_LENGTH - 3]}..."

    formatted = ", ".join(clipped(path) for path in visible)
    remaining = len(unique_paths) - len(visible)
    if remaining > 0:
        formatted = f"{formatted}, ... (+{remaining} more)"
    return formatted


def _set_nested_value(target: dict[str, Any], path: str, value: Any) -> None:
    cursor: dict[str, Any] = target
    parts = path.split(".")
    for part in parts[:-1]:
        next_cursor = cursor.setdefault(part, {})
        if not isinstance(next_cursor, dict):
            next_cursor = {}
            cursor[part] = next_cursor
        cursor = next_cursor
    cursor[parts[-1]] = value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_string_dict(value: Any) -> bool:
    return isinstance(value, dict) and all(isinstance(item, str) for item in value.values())


def validate_explicit_config(payload: dict[str, Any], source: Path) -> None:
    errors: list[str] = []

    def add(path: str, expected: str) -> None:
        errors.append(f"{path} must be {expected}")

    def visit(path: str, value: Any) -> None:
        if path in CONFIG_SECTION_PATHS:
            if not isinstance(value, dict):
                add(path, "a JSON object")
                return
            for key, child in value.items():
                visit(f"{path}.{key}", child)
            return

        if path in CONFIG_BOOLEAN_PATHS:
            if type(value) is not bool:
                add(path, "a JSON boolean")
            return

        if path in CONFIG_INT_PATHS:
            if not _is_int(value) or value < 0:
                add(path, "a non-negative JSON integer")
            return

        if path in CONFIG_NUMBER_PATHS:
            if not _is_number(value) or value < 0:
                add(path, "a non-negative JSON number")
            return

        if path in CONFIG_STRING_OR_NULL_PATHS:
            if value is not None and not isinstance(value, str):
                add(path, "a string or null")
            return

        if path in CONFIG_STRING_PATHS:
            if not isinstance(value, str):
                add(path, "a string")
                return
            if path == "profile" and value not in VALID_PROFILES:
                add(path, f"one of {', '.join(sorted(VALID_PROFILES))}")
            return

        if path in CONFIG_STRING_LIST_PATHS:
            if not _is_string_list(value):
                add(path, "a list of strings")
            return

        if path in CONFIG_STRING_LIST_OR_STRING_PATHS:
            if not isinstance(value, str) and not _is_string_list(value):
                add(path, "a string or list of strings")
            return

        if path in CONFIG_STRING_DICT_PATHS:
            if not _is_string_dict(value):
                add(path, "an object with string values")
            return

        if path == "maxFindings":
            if _is_int(value) and value >= 0:
                return
            if isinstance(value, str) and value.lower() == "all":
                return
            add(path, "a non-negative integer or 'all'")
            return

        if path == "report.formats":
            if not _is_string_list(value) or any(item not in VALID_REPORT_FORMATS for item in value):
                add(path, "a list containing markdown and/or json")
            return

    for key, value in payload.items():
        visit(key, value)

    if errors:
        details = "; ".join(errors[:10])
        remaining = len(errors) - 10
        if remaining > 0:
            details = f"{details}; ... (+{remaining} more)"
        raise ConfigError(f"config has invalid value(s) in {source}: {details}")


def sanitize_repo_local_config(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    sanitized: dict[str, Any] = {}
    ignored: list[str] = []

    def visit(path: str, value: Any) -> None:
        expected_type = REPO_LOCAL_ALLOWED_TYPES.get(path)
        if expected_type:
            if type(value) is expected_type:
                _set_nested_value(sanitized, path, value)
            else:
                ignored.append(path)
            return

        if isinstance(value, dict):
            if not value:
                return
            if _has_repo_local_allowed_descendant(path):
                for key, child in value.items():
                    visit(f"{path}.{key}", child)
            else:
                ignored.extend(_repo_config_leaf_paths(path, value))
            return

        ignored.append(path)

    for key, value in payload.items():
        visit(key, value)
    return sanitized, ignored


def _read_config_file(path: Path) -> dict[str, Any]:
    try:
        file_stat = path.lstat()
    except OSError as error:
        raise ConfigError(f"config could not be stat'd: {path}") from error
    size = file_stat.st_size
    if not stat.S_ISREG(file_stat.st_mode):
        raise ConfigError(f"config could not be read: {path}")
    if size > MAX_CONFIG_BYTES:
        raise ConfigError(f"config file exceeds {MAX_CONFIG_BYTES} bytes: {path}")
    if stat.S_IMODE(file_stat.st_mode) & 0o444 == 0:
        raise ConfigError(f"config could not be read: {path}")
    with _open_config_file(path, file_stat) as handle:
        try:
            payload = json.load(handle)
        except json.JSONDecodeError as error:
            raise ConfigError(f"config is not valid JSON: {path}: {error.msg}") from error
        except RecursionError as error:
            raise ConfigError(f"config nesting is too deep: {path}") from error
    if not isinstance(payload, dict):
        raise ConfigError(f"config must be a JSON object: {path}")
    return payload


def _open_config_file(path: Path, expected_stat: os.stat_result) -> Any:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConfigError(f"config could not be read: {path}") from error
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ConfigError(f"config could not be read: {path}")
        if (opened_stat.st_dev, opened_stat.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
            raise ConfigError(f"config could not be read: {path}")
        return os.fdopen(descriptor, "r", encoding="utf-8")
    except Exception:
        os.close(descriptor)
        raise


def load_default_config() -> dict[str, Any]:
    return _read_config_file(default_config_path())


def load_config(repo: Path, explicit_path: Path | None = None) -> dict[str, Any]:
    config = load_default_config()
    if explicit_path:
        if not explicit_path.exists():
            raise SystemExit(f"config file does not exist: {explicit_path}")
        override = _read_config_file(explicit_path)
        validate_explicit_config(override, explicit_path)
        try:
            config = deep_merge(config, override)
        except RecursionError as error:
            raise ConfigError(f"config nesting is too deep: {explicit_path}") from error
        return config

    repo_config = repo / ".codebase-auditor.json"
    if repo_config.exists():
        override = _read_config_file(repo_config)
        sanitized, removed = strip_operator_only_keys(override)
        if removed:
            joined = format_config_paths(removed)
            print(
                f"warning: ignoring operator-only keys from {repo_config}: {joined}. "
                f"Move them into an explicit --config file.",
                file=sys.stderr,
            )
        sanitized, ignored = sanitize_repo_local_config(sanitized)
        if ignored:
            joined = format_config_paths(ignored)
            print(
                f"warning: ignoring unsupported repo-local config keys from {repo_config}: {joined}. "
                f"Repo-local config only supports report presentation settings.",
                file=sys.stderr,
            )
        try:
            config = deep_merge(config, sanitized)
        except RecursionError as error:
            raise ConfigError(f"config nesting is too deep: {repo_config}") from error
    return config
