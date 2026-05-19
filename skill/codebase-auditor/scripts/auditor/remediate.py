from __future__ import annotations

import ast
import difflib
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
from pathlib import Path
from typing import Any

from .config import load_config
from .discover_repo import prime_repo_cache
from .scan_complexity import scan_complexity


MEMBERSHIP_VARNAME_RE = re.compile(r"^_auditor_membership_set_\d+$")
MAX_LITERAL_SOURCE_LEN = 10_000


def validate_membership_fix(fix: dict[str, Any]) -> str | None:
    required = ("loopLine", "literalLine", "literalColumnStart", "literalColumnEnd", "literalSource", "variableName", "setSource")
    for key in required:
        if key not in fix:
            return f"fix metadata is missing {key}"

    variable_name = fix["variableName"]
    if not isinstance(variable_name, str) or not MEMBERSHIP_VARNAME_RE.fullmatch(variable_name):
        return "fix.variableName must match _auditor_membership_set_<digits>"

    set_source = fix["setSource"]
    if not isinstance(set_source, str) or len(set_source) > MAX_LITERAL_SOURCE_LEN:
        return "fix.setSource must be a string under 10000 chars"
    try:
        tree = ast.parse(set_source, mode="eval")
    except (SyntaxError, ValueError):
        return "fix.setSource is not a valid Python expression"
    if not isinstance(tree.body, ast.Set):
        return "fix.setSource must be a set literal"
    for element in tree.body.elts:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            return "fix.setSource must contain only string constants"

    for key in ("loopLine", "literalLine", "literalColumnStart", "literalColumnEnd"):
        value = fix[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return f"fix.{key} must be a non-negative integer"

    literal_source = fix["literalSource"]
    if not isinstance(literal_source, str) or not literal_source or len(literal_source) > MAX_LITERAL_SOURCE_LEN:
        return "fix.literalSource must be a non-empty string under 10000 chars"

    return None


def validate_finding_for_remediation(finding: dict[str, Any]) -> str | None:
    if not isinstance(finding, dict):
        return "finding must be a JSON object"
    location = finding.get("location")
    if not isinstance(location, dict) or not isinstance(location.get("path"), str):
        return "finding.location.path must be a string"
    return None


def unsupported_result(finding_id: str, reason: str, finding: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "status": "unsupported",
        "findingId": finding_id,
        "reason": reason,
        "changedFiles": [],
        "diff": "",
        "verification": [],
        "finding": finding,
    }


def find_report_finding(report_path: Path, finding_id: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for finding in payload.get("findings", []):
        if isinstance(finding, dict) and finding.get("id") == finding_id:
            return finding
    return None


def find_scanned_finding(repo: Path, config: dict[str, Any], finding_id: str) -> dict[str, Any] | None:
    prime_repo_cache(repo, config)
    for finding in scan_complexity(repo, config):
        if finding["id"] == finding_id:
            return finding
    return None


def resolve_finding_path(repo: Path, raw_path: str) -> tuple[Path, str]:
    rel_candidate = Path(raw_path)
    if rel_candidate.is_absolute():
        raise ValueError("finding path must be relative to the repository")
    raw_target = repo / rel_candidate
    try:
        metadata = raw_target.lstat()
    except OSError:
        metadata = None
    if metadata is not None and stat.S_ISLNK(metadata.st_mode):
        raise ValueError("finding path must not be a symlink")
    path = raw_target.resolve()
    try:
        repo_relative = path.relative_to(repo)
    except ValueError as error:
        raise ValueError("finding path escapes the repository") from error
    return path, repo_relative.as_posix()


def line_indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def replace_text_without_following_links(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temp_path: Path | None = None
    for _attempt in range(100):
        candidate = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        try:
            descriptor = os.open(candidate, flags, 0o666)
            temp_path = candidate
            break
        except FileExistsError:
            continue
    else:
        raise OSError("could not allocate a temporary patch file")

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp_path, path)
    except OSError:
        if temp_path:
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def rewrite_membership_literal(repo: Path, finding: dict[str, Any], dry_run: bool) -> dict[str, Any]:
    fix = finding.get("fix")
    if not isinstance(fix, dict) or fix.get("kind") != "python-membership-literal-set-hoist":
        return unsupported_result(finding["id"], "finding does not have a supported mechanical fix", finding)

    schema_error = validate_membership_fix(fix)
    if schema_error:
        return unsupported_result(finding["id"], schema_error, finding)

    try:
        path, rel_path = resolve_finding_path(repo, str(finding["location"]["path"]))
    except ValueError as error:
        return unsupported_result(finding["id"], str(error), finding)
    if not path.exists() or path.suffix != ".py":
        return unsupported_result(finding["id"], "target Python file is missing", finding)
    try:
        metadata = path.lstat()
    except OSError:
        return unsupported_result(finding["id"], "could not stat target file", finding)
    if not stat.S_ISREG(metadata.st_mode):
        return unsupported_result(finding["id"], "target path is not a regular file", finding)

    original = path.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    literal_line = int(fix["literalLine"])
    loop_line = int(fix["loopLine"])
    start = int(fix["literalColumnStart"])
    end = int(fix["literalColumnEnd"])
    literal_source = str(fix["literalSource"])
    variable_name = str(fix["variableName"])
    set_source = str(fix["setSource"])

    if variable_name in original:
        return unsupported_result(finding["id"], f"generated variable name already exists: {variable_name}", finding)
    if literal_line < 1 or literal_line > len(lines) or loop_line < 1 or loop_line > len(lines):
        return unsupported_result(finding["id"], "finding location no longer matches file", finding)

    target_line = lines[literal_line - 1]
    if target_line[start:end] != literal_source:
        return unsupported_result(finding["id"], "literal source no longer matches file", finding)

    rewritten = list(lines)
    rewritten[literal_line - 1] = target_line[:start] + variable_name + target_line[end:]
    assignment = f"{line_indent(lines[loop_line - 1])}{variable_name} = {set_source}\n"
    rewritten.insert(loop_line - 1, assignment)
    updated = "".join(rewritten)

    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=rel_path,
            tofile=rel_path,
        )
    )
    if not dry_run:
        try:
            replace_text_without_following_links(path, updated)
        except OSError as error:
            reason = error.strerror or str(error)
            return unsupported_result(finding["id"], f"could not write target file safely: {reason}", finding)

    return {
        "status": "dry_run" if dry_run else "patched",
        "findingId": finding["id"],
        "reason": None,
        "changedFiles": [] if dry_run else [rel_path],
        "diff": diff,
        "verification": [],
        "finding": finding,
    }


def run_command(command: str, cwd: Path, timeout_seconds: int = 60) -> dict[str, Any]:
    try:
        result = subprocess.run(shlex.split(command), cwd=cwd, text=True, capture_output=True, timeout=timeout_seconds, check=False)
        status = "passed" if result.returncode == 0 else "failed"
        return {
            "command": command,
            "status": status,
            "returnCode": result.returncode,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
        }
    except subprocess.TimeoutExpired as error:
        return {
            "command": command,
            "status": "timeout",
            "returnCode": None,
            "stdout": (error.stdout or "")[-2000:] if isinstance(error.stdout, str) else "",
            "stderr": (error.stderr or "")[-2000:] if isinstance(error.stderr, str) else "",
        }
    except (OSError, ValueError) as error:
        return {
            "command": command,
            "status": "failed",
            "returnCode": None,
            "stdout": "",
            "stderr": str(error)[-2000:],
        }


def verification_commands(repo: Path, result: dict[str, Any], extra_commands: list[str]) -> list[str]:
    commands = []
    for rel_path in result.get("changedFiles", []):
        if rel_path.endswith(".py"):
            commands.append(
                "python -c \"import pathlib, sys; "
                "compile(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), sys.argv[1], 'exec')\" "
                f"{json.dumps(rel_path)}"
            )
    commands.extend(extra_commands)
    unique = []
    for command in commands:
        if command not in unique:
            unique.append(command)
    return unique


def remediate_finding(
    repo: Path,
    finding_id: str,
    *,
    config_path: Path | None = None,
    report_path: Path | None = None,
    dry_run: bool = False,
    test_commands: list[str] | None = None,
) -> dict[str, Any]:
    repo = repo.resolve()
    config = load_config(repo, config_path)
    finding = find_report_finding(report_path, finding_id) if report_path else None
    if not finding:
        finding = find_scanned_finding(repo, config, finding_id)
    if not finding:
        return unsupported_result(finding_id, "finding ID was not found in the report or current complexity scan")

    shape_error = validate_finding_for_remediation(finding)
    if shape_error:
        return unsupported_result(finding_id, shape_error, finding if isinstance(finding, dict) else None)

    if isinstance(finding.get("fix"), dict) and finding["fix"].get("kind") == "python-membership-literal-set-hoist":
        result = rewrite_membership_literal(repo, finding, dry_run)
    else:
        result = unsupported_result(finding_id, "finding has no supported mechanical fix", finding)

    if result["status"] == "patched":
        result["verification"] = [run_command(command, repo) for command in verification_commands(repo, result, test_commands or [])]
        if result["verification"] and any(item["status"] != "passed" for item in result["verification"]):
            result["status"] = "patched_verification_failed"
    elif dry_run:
        result["verification"] = []
    return result
