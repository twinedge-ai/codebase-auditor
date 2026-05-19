from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .discover_repo import iter_repo_files, read_text, rel
from .external_tools import resolve_external_tool


SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"), "critical", "high"),
    ("aws-access-key", re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"), "high", "high"),
    (
        "aws-secret-key",
        re.compile(r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        "high",
        "high",
    ),
    ("jwt-token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high", "medium"),
    (
        "database-url-with-password",
        re.compile(r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"),
        "high",
        "high",
    ),
    (
        "generic-api-secret",
        re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_.\-/+=]{24,})"),
        "medium",
        "medium",
    ),
]

SKIP_SECRET_FILES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
    "Pipfile.lock",
}


def finding_id(path: str, line: int | None, kind: str) -> str:
    digest = hashlib.sha256(f"{path}:{line}:{kind}".encode("utf-8")).hexdigest()[:10]
    return f"secret-{digest}"


def is_placeholder(match: re.Match[str]) -> bool:
    values = [group for group in match.groups() if group] or [match.group(0)]
    lowered = " ".join(values).lower()
    return any(token in lowered for token in ["example", "placeholder", "your_", "changeme"])


def redact_secret_text(text: str) -> str:
    redacted = text
    for kind, pattern, _severity, _confidence in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match, secret_kind=kind: redact_secret_match(secret_kind, match), redacted)
    return redacted


def redact_secret_match(kind: str, match: re.Match[str]) -> str:
    value = match.group(0)
    groups = [group for group in match.groups() if group]
    if not groups:
        return f"[redacted {kind}]"
    for group in groups:
        value = value.replace(group, "[redacted]")
    return value


def secret_finding(
    path: str,
    line: int | None,
    kind: str,
    severity: str,
    confidence: str,
    source: str = "scan_secrets",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id(path, line, kind),
        "category": "secret",
        "severity": severity,
        "confidence": confidence,
        "title": f"Potential {kind.replace('-', ' ')} committed to repository",
        "location": {"path": path, "line": line, "symbol": kind},
        "evidence": f"{kind}: [redacted]",
        "impact": {"performance": None, "security": "Credential exposure can allow unauthorized access.", "architecture": None},
        "recommendation": "Revoke or rotate the secret, remove it from history if needed, and load it from a secure secret manager.",
        "estimatedEffort": "medium",
        "estimatedRoi": "high",
        "verification": ["secret scan", "credential rotation confirmation"],
        "source": source,
        "metadata": metadata or {},
    }


def line_number(value: object) -> int | None:
    try:
        line = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def is_external_secret(finding: dict[str, Any]) -> bool:
    if finding.get("category") != "secret":
        return False
    metadata = finding.get("metadata")
    if isinstance(metadata, dict) and "externalSecret" in metadata:
        return bool(metadata.get("externalSecret"))
    return finding.get("source") != "scan_secrets"


def external_secret_redactions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    redactions: list[dict[str, Any]] = []
    for finding in findings:
        if not is_external_secret(finding):
            continue
        location = finding.get("location", {})
        if not isinstance(location, dict) or not isinstance(location.get("path"), str):
            continue
        metadata = finding.get("metadata", {})
        start = line_number(location.get("line"))
        end = start
        if isinstance(metadata, dict):
            start = line_number(metadata.get("startLine")) or start
            end = line_number(metadata.get("endLine")) or end
        if start is None:
            continue
        if end is None or end < start:
            end = start
        redactions.append(
            {
                "path": location["path"],
                "startLine": start,
                "endLine": end,
                "source": finding.get("source", "external-secret"),
            }
        )
    return redactions


def built_in_secret_findings(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in iter_repo_files(repo, config, max_bytes=1_000_000):
        if path.name in SKIP_SECRET_FILES:
            continue
        findings.extend(built_in_secret_file_findings(repo, path))
    return findings


def built_in_secret_file_findings(repo: Path, path: Path) -> list[dict[str, Any]]:
    findings = []
    rel_path = rel(path, repo)
    for index, line in enumerate(read_text(path).splitlines(), start=1):
        finding = secret_finding_for_line(rel_path, index, line)
        if finding:
            findings.append(finding)
    return findings


def secret_finding_for_line(rel_path: str, index: int, line: str) -> dict[str, Any] | None:
    for kind, pattern, severity, confidence in SECRET_PATTERNS:
        match = pattern.search(line)
        if match and not is_placeholder(match):
            return secret_finding(rel_path, index, kind, severity, confidence)
    return None


def gitleaks_findings(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    gitleaks = resolve_external_tool(config, "gitleaks")
    if not config.get("security", {}).get("runGitleaks") or not gitleaks:
        return []
    with tempfile.TemporaryDirectory(prefix="auditor-gitleaks-") as temp_dir:
        report_path = Path(temp_dir) / "gitleaks.json"
        try:
            subprocess.run(
                [
                    gitleaks,
                    "detect",
                    "--no-git",
                    "--redact",
                    "--source",
                    str(repo),
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_path),
                ],
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if not report_path.exists():
            return []
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    findings = []
    for item in payload if isinstance(payload, list) else []:
        file_path = item.get("File") or item.get("file") or "unknown"
        line = item.get("StartLine") or item.get("line")
        end_line = item.get("EndLine") or item.get("endLine") or line
        rule = item.get("RuleID") or item.get("Description") or "gitleaks-secret"
        findings.append(
            secret_finding(
                str(file_path),
                line,
                str(rule),
                "high",
                "high",
                "scan_secrets:gitleaks",
                {"externalSecret": True, "startLine": line, "endLine": end_line},
            )
        )
    return findings


def scan_secrets(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    if not config.get("security", {}).get("scanSecrets", True):
        return []
    return built_in_secret_findings(repo, config) + gitleaks_findings(repo, config)


def redact_findings_evidence(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for finding in findings:
        evidence = finding.get("evidence")
        if isinstance(evidence, str) and evidence:
            finding["evidence"] = redact_secret_text(evidence)
    return findings
