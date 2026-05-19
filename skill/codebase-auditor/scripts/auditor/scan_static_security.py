from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .discover_repo import SOURCE_EXTENSIONS, iter_repo_files, read_text
from .discover_repo import rel as relpath
from .external_tools import resolve_external_tool
from .source_sanitize import sanitize_code_lines


SECURITY_PATTERNS = [
    ("js-eval", re.compile(r"\b(eval|Function)\s*\("), "high", "medium", "RCE", "Avoid dynamic code execution; use structured parsing or explicit dispatch."),
    ("js-shell-exec", re.compile(r"\b(exec|execSync)\s*\("), "medium", "low", "RCE", "Verify user input cannot reach shell execution; prefer argument arrays and safe process APIs."),
    ("python-shell-true", re.compile(r"shell\s*=\s*True"), "high", "medium", "RCE", "Avoid shell=True with user-controlled input; pass arguments as a list."),
    ("pickle-load", re.compile(r"\bpickle\.loads?\s*\("), "high", "medium", "unsafe deserialization", "Avoid pickle for untrusted data; use safe formats such as JSON."),
    ("yaml-load", re.compile(r"\byaml\.load\s*\("), "medium", "medium", "unsafe deserialization", "Use yaml.safe_load unless a trusted Loader is required."),
    ("weak-crypto", re.compile(r"\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\s*\("), "medium", "low", "weak crypto", "Use SHA-256 or a password hashing function when security-sensitive."),
    ("xss-sink", re.compile(r"\b(innerHTML|outerHTML|dangerouslySetInnerHTML|v-html)\b"), "medium", "medium", "XSS", "Sanitize untrusted HTML or render text instead of HTML."),
    ("cors-wildcard", re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|origin\s*:\s*['\"]\*"), "medium", "medium", "CORS misconfiguration", "Restrict CORS origins to trusted callers."),
    ("sql-concat", re.compile(r"\b(query|execute)\s*\([^)]*(\+|\$\{)"), "high", "medium", "injection", "Use parameterized queries or a query builder."),
    ("ssrf", re.compile(r"\b(fetch|axios\.get|requests\.get|http\.get)\s*\([^)]*(req\.|request\.|params|query)"), "high", "low", "SSRF", "Validate and allowlist outbound request targets."),
    ("path-traversal", re.compile(r"\b(readFile|sendFile|open)\s*\([^)]*(req\.|request\.|params|query)"), "high", "low", "path traversal", "Normalize paths and constrain access to an allowlisted base directory."),
]


def should_skip_static_line(line: str, path: str = "") -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "//", "/*", "*")):
        return True
    return path.endswith("scan_static_security.py") and "re.compile(" in stripped


def finding_id(path: str, line: int | None, tag: str) -> str:
    digest = hashlib.sha256(f"{path}:{line}:{tag}".encode("utf-8")).hexdigest()[:10]
    return f"security-{digest}"


def static_finding(
    *,
    path: str,
    line: int | None,
    tag: str,
    severity: str,
    confidence: str,
    risk: str,
    evidence: str,
    recommendation: str,
    source: str = "scan_static_security",
) -> dict[str, Any]:
    return {
        "id": finding_id(path, line, tag),
        "category": "security",
        "severity": severity,
        "confidence": confidence,
        "title": f"Potential {risk} issue",
        "location": {"path": path, "line": line, "symbol": tag},
        "evidence": evidence.strip()[:220],
        "impact": {"performance": None, "security": f"Potential {risk} if user-controlled input reaches this sink.", "architecture": None},
        "recommendation": recommendation,
        "estimatedEffort": "small",
        "estimatedRoi": "high" if severity in {"critical", "high"} else "medium",
        "verification": ["source review", "security test"],
        "source": source,
    }


def built_in_static_findings(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in iter_repo_files(repo, config, max_bytes=1_000_000):
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        findings.extend(built_in_static_file_findings(repo, path))
    return findings


def built_in_static_file_findings(repo: Path, path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rel_path = relpath(path, repo)
    raw_lines = read_text(path).splitlines()
    code_lines = sanitize_code_lines("\n".join(raw_lines))
    for index, line in enumerate(code_lines, start=1):
        finding = static_finding_for_line(rel_path, raw_lines, index, line)
        if finding:
            findings.append(finding)
    return findings


def static_finding_for_line(rel_path: str, raw_lines: list[str], index: int, line: str) -> dict[str, Any] | None:
    if should_skip_static_line(line, rel_path):
        return None
    evidence = raw_lines[index - 1] if index - 1 < len(raw_lines) else line
    for tag, pattern, severity, confidence, risk, recommendation in SECURITY_PATTERNS:
        if pattern.search(line):
            return static_finding(
                path=rel_path,
                line=index,
                tag=tag,
                severity=severity,
                confidence=confidence,
                risk=risk,
                evidence=evidence,
                recommendation=recommendation,
            )
    return None


def semgrep_config_needs_network(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered == "auto":
        return True
    if lowered.startswith(("http://", "https://")):
        return True
    if lowered.startswith(("p/", "r/", "s/")):
        return True
    return False


def semgrep_findings(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    security = config.get("security", {})
    semgrep = resolve_external_tool(config, "semgrep")
    if not security.get("runSemgrep") or not semgrep:
        return []
    semgrep_config = security.get("semgrepConfig")
    if not semgrep_config:
        if not config.get("allowNetwork"):
            return []
        semgrep_config = "auto"
    elif semgrep_config_needs_network(str(semgrep_config)) and not config.get("allowNetwork"):
        return []
    try:
        result = subprocess.run(
            [semgrep, "--config", str(semgrep_config), "--json", "--quiet", str(repo)],
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    findings = []
    for item in payload.get("results", []):
        check_id = item.get("check_id", "semgrep")
        extra = item.get("extra", {})
        severity = str(extra.get("severity", "WARNING")).lower()
        mapped = "high" if severity == "error" else "medium" if severity == "warning" else "low"
        path = item.get("path", "unknown")
        start = item.get("start", {})
        findings.append(
            static_finding(
                path=path,
                line=start.get("line"),
                tag=check_id,
                severity=mapped,
                confidence="high",
                risk=extra.get("message", "security"),
                evidence=f"semgrep: {check_id}",
                recommendation="Review the semgrep rule guidance and patch the affected data flow.",
                source="scan_static_security:semgrep",
            )
        )
    return findings


def scan_static_security(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    if not config.get("security", {}).get("staticSecurity", True):
        return []
    return built_in_static_findings(repo, config) + semgrep_findings(repo, config)
