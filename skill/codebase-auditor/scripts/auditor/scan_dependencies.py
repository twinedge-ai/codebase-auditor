from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from .dependency_parsers import Dependency, collect_dependencies
from .discover_repo import iter_repo_files, rel
from .external_tools import resolve_external_tool
from .network_policy import UrlPolicyError, http_post_json


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
USER_AGENT = "codex-codebase-auditor/1.0"
UNSTABLE_VERSION_RE = re.compile(r"(?:^|[._-])(alpha\d*|beta\d*|rc\d*|m\d*|snapshot|preview\d*|dev\d*|nightly|canary|next|pre\d*)(?:$|[._-])", re.IGNORECASE)


def dependency_to_dict(dep: Dependency, status: str) -> dict[str, Any]:
    return {
        "name": dep.name,
        "version": dep.version,
        "ecosystem": dep.ecosystem,
        "manager": dep.manager,
        "path": dep.path,
        "line": dep.line,
        "scope": dep.scope,
        "vulnerabilityStatus": status,
    }


def finding_id(*parts: object) -> str:
    digest = hashlib.sha256(":".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:10]
    return f"dependency-{digest}"


def is_exact_stable_version(version: str) -> bool:
    value = version.strip()
    if not value or not value[0].isdigit():
        return False
    if any(char in value for char in " <>=^~*[](),|+"):
        return False
    if re.search(r"(?i)(?:^|:)(?:git|http|https|file|link|workspace|npm):", value):
        return False
    if UNSTABLE_VERSION_RE.search(value):
        return False
    return bool(re.fullmatch(r"\d[A-Za-z0-9._-]*", value))


def unresolved_osv_status(osv_status: str) -> str:
    if osv_status == "no_exact_versions":
        return "not_checked_version_not_exact"
    if osv_status == "checked":
        return "not_checked"
    return f"not_checked_{osv_status}"


def osv_queries(deps: list[Dependency]) -> tuple[list[dict[str, Any]], list[Dependency]]:
    queries: list[dict[str, Any]] = []
    queried: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()
    for dep in deps:
        if not dep.version or not is_exact_stable_version(dep.version):
            continue
        key = (dep.ecosystem, dep.name.lower(), dep.version)
        if key in seen:
            continue
        seen.add(key)
        queried.append(dep)
        queries.append({"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version})
    return queries, queried


def query_osv(deps: list[Dependency], config: dict[str, Any], timeout_seconds: int = 20) -> tuple[dict[tuple[str, str, str], list[dict[str, Any]]], str]:
    queries, queried = osv_queries(deps)
    if not queries:
        return {}, "no_exact_versions"

    allow_mocks = bool(config.get("allowMocks"))
    mock_path = os.environ.get("CODEX_AUDITOR_OSV_RESPONSE_FILE") if allow_mocks else None
    if mock_path:
        try:
            response = json.loads(Path(mock_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}, "osv_mock_unavailable"
    else:
        try:
            response = http_post_json(
                OSV_BATCH_URL,
                {"queries": queries},
                allow_private_network=False,
                timeout=float(timeout_seconds),
                user_agent=USER_AGENT,
            )
        except (UrlPolicyError, OSError, TimeoutError, ValueError, json.JSONDecodeError):
            return {}, "osv_unavailable"

    results = response.get("results", [])
    vulns_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for dep, result in zip(queried, results):
        vulns = result.get("vulns", []) if isinstance(result, dict) else []
        if vulns:
            vulns_by_key[(dep.ecosystem, dep.name.lower(), dep.version or "")] = vulns
    return vulns_by_key, "checked"


def severity_from_score(score: str) -> str | None:
    word = score.strip().lower()
    if word in {"critical", "high", "medium", "moderate", "low"}:
        return "medium" if word == "moderate" else word
    if re.fullmatch(r"\d+(?:\.\d+)?", word):
        value = float(word)
        if value >= 9:
            return "critical"
        if value >= 7:
            return "high"
        if value >= 4:
            return "medium"
        if value > 0:
            return "low"
    return None


def severity_from_vuln(vuln: dict[str, Any]) -> str:
    severities: list[str] = []
    db_specific = vuln.get("database_specific", {})
    if isinstance(db_specific, dict) and isinstance(db_specific.get("severity"), str):
        parsed = severity_from_score(db_specific["severity"])
        if parsed:
            severities.append(parsed)
    for entry in vuln.get("severity", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("score"), str):
            parsed = severity_from_score(entry["score"])
            if parsed:
                severities.append(parsed)
    for severity in ["critical", "high", "medium", "low"]:
        if severity in severities:
            return severity
    return "medium" if vuln.get("aliases") else "low"


def vuln_finding(dep: Dependency, vuln: dict[str, Any]) -> dict[str, Any]:
    vuln_id = vuln.get("id", "unknown-vulnerability")
    aliases = [alias for alias in vuln.get("aliases", []) if isinstance(alias, str)]
    evidence_ids = ", ".join([vuln_id, *aliases[:3]])
    return {
        "id": finding_id(dep.ecosystem, dep.name, dep.version, vuln_id),
        "category": "dependency",
        "severity": severity_from_vuln(vuln),
        "confidence": "high",
        "title": f"Vulnerable dependency {dep.name}@{dep.version}",
        "location": {"path": dep.path, "line": dep.line, "symbol": dep.name},
        "evidence": f"OSV matched {evidence_ids}",
        "impact": {"performance": None, "security": vuln.get("summary") or "Known dependency vulnerability", "architecture": None},
        "recommendation": "Upgrade to a patched version or replace the dependency after checking compatibility.",
        "estimatedEffort": "small",
        "estimatedRoi": "high",
        "verification": ["dependency audit", "test suite"],
        "source": "scan_dependencies:osv",
    }


def run_command_json(command: list[str], cwd: Path, timeout_seconds: int = 45) -> dict[str, Any] | None:
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout_seconds, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = result.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def external_audit_findings(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    security = config.get("security", {})
    findings: list[dict[str, Any]] = []
    if not config.get("allowNetwork"):
        return findings

    npm = resolve_external_tool(config, "npm")
    if security.get("runNpmAudit") and npm and (repo / "package-lock.json").exists():
        payload = run_command_json([npm, "audit", "--json"], repo)
        vulnerabilities = payload.get("vulnerabilities", {}) if isinstance(payload, dict) else {}
        for name, vuln in vulnerabilities.items():
            if not isinstance(vuln, dict):
                continue
            severity = str(vuln.get("severity", "medium")).lower()
            findings.append(
                {
                    "id": finding_id("npm-audit", name, severity),
                    "category": "dependency",
                    "severity": severity if severity in {"critical", "high", "medium", "low"} else "medium",
                    "confidence": "high",
                    "title": f"npm audit reported vulnerable package {name}",
                    "location": {"path": "package-lock.json", "line": None, "symbol": name},
                    "evidence": f"npm audit: {name}",
                    "impact": {"performance": None, "security": "npm audit reported a dependency vulnerability", "architecture": None},
                    "recommendation": "Run npm audit fix only after reviewing compatibility, or upgrade the affected package manually.",
                    "estimatedEffort": "small",
                    "estimatedRoi": "high",
                    "verification": ["npm audit", "test suite"],
                    "source": "scan_dependencies:npm-audit",
                }
            )

    pip_audit = resolve_external_tool(config, "pip-audit")
    if security.get("runPipAudit") and pip_audit:
        for requirements in iter_repo_files(repo, config, max_bytes=5_000_000):
            if requirements.name != "requirements.txt":
                continue
            payload = run_command_json([pip_audit, "-r", str(requirements), "-f", "json"], repo)
            findings.extend(pip_audit_payload_findings(payload or {}, requirements, repo))

    cargo = resolve_external_tool(config, "cargo")
    if security.get("runCargoAudit") and cargo and (repo / "Cargo.lock").exists():
        payload = run_command_json([cargo, "audit", "--json"], repo)
        for vuln in (payload or {}).get("vulnerabilities", {}).get("list", []):
            package = vuln.get("package", {})
            advisory = vuln.get("advisory", {})
            findings.append(
                {
                    "id": finding_id("cargo-audit", package.get("name"), advisory.get("id")),
                    "category": "dependency",
                    "severity": "high",
                    "confidence": "high",
                    "title": f"cargo audit reported vulnerable crate {package.get('name')}",
                    "location": {"path": "Cargo.lock", "line": None, "symbol": package.get("name")},
                    "evidence": f"cargo audit: {advisory.get('id', 'unknown')}",
                    "impact": {"performance": None, "security": advisory.get("title") or "Rust dependency vulnerability", "architecture": None},
                    "recommendation": "Upgrade the crate to a patched version after checking compatibility.",
                    "estimatedEffort": "small",
                    "estimatedRoi": "high",
                    "verification": ["cargo audit", "cargo test"],
                    "source": "scan_dependencies:cargo-audit",
                }
            )

    trivy = resolve_external_tool(config, "trivy")
    if security.get("runTrivy") and trivy:
        payload = run_command_json([trivy, "fs", "--format", "json", str(repo)], repo, timeout_seconds=90)
        for result in (payload or {}).get("Results", []):
            findings.extend(trivy_result_findings(result))
    return findings


def pip_audit_payload_findings(payload: dict[str, Any], requirements: Path, repo: Path) -> list[dict[str, Any]]:
    findings = []
    for dep in payload.get("dependencies", []):
        findings.extend(pip_audit_dependency_findings(dep, requirements, repo))
    return findings


def pip_audit_dependency_findings(dep: dict[str, Any], requirements: Path, repo: Path) -> list[dict[str, Any]]:
    return [
        {
            "id": finding_id("pip-audit", dep.get("name"), vuln.get("id")),
            "category": "dependency",
            "severity": "high" if str(vuln.get("id", "")).startswith("CVE-") else "medium",
            "confidence": "high",
            "title": f"pip-audit reported vulnerable package {dep.get('name')}",
            "location": {"path": rel(requirements, repo), "line": None, "symbol": dep.get("name")},
            "evidence": f"pip-audit: {vuln.get('id', 'unknown')}",
            "impact": {"performance": None, "security": vuln.get("description") or "Python dependency vulnerability", "architecture": None},
            "recommendation": "Upgrade to a fixed version after checking compatibility.",
            "estimatedEffort": "small",
            "estimatedRoi": "high",
            "verification": ["pip-audit", "test suite"],
            "source": "scan_dependencies:pip-audit",
        }
        for vuln in dep.get("vulns", [])
    ]


def trivy_result_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    target = result.get("Target", "repository")
    findings = []
    for vuln in result.get("Vulnerabilities", []) or []:
        pkg = vuln.get("PkgName", "unknown")
        findings.append(
            {
                "id": finding_id("trivy", target, pkg, vuln.get("VulnerabilityID")),
                "category": "dependency",
                "severity": str(vuln.get("Severity", "MEDIUM")).lower(),
                "confidence": "high",
                "title": f"trivy reported vulnerable package {pkg}",
                "location": {"path": target, "line": None, "symbol": pkg},
                "evidence": f"trivy: {vuln.get('VulnerabilityID', 'unknown')}",
                "impact": {"performance": None, "security": vuln.get("Title") or "Dependency vulnerability", "architecture": None},
                "recommendation": "Upgrade to a fixed version or apply the vendor remediation.",
                "estimatedEffort": "medium",
                "estimatedRoi": "high",
                "verification": ["trivy fs", "test suite"],
                "source": "scan_dependencies:trivy",
            }
        )
    return findings


def scan_dependencies(repo: Path, config: dict[str, Any]) -> dict[str, Any]:
    deps = collect_dependencies(repo, config)
    status_by_key: dict[tuple[str, str, str], str] = {}
    findings: list[dict[str, Any]] = []
    osv_status = "not_checked_offline"

    if config.get("allowNetwork") and config.get("security", {}).get("dependencyAudit", True):
        vulns_by_key, osv_status = query_osv(deps, config)
        reported_vulns: set[str] = set()
        for dep in sorted(deps, key=lambda item: item.scope != "lockfile"):
            if osv_status != "checked" or not dep.version or not is_exact_stable_version(dep.version):
                continue
            key = (dep.ecosystem, dep.name.lower(), dep.version)
            vulns = vulns_by_key.get(key, [])
            status_by_key[key] = "vulnerable" if vulns else "checked"
            findings.extend(osv_findings_for_dependency(dep, vulns, reported_vulns))
        findings.extend(external_audit_findings(repo, config))

    inventory = []
    for dep in deps:
        if not dep.version:
            status = "version_unknown"
        elif not config.get("allowNetwork"):
            status = "not_checked_offline"
        elif not config.get("security", {}).get("dependencyAudit", True):
            status = "audit_disabled"
        elif not is_exact_stable_version(dep.version):
            status = "not_checked_version_not_exact"
        else:
            status = status_by_key.get((dep.ecosystem, dep.name.lower(), dep.version), unresolved_osv_status(osv_status))
        inventory.append(dependency_to_dict(dep, status))

    return {
        "inventory": inventory,
        "findings": findings,
        "summary": {
            "totalDependencies": len(inventory),
            "osvStatus": osv_status,
            "managers": sorted({dep["manager"] for dep in inventory}),
        },
    }


def osv_findings_for_dependency(dep: Dependency, vulns: list[dict[str, Any]], reported_vulns: set[str]) -> list[dict[str, Any]]:
    findings = []
    for vuln in vulns:
        finding = vuln_finding(dep, vuln)
        if finding["id"] in reported_vulns:
            continue
        reported_vulns.add(finding["id"])
        findings.append(finding)
    return findings
