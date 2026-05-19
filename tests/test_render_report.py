from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDITOR_SCRIPTS = ROOT / "skill" / "codebase-auditor" / "scripts"
if str(AUDITOR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(AUDITOR_SCRIPTS))

from auditor import cli as auditor_cli  # noqa: E402
from auditor import scan_secrets as scan_secrets_module  # noqa: E402
from auditor.render_report import render_html  # noqa: E402


def minimal_result(repo: Path) -> dict:
    return {
        "generatedAt": "2026-05-18T00:00:00Z",
        "profile": "test",
        "allowNetwork": False,
        "repository": str(repo),
        "summary": {"totalFindings": 0, "bySeverity": {}},
        "findings": [],
        "dependencies": [],
        "dependencySummary": {"totalDependencies": 0, "osvStatus": "not_run"},
        "architecture": {"summary": {}, "services": []},
        "performance": {},
        "sourceRedactions": {"externalSecrets": []},
        "discovery": {
            "root": str(repo),
            "totals": {"files": 0, "sourceFiles": 0, "sourceLines": 0},
            "languages": [],
            "packageManagers": [],
            "frameworks": [],
            "infrastructure": [],
            "commands": {},
            "manifests": [],
        },
    }


class RenderReportTest(unittest.TestCase):
    def test_html_report_links_absolute_in_repo_finding_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-render-absolute-") as temp_dir:
            repo = Path(temp_dir)
            source = repo / "app.js"
            source.write_text("const value = 1;\n", encoding="utf-8")
            result = minimal_result(repo)
            result["summary"] = {"totalFindings": 1, "bySeverity": {"medium": 1}}
            result["findings"] = [
                {
                    "id": "TEST-001",
                    "title": "Absolute path finding",
                    "category": "complexity",
                    "severity": "medium",
                    "confidence": "high",
                    "location": {"path": str(source), "line": 1},
                    "evidence": "test evidence",
                    "impact": {"architecture": "test impact"},
                    "recommendation": "test recommendation",
                    "estimatedEffort": "small",
                    "estimatedRoi": "medium",
                    "verification": ["inspect report"],
                    "source": "test",
                }
            ]

            html = render_html(result)

        self.assertIn('class="source-link" href="#src-', html)
        self.assertIn('id="src-', html)
        self.assertIn("const value = 1;", html)

    def test_html_report_marks_truncated_dependency_and_service_tables(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-render-truncated-") as temp_dir:
            repo = Path(temp_dir)
            result = minimal_result(repo)
            result["dependencies"] = [
                {
                    "name": f"package-{index}",
                    "version": "1.0.0",
                    "ecosystem": "npm",
                    "manager": "npm",
                    "vulnerabilityStatus": "not_checked",
                    "path": "package.json",
                }
                for index in range(51)
            ]
            result["dependencySummary"] = {"totalDependencies": 51, "osvStatus": "skipped"}
            result["architecture"] = {
                "summary": {"serviceCount": 41},
                "services": [
                    {
                        "name": f"service-{index}",
                        "type": "node",
                        "path": f"services/{index}",
                        "ports": [],
                        "dependsOn": [],
                        "routes": [],
                    }
                    for index in range(41)
                ],
            }

            html = render_html(result)

        self.assertEqual(html.count("... 1 more omitted"), 2)

    def test_html_report_header_code_chips_have_dark_text(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-render-header-") as temp_dir:
            html = render_html(minimal_result(Path(temp_dir)))

        self.assertIn("header code{color:#17202a;", html)
        self.assertIn("Profile: <code>test</code>", html)
        self.assertIn("Repository: <code>", html)

    def test_html_report_suppresses_external_secret_source_snippets(self) -> None:
        external_marker = "external-redaction-marker-alpha"
        with tempfile.TemporaryDirectory(prefix="auditor-render-external-secret-") as temp_dir:
            repo = Path(temp_dir)
            source = repo / "app.js"
            source.write_text(
                "\n".join(
                    [
                        "const users = [];",
                        f'const marker = "{external_marker}";',
                        "users.map((user) => users.find((other) => other.id === user.id));",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            result = minimal_result(repo)
            result["summary"] = {"totalFindings": 2, "bySeverity": {"high": 1, "medium": 1}}
            result["findings"] = [
                {
                    "id": "SECRET-001",
                    "title": "External scanner secret",
                    "category": "secret",
                    "severity": "high",
                    "confidence": "high",
                    "location": {"path": "app.js", "line": 2},
                    "evidence": "gitleaks-secret: [redacted]",
                    "impact": {"security": "Credential exposure can allow unauthorized access."},
                    "recommendation": "Rotate the secret.",
                    "estimatedEffort": "medium",
                    "estimatedRoi": "high",
                    "verification": ["secret scan"],
                    "source": "scan_secrets:gitleaks",
                    "metadata": {"externalSecret": True, "startLine": 2, "endLine": 2},
                },
                {
                    "id": "COMPLEX-001",
                    "title": "Repeated lookup",
                    "category": "complexity",
                    "severity": "medium",
                    "confidence": "medium",
                    "location": {"path": "app.js", "line": 3},
                    "evidence": "nested lookup",
                    "impact": {"performance": "Potential quadratic work."},
                    "recommendation": "Use an index.",
                    "estimatedEffort": "small",
                    "estimatedRoi": "medium",
                    "verification": ["inspect report"],
                    "source": "scan_complexity",
                },
            ]

            html = render_html(result)

        self.assertNotIn(external_marker, html)
        self.assertIn("[redacted external-secret]", html)
        self.assertEqual(html.count('class="source-link"'), 1)
        self.assertEqual(html.count('<article class="source-ref">'), 1)

    def test_html_report_uses_uncapped_external_secret_redactions(self) -> None:
        external_marker = "external-redaction-marker-beta"
        with tempfile.TemporaryDirectory(prefix="auditor-render-capped-secret-") as temp_dir:
            repo = Path(temp_dir)
            source = repo / "app.js"
            source.write_text(
                "\n".join(
                    [
                        "const users = [];",
                        f'const marker = "{external_marker}";',
                        "eval(req.query.value);",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            result = minimal_result(repo)
            result["summary"] = {"totalFindings": 1, "bySeverity": {"critical": 1}}
            result["sourceRedactions"] = {"externalSecrets": [{"path": "app.js", "startLine": 2, "endLine": 2}]}
            result["findings"] = [
                {
                    "id": "SECURITY-001",
                    "title": "Static security finding",
                    "category": "security",
                    "severity": "critical",
                    "confidence": "high",
                    "location": {"path": "app.js", "line": 3},
                    "evidence": "semgrep finding",
                    "impact": {"security": "Untrusted code execution."},
                    "recommendation": "Remove eval.",
                    "estimatedEffort": "small",
                    "estimatedRoi": "high",
                    "verification": ["inspect report"],
                    "source": "scan_static_security:semgrep",
                }
            ]

            html = render_html(result)

        self.assertNotIn(external_marker, html)
        self.assertIn("[redacted external-secret]", html)
        self.assertIn('class="source-link" href="#src-', html)

    def test_scan_result_preserves_external_secret_redactions_before_cap(self) -> None:
        external_marker = "external-redaction-marker-gamma"
        with tempfile.TemporaryDirectory(prefix="auditor-result-capped-secret-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text(
                "\n".join(
                    [
                        "const users = [];",
                        f'const marker = "{external_marker}";',
                        "eval(req.query.value);",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            original_scan_secrets = auditor_cli.scan_secrets
            original_scan_static_security = auditor_cli.scan_static_security
            try:
                auditor_cli.scan_secrets = lambda _repo, _config: [
                    {
                        "id": "SECRET-001",
                        "title": "External scanner secret",
                        "category": "secret",
                        "severity": "high",
                        "confidence": "high",
                        "location": {"path": "app.js", "line": 2},
                        "evidence": "gitleaks-secret: [redacted]",
                        "impact": {"security": "Credential exposure can allow unauthorized access."},
                        "recommendation": "Rotate the secret.",
                        "estimatedEffort": "medium",
                        "estimatedRoi": "high",
                        "verification": ["secret scan"],
                        "source": "scan_secrets:gitleaks",
                        "metadata": {"externalSecret": True, "startLine": 2, "endLine": 2},
                    }
                ]
                auditor_cli.scan_static_security = lambda _repo, _config: [
                    {
                        "id": "SECURITY-001",
                        "title": "Static security finding",
                        "category": "security",
                        "severity": "critical",
                        "confidence": "high",
                        "location": {"path": "app.js", "line": 3},
                        "evidence": "semgrep finding",
                        "impact": {"security": "Untrusted code execution."},
                        "recommendation": "Remove eval.",
                        "estimatedEffort": "small",
                        "estimatedRoi": "high",
                        "verification": ["inspect report"],
                        "source": "scan_static_security:semgrep",
                    }
                ]
                result = auditor_cli.build_scan_result(repo, "security", None, 1, allow_network=False)
            finally:
                auditor_cli.scan_secrets = original_scan_secrets
                auditor_cli.scan_static_security = original_scan_static_security

            html = render_html(result)

        self.assertEqual([finding["id"] for finding in result["findings"]], ["SECURITY-001"])
        self.assertEqual(result["sourceRedactions"]["externalSecrets"][0]["path"], "app.js")
        self.assertNotIn(external_marker, html)
        self.assertIn("[redacted external-secret]", html)

    def test_html_report_redacts_source_references_with_synthetic_pattern(self) -> None:
        original_patterns = scan_secrets_module.SECRET_PATTERNS
        synthetic_marker = "synthetic-redaction-marker-123"
        try:
            scan_secrets_module.SECRET_PATTERNS = [
                ("synthetic-marker", re.compile(r"synthetic-redaction-marker-\d+"), "high", "high")
            ]
            with tempfile.TemporaryDirectory(prefix="auditor-render-synthetic-redaction-") as temp_dir:
                repo = Path(temp_dir)
                source = repo / "app.js"
                source.write_text(
                    "\n".join(
                        [
                            f'const marker = "{synthetic_marker}";',
                            "const users = [];",
                            "users.map((user) => users.find((other) => other.id === user.id));",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )
                result = minimal_result(repo)
                result["summary"] = {"totalFindings": 1, "bySeverity": {"medium": 1}}
                result["findings"] = [
                    {
                        "id": "COMPLEX-001",
                        "title": "Repeated lookup",
                        "category": "complexity",
                        "severity": "medium",
                        "confidence": "medium",
                        "location": {"path": "app.js", "line": 3},
                        "evidence": "nested lookup",
                        "impact": {"performance": "Potential quadratic work."},
                        "recommendation": "Use an index.",
                        "estimatedEffort": "small",
                        "estimatedRoi": "medium",
                        "verification": ["inspect report"],
                        "source": "scan_complexity",
                    }
                ]

                html = render_html(result)
        finally:
            scan_secrets_module.SECRET_PATTERNS = original_patterns

        self.assertNotIn(synthetic_marker, html)
        self.assertIn("[redacted synthetic-marker]", html)


if __name__ == "__main__":
    unittest.main()
