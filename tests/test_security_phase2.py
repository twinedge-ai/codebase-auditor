from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "codex-codebase-auditor.js"
DEPS_FIXTURE = ROOT / "tests" / "fixtures" / "security-deps"
AUDITOR_SCRIPTS = ROOT / "skill" / "codebase-auditor" / "scripts"
if str(AUDITOR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(AUDITOR_SCRIPTS))

from auditor import scan_secrets as scan_secrets_module  # noqa: E402


def fake_tool_path(directory: Path, name: str) -> Path:
    suffix = ".cmd" if os.name == "nt" else ""
    return directory / f"{name}{suffix}"


def sh_quote(value: Path) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def write_fake_json_tool(path: Path, *, marker: Path | None = None, args_mode: str | None = None) -> None:
    if os.name == "nt":
        lines = ["@echo off"]
        if marker is not None and args_mode == "append":
            lines.append(f'echo %* >> "{marker}"')
        elif marker is not None and args_mode == "write":
            lines.append(f'echo %* > "{marker}"')
        elif marker is not None:
            lines.append(f'type nul > "{marker}"')
        lines.append('echo {"results":[]}')
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        lines = ["#!/bin/sh"]
        if marker is not None and args_mode == "append":
            lines.append(f'echo "$@" >> {sh_quote(marker)}')
        elif marker is not None and args_mode == "write":
            lines.append(f'echo "$@" > {sh_quote(marker)}')
        elif marker is not None:
            lines.append(f"touch {sh_quote(marker)}")
        lines.append("printf '{\"results\":[]}'")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o755)


def write_fake_gitleaks_tool(path: Path, findings: list[dict]) -> None:
    payload = json.dumps(findings)
    script = path.with_suffix(".py") if os.name == "nt" else path
    script.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import sys",
                "from pathlib import Path",
                f"payload = {payload!r}",
                "args = sys.argv[1:]",
                "report_path = None",
                "for index, arg in enumerate(args[:-1]):",
                "    if arg == '--report-path':",
                "        report_path = args[index + 1]",
                "if report_path:",
                "    Path(report_path).write_text(payload, encoding='utf-8')",
                "",
            ]
        ),
        encoding="utf-8",
    )
    if os.name == "nt":
        path.write_text(f'@echo off\n"{sys.executable}" "{script}" %*\n', encoding="utf-8")
    path.chmod(0o755)


def run_scan(fixture: Path, *extra_args: str, env: dict[str, str] | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix="auditor-phase2-") as temp_dir:
        temp = Path(temp_dir)
        json_path = temp / "audit.json"
        md_path = temp / "audit.md"
        merged_env = {**os.environ, **(env or {})}
        result = subprocess.run(
            [
                "node",
                str(BIN),
                "scan",
                str(fixture),
                "--profile",
                "security",
                "--out",
                str(md_path),
                "--json-out",
                str(json_path),
                *extra_args,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=merged_env,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        return json.loads(json_path.read_text(encoding="utf-8"))


class SecurityPhase2Test(unittest.TestCase):
    def test_osv_mock_produces_high_severity_dependency_finding(self) -> None:
        payload = run_scan(
            DEPS_FIXTURE,
            "--allow-network",
            "--allow-mocks",
            env={"CODEX_AUDITOR_OSV_RESPONSE_FILE": str(DEPS_FIXTURE / "osv-response.json")},
        )
        dependency_findings = [finding for finding in payload["findings"] if finding["category"] == "dependency"]
        self.assertTrue(dependency_findings)
        self.assertTrue(any(finding["severity"] in {"high", "critical"} for finding in dependency_findings))
        self.assertEqual(payload["dependencySummary"]["osvStatus"], "checked")

    def test_offline_dependency_inventory_does_not_require_network(self) -> None:
        payload = run_scan(DEPS_FIXTURE, "--offline")
        self.assertGreaterEqual(payload["dependencySummary"]["totalDependencies"], 1)
        self.assertEqual(payload["dependencySummary"]["osvStatus"], "not_checked_offline")
        self.assertTrue(
            any(dep["vulnerabilityStatus"] == "not_checked_offline" for dep in payload["dependencies"]),
            payload["dependencies"],
        )

    def test_secret_findings_are_redacted_and_static_leads_are_reported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-security-secrets-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            fake_gitleaks = fake_tool_path(temp, "gitleaks")
            write_fake_gitleaks_tool(
                fake_gitleaks,
                [{"File": "app.js", "StartLine": 3, "EndLine": 3, "RuleID": "synthetic-rule"}],
            )
            operator_config = temp / "operator-config.json"
            operator_config.write_text(
                json.dumps({"security": {"runGitleaks": True}, "externalTools": {"gitleaks": str(fake_gitleaks)}}),
                encoding="utf-8",
            )
            (repo / "app.js").write_text(
                "\n".join(
                    [
                        'const express = require("express");',
                        "const app = express();",
                        'const reviewMarker = "source-review-marker";',
                        "app.get('/proxy', async (req, res) => {",
                        "  const response = await fetch(req.query.url);",
                        "  res.send(await response.text());",
                        "});",
                        "app.post('/preview', (req, res) => {",
                        "  document.body.innerHTML = req.body.html;",
                        "  res.send('ok');",
                        "});",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--offline", "--config", str(operator_config))
        rendered = json.dumps(payload)
        self.assertNotIn("source-review-marker", rendered)
        secrets = [finding for finding in payload["findings"] if finding["category"] == "secret"]
        static_security = [finding for finding in payload["findings"] if finding["category"] == "security"]
        self.assertTrue(secrets)
        self.assertTrue(all("[redacted]" in finding["evidence"] for finding in secrets))
        self.assertTrue(static_security)

    def test_symlinked_repo_files_are_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-symlink-file-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            outside = temp / "outside.js"
            outside.write_text("const value = eval(req.query.value);\n", encoding="utf-8")
            try:
                os.symlink(outside, repo / "leak.js")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")

            payload = run_scan(repo, "--offline")

        self.assertFalse(
            any(finding["location"]["path"] == "leak.js" for finding in payload["findings"]),
            payload["findings"],
        )

    def test_placeholder_comment_does_not_hide_matched_sensitive_value(self) -> None:
        original_patterns = scan_secrets_module.SECRET_PATTERNS
        try:
            scan_secrets_module.SECRET_PATTERNS = [
                ("synthetic-sensitive-marker", re.compile(r"synthetic-sensitive-marker=([A-Z]{6})"), "high", "high")
            ]
            finding = scan_secrets_module.secret_finding_for_line(
                "app.js",
                1,
                'const marker = "synthetic-sensitive-marker=ABCDEF"; // example test credential',
            )
        finally:
            scan_secrets_module.SECRET_PATTERNS = original_patterns

        self.assertIsNotNone(finding)
        self.assertEqual(finding["location"]["path"], "app.js")

    def test_re_compile_line_does_not_hide_static_sink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-static-recompile-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("const value = eval(re.compile(user).pattern);\n", encoding="utf-8")
            payload = run_scan(repo, "--offline")

        self.assertTrue(
            any(finding["location"]["path"] == "app.js" and finding["location"]["symbol"] == "js-eval" for finding in payload["findings"]),
            payload["findings"],
        )

    def test_static_security_ignores_commented_and_string_sinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-static-comments-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text(
                "\n".join(
                    [
                        "// eval(userInput)",
                        "const text = 'dangerouslySetInnerHTML';",
                        "const safe = 1;",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--offline")

        self.assertFalse([finding for finding in payload["findings"] if finding["category"] == "security"], payload["findings"])

    def test_static_security_detects_template_literal_sql_interpolation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-static-template-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n", encoding="utf-8")
            payload = run_scan(repo, "--offline")

        self.assertTrue(
            any(finding["location"]["symbol"] == "sql-concat" for finding in payload["findings"] if finding["category"] == "security"),
            payload["findings"],
        )

    def test_xml_dependency_parser_rejects_doctype_entities(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-xml-unsafe-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "pom.xml").write_text(
                """<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>&xxe;</artifactId>
      <version>1.0.0</version>
    </dependency>
  </dependencies>
</project>
""",
                encoding="utf-8",
            )
            payload = run_scan(repo, "--offline")

        self.assertEqual(payload["dependencySummary"]["totalDependencies"], 0)

    def test_modern_pnpm_and_yarn_lock_entries_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-lockfiles-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "pnpm-lock.yaml").write_text(
                "\n".join(
                    [
                        "lockfileVersion: '9.0'",
                        "importers:",
                        "  .: {}",
                        "packages:",
                        "  /left-pad@1.3.0:",
                        "    resolution: {integrity: sha512-test}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / "yarn.lock").write_text(
                "\n".join(
                    [
                        "__metadata:",
                        '  version: "8"',
                        '"@scope/pkg@npm:^2.0.0":',
                        '  version: "2.1.0"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--offline")

        names = {dep["name"] for dep in payload["dependencies"]}
        self.assertIn("left-pad", names)
        self.assertIn("@scope/pkg", names)

    def test_yarn_v1_lock_entries_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-yarn-v1-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "yarn.lock").write_text(
                "\n".join(
                    [
                        "left-pad@^1.3.0:",
                        '  version "1.3.0"',
                        '  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--offline")

        self.assertTrue(any(dep["name"] == "left-pad" and dep["version"] == "1.3.0" for dep in payload["dependencies"]), payload["dependencies"])

    def test_non_queried_osv_versions_are_not_marked_checked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-osv-status-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "^1.3.0"}}), encoding="utf-8")
            payload = run_scan(repo, "--allow-network", "--allow-mocks", env={"CODEX_AUDITOR_OSV_RESPONSE_FILE": str(repo / "missing-osv.json")})

        dep = next(item for item in payload["dependencies"] if item["name"] == "left-pad")
        self.assertEqual(dep["vulnerabilityStatus"], "not_checked_version_not_exact")
        self.assertEqual(payload["dependencySummary"]["osvStatus"], "no_exact_versions")

    def test_maven_final_versions_are_queried_as_exact_stable_versions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-maven-final-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "pom.xml").write_text(
                """<project>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>demo</artifactId>
      <version>1.0.0.Final</version>
    </dependency>
  </dependencies>
</project>
""",
                encoding="utf-8",
            )
            osv_response = repo / "osv-response.json"
            osv_response.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "vulns": [
                                    {
                                        "id": "OSV-TEST",
                                        "summary": "mock vulnerability",
                                        "aliases": ["CVE-0000-0000"],
                                        "database_specific": {"severity": "HIGH"},
                                    }
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--allow-network", "--allow-mocks", env={"CODEX_AUDITOR_OSV_RESPONSE_FILE": str(osv_response)})

        dep = next(item for item in payload["dependencies"] if item["name"] == "org.example:demo")
        self.assertEqual(dep["vulnerabilityStatus"], "vulnerable")
        self.assertEqual(payload["dependencySummary"]["osvStatus"], "checked")

    def test_external_tools_are_not_resolved_from_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-path-tools-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            tools = temp / "tools"
            marker = temp / "semgrep-ran"
            repo.mkdir()
            tools.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps({"security": {"runSemgrep": True}}),
                encoding="utf-8",
            )
            fake_semgrep = fake_tool_path(tools, "semgrep")
            write_fake_json_tool(fake_semgrep, marker=marker)
            payload = run_scan(
                repo,
                "--offline",
                "--config",
                str(operator_config),
                env={"PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}"},
            )

        self.assertFalse(marker.exists())
        self.assertEqual(payload["summary"]["byCategory"].get("security", 0), 0)

    def test_external_tool_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-symlink-tool-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            tools = temp / "tools"
            marker = temp / "semgrep-ran"
            repo.mkdir()
            tools.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            real_semgrep = fake_tool_path(tools, "real-semgrep")
            write_fake_json_tool(real_semgrep, marker=marker)
            symlink = fake_tool_path(tools, "semgrep")
            os.symlink(real_semgrep, symlink)
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps({"security": {"runSemgrep": True}, "externalTools": {"semgrep": str(symlink)}}),
                encoding="utf-8",
            )
            run_scan(repo, "--offline", "--config", str(operator_config))

        self.assertFalse(marker.exists())

    def test_semgrep_auto_config_requires_allow_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-semgrep-auto-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            tools = temp / "tools"
            marker = temp / "semgrep-ran"
            repo.mkdir()
            tools.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            fake_semgrep = fake_tool_path(tools, "semgrep")
            write_fake_json_tool(fake_semgrep, marker=marker, args_mode="append")
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps({"security": {"runSemgrep": True}, "externalTools": {"semgrep": str(fake_semgrep)}}),
                encoding="utf-8",
            )
            run_scan(repo, "--offline", "--config", str(operator_config))

        self.assertFalse(marker.exists())

    def test_semgrep_explicit_local_config_runs_offline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-semgrep-local-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            tools = temp / "tools"
            marker = temp / "semgrep-args"
            repo.mkdir()
            tools.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            fake_semgrep = fake_tool_path(tools, "semgrep")
            write_fake_json_tool(fake_semgrep, marker=marker, args_mode="write")
            local_rules = repo / "semgrep-rules.yml"
            local_rules.write_text("rules: []\n", encoding="utf-8")
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps(
                    {
                        "security": {"runSemgrep": True, "semgrepConfig": str(local_rules)},
                        "externalTools": {"semgrep": str(fake_semgrep)},
                    }
                ),
                encoding="utf-8",
            )
            run_scan(repo, "--offline", "--config", str(operator_config))
            marker_existed = marker.exists()
            args = marker.read_text(encoding="utf-8") if marker_existed else ""

        self.assertTrue(marker_existed)
        self.assertIn(str(local_rules), args)
        self.assertNotIn(" auto ", f" {args} ")

    def test_semgrep_explicit_auto_config_blocked_offline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-semgrep-explicit-auto-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            tools = temp / "tools"
            marker = temp / "semgrep-ran"
            repo.mkdir()
            tools.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            fake_semgrep = fake_tool_path(tools, "semgrep")
            write_fake_json_tool(fake_semgrep, marker=marker)
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps(
                    {
                        "security": {"runSemgrep": True, "semgrepConfig": "auto"},
                        "externalTools": {"semgrep": str(fake_semgrep)},
                    }
                ),
                encoding="utf-8",
            )
            run_scan(repo, "--offline", "--config", str(operator_config))

        self.assertFalse(marker.exists())

    def test_semgrep_saved_snapshot_config_blocked_offline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-semgrep-snapshot-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            tools = temp / "tools"
            marker = temp / "semgrep-ran"
            repo.mkdir()
            tools.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            fake_semgrep = fake_tool_path(tools, "semgrep")
            write_fake_json_tool(fake_semgrep, marker=marker)
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps(
                    {
                        "security": {"runSemgrep": True, "semgrepConfig": "s/saved-snapshot"},
                        "externalTools": {"semgrep": str(fake_semgrep)},
                    }
                ),
                encoding="utf-8",
            )
            run_scan(repo, "--offline", "--config", str(operator_config))

        self.assertFalse(marker.exists())

    def test_repo_local_config_cannot_set_external_tools(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-repo-config-trust-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            tools = temp / "tools"
            marker = temp / "evil-semgrep-ran"
            repo.mkdir()
            tools.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            fake_semgrep = fake_tool_path(tools, "semgrep")
            write_fake_json_tool(fake_semgrep, marker=marker)
            (repo / ".codebase-auditor.json").write_text(
                json.dumps({"security": {"runSemgrep": True}, "externalTools": {"semgrep": str(fake_semgrep)}}),
                encoding="utf-8",
            )
            run_scan(repo, "--offline")

        self.assertFalse(marker.exists())

    def test_repo_local_config_cannot_suppress_security_results(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-repo-config-security-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text(
                "\n".join(
                    [
                        "const value = eval(req.query.value);",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / ".codebase-auditor.json").write_text(
                json.dumps(
                    {
                        "exclude": ["."],
                        "maxFindings": 0,
                        "security": {
                            "scanSecrets": False,
                            "staticSecurity": False,
                            "dependencyAudit": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--offline")

        categories = {finding["category"] for finding in payload["findings"]}
        self.assertIn("security", categories, payload["findings"])

    def test_repo_local_config_exceeding_size_cap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-repo-config-size-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            (repo / ".codebase-auditor.json").write_text(
                json.dumps({"exclude": ["x" * 2_000_000]}),
                encoding="utf-8",
            )
            with self.assertRaises(AssertionError) as caught:
                run_scan(repo, "--offline")

        self.assertIn("exceeds", str(caught.exception))
        self.assertNotIn("Traceback", str(caught.exception))

    def test_safe_subprocess_array_is_not_reported_as_shell_execution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-static-security-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "safe.py").write_text(
                "import subprocess\nsubprocess.run(['python', '--version'], check=False)\n",
                encoding="utf-8",
            )
            (repo / "unsafe.py").write_text(
                "import subprocess\nsubprocess.run('python --version', shell=True, check=False)\n",
                encoding="utf-8",
            )
            payload = run_scan(repo, "--offline")

        findings = [finding for finding in payload["findings"] if finding["category"] == "security"]
        self.assertFalse(any(finding["location"]["path"] == "safe.py" for finding in findings), findings)
        self.assertTrue(any(finding["location"]["path"] == "unsafe.py" and finding["location"]["symbol"] == "python-shell-true" for finding in findings))


if __name__ == "__main__":
    unittest.main()
