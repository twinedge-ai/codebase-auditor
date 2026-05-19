from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "codex-codebase-auditor.js"
FIXTURE = ROOT / "tests" / "fixtures" / "js-complexity"


def run_scan(repo: Path, *extra_args: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="auditor-scan-") as temp_dir:
        temp = Path(temp_dir)
        md_path = temp / "audit.md"
        json_path = temp / "audit.json"
        result = subprocess.run(
            [
                "node",
                str(BIN),
                "scan",
                str(repo),
                "--out",
                str(md_path),
                "--json-out",
                str(json_path),
                *extra_args,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        return json.loads(json_path.read_text(encoding="utf-8"))


def run_scan_outputs(repo: Path, *extra_args: str) -> tuple[dict, str]:
    with tempfile.TemporaryDirectory(prefix="auditor-scan-") as temp_dir:
        temp = Path(temp_dir)
        md_path = temp / "audit.md"
        json_path = temp / "audit.json"
        result = subprocess.run(
            [
                "node",
                str(BIN),
                "scan",
                str(repo),
                "--out",
                str(md_path),
                "--json-out",
                str(json_path),
                *extra_args,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        return json.loads(json_path.read_text(encoding="utf-8")), md_path.read_text(encoding="utf-8")


def run_scan_process(repo: Path, *extra_args: str) -> tuple[subprocess.CompletedProcess[str], dict, str]:
    with tempfile.TemporaryDirectory(prefix="auditor-scan-") as temp_dir:
        temp = Path(temp_dir)
        md_path = temp / "audit.md"
        json_path = temp / "audit.json"
        result = subprocess.run(
            [
                "node",
                str(BIN),
                "scan",
                str(repo),
                "--out",
                str(md_path),
                "--json-out",
                str(json_path),
                *extra_args,
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        payload = json.loads(json_path.read_text(encoding="utf-8")) if json_path.exists() else {}
        markdown = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
        return result, payload, markdown


class CliSmokeTest(unittest.TestCase):
    def test_scan_emits_markdown_and_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-scan-") as temp_dir:
            temp = Path(temp_dir)
            md_path = temp / "audit.md"
            json_path = temp / "audit.json"
            result = subprocess.run(
                [
                    "node",
                    str(BIN),
                    "scan",
                    str(FIXTURE),
                    "--out",
                    str(md_path),
                    "--json-out",
                    str(json_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(md_path.exists())
            self.assertTrue(json_path.exists())

            markdown = md_path.read_text(encoding="utf-8")
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertIn("# Codebase Audit Report", markdown)
            self.assertGreaterEqual(payload["summary"]["totalFindings"], 2)
            self.assertEqual(set(payload["summary"]["bySeverity"]), {"critical", "high", "medium", "low", "info"})
            self.assertIn("JavaScript", {row["name"] for row in payload["discovery"]["languages"]})
            self.assertIn("React", payload["discovery"]["frameworks"])

    def test_discovery_reports_source_lines(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-lines-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.py").write_text("print('one')\n\nprint('two')\n", encoding="utf-8")
            (repo / "data.json").write_text("{\n  \"ok\": true\n}\n", encoding="utf-8")
            payload, markdown = run_scan_outputs(repo, "--profile", "complexity")

        totals = payload["discovery"]["totals"]
        languages = {row["name"]: row for row in payload["discovery"]["languages"]}
        self.assertEqual(totals["sourceFiles"], 1)
        self.assertEqual(totals["sourceLines"], 3)
        self.assertGreaterEqual(payload["scanDurationMs"], 0)
        self.assertEqual(languages["Python"]["lines"], 3)
        self.assertEqual(languages["JSON"]["lines"], 3)
        self.assertIn("- Lines of code scanned: 3", markdown)
        self.assertIn("- Scan duration:", markdown)
        self.assertNotIn("- Primary language:", markdown)
        self.assertIn("| Language | Files | Lines | Bytes |", markdown)

    def test_discovery_counts_sql_as_source_lines(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-sql-lines-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "schema.sql").write_text("select 1;\nselect 2;\n", encoding="utf-8")
            payload, markdown = run_scan_outputs(repo, "--profile", "complexity")

        totals = payload["discovery"]["totals"]
        languages = {row["name"]: row for row in payload["discovery"]["languages"]}
        self.assertEqual(payload["discovery"]["primaryLanguage"], "SQL")
        self.assertEqual(totals["sourceFiles"], 1)
        self.assertEqual(totals["sourceLines"], 2)
        self.assertEqual(languages["SQL"]["lines"], 2)
        self.assertIn("- Lines of code scanned: 2", markdown)

    def test_max_findings_caps_final_report(self) -> None:
        payload = run_scan(FIXTURE, "--profile", "complexity", "--max-findings", "1")
        self.assertEqual(len(payload["findings"]), 1)
        self.assertEqual(payload["summary"]["totalFindings"], 1)

    def test_max_findings_all_is_supported_and_negative_is_rejected(self) -> None:
        payload = run_scan(FIXTURE, "--profile", "complexity", "--max-findings", "all")
        self.assertGreaterEqual(len(payload["findings"]), 2)
        result = subprocess.run(
            ["node", str(BIN), "scan", str(FIXTURE), "--profile", "complexity", "--max-findings", "-1"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_non_repeatable_flags_are_rejected_by_python_cli(self) -> None:
        result = subprocess.run(
            ["node", str(BIN), "scan", str(FIXTURE), "--out", "a.md", "--out", "b.md"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate flag", result.stderr)

    def test_nested_exclude_path_is_respected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-exclude-") as temp_dir:
            repo = Path(temp_dir)
            included = repo / "keep" / "src"
            excluded = repo / "skip" / "nested"
            included.mkdir(parents=True)
            excluded.mkdir(parents=True)
            (included / "ok.js").write_text("const value = 1;\n", encoding="utf-8")
            (excluded / "hot.js").write_text(
                "items.map((item) => users.find((user) => user.id === item.userId));\n",
                encoding="utf-8",
            )
            config = repo / "auditor-config.json"
            config.write_text(json.dumps({"exclude": ["skip/nested"]}), encoding="utf-8")

            without_exclude = run_scan(repo, "--profile", "complexity")
            with_exclude = run_scan(repo, "--profile", "complexity", "--config", str(config))

        self.assertTrue(any(finding["location"]["path"].startswith("skip/nested/") for finding in without_exclude["findings"]))
        self.assertFalse(any(finding["location"]["path"].startswith("skip/nested/") for finding in with_exclude["findings"]))

    def test_missing_explicit_config_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-missing-config-") as temp_dir:
            missing = Path(temp_dir) / "missing.json"
            result = subprocess.run(
                ["node", str(BIN), "scan", str(FIXTURE), "--config", str(missing)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("config file does not exist", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_bad_config_errors_are_user_facing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-bad-config-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            config = temp / "config.json"
            config.write_text("[]\n", encoding="utf-8")
            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--config", str(config)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("config must be a JSON object", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_explicit_config_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-config-symlink-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            outside = temp / "outside.json"
            outside.write_text("{}\n", encoding="utf-8")
            config = temp / "config.json"
            try:
                os.symlink(outside, config)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")

            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--config", str(config)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("config could not be read", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_output_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-output-symlink-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            outside = temp / "outside.md"
            outside.write_text("do not overwrite\n", encoding="utf-8")
            output = repo / "audit.md"
            try:
                os.symlink(outside, output)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")

            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--profile", "security", "--offline", "--out", str(output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            outside_content = outside.read_text(encoding="utf-8")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to overwrite unsafe output path", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(outside_content, "do not overwrite\n")

    def test_output_hardlink_is_replaced_without_clobbering_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-output-hardlink-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            outside = temp / "outside.md"
            outside.write_text("do not overwrite\n", encoding="utf-8")
            output = repo / "audit.md"
            try:
                os.link(outside, output)
            except OSError as error:
                self.skipTest(f"hardlinks unavailable: {error}")

            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--profile", "security", "--offline", "--format", "markdown", "--out", str(output)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            outside_content = outside.read_text(encoding="utf-8")
            output_content = output.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside_content, "do not overwrite\n")
        self.assertIn("# Codebase Audit Report", output_content)

    def test_explicit_config_rejects_string_booleans(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-config-bool-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            config = temp / "config.json"
            config.write_text(json.dumps({"allowNetwork": "false"}), encoding="utf-8")
            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--config", str(config)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("allowNetwork must be a JSON boolean", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_explicit_config_rejects_invalid_known_shapes(self) -> None:
        cases = [
            {"security": []},
            {"frontend": []},
            {"performance": []},
            {"architecture": []},
            {"report": []},
            {"externalTools": []},
            {"testCommands": "npm test"},
            {"report": {"includeMermaidDiagrams": "false"}},
            {"performance": {"requests": "100"}},
        ]
        for config_payload in cases:
            with self.subTest(config=config_payload), tempfile.TemporaryDirectory(prefix="auditor-config-shape-") as temp_dir:
                temp = Path(temp_dir)
                repo = temp / "repo"
                repo.mkdir()
                config = temp / "config.json"
                config.write_text(json.dumps(config_payload), encoding="utf-8")
                result = subprocess.run(
                    ["node", str(BIN), "scan", str(repo), "--config", str(config)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("config has invalid value", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_unreadable_config_errors_are_user_facing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-unreadable-config-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            config = temp / "config.json"
            config.mkdir()
            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--config", str(config)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("config could not be read", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_test_fixtures_are_excluded_by_default_but_operator_can_include(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-fixtures-default-") as temp_dir:
            repo = Path(temp_dir)
            fixture_dir = repo / "tests" / "fixtures"
            fixture_dir.mkdir(parents=True)
            (fixture_dir / "package.json").write_text(json.dumps({"dependencies": {"left-pad": "1.3.0"}}), encoding="utf-8")
            config = repo / "operator-config.json"
            config.write_text(json.dumps({"exclude": [".git", "node_modules", "__pycache__"]}), encoding="utf-8")

            default_payload = run_scan(repo, "--profile", "security", "--offline")
            explicit_payload = run_scan(repo, "--profile", "security", "--offline", "--config", str(config))

        self.assertFalse(any(dep["path"] == "tests/fixtures/package.json" for dep in default_payload["dependencies"]), default_payload["dependencies"])
        self.assertTrue(any(dep["path"] == "tests/fixtures/package.json" for dep in explicit_payload["dependencies"]), explicit_payload["dependencies"])

    def test_selector_helper_name_is_not_treated_as_query_call(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-query-heuristic-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "parser.py").write_text(
                "\n".join(
                    [
                        "def package_name_from_selector(value):",
                        "    return value",
                        "",
                        "def parse(lines):",
                        "    names = []",
                        "    for line in lines:",
                        "        names.append(package_name_from_selector(line))",
                        "    return names",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--profile", "complexity")

        self.assertFalse(
            any(finding["title"] == "I/O or query-like call happens inside a loop" for finding in payload["findings"]),
            payload["findings"],
        )

    def test_for_iterator_sort_is_not_reported_as_sort_inside_loop(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-for-iterator-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "sorts.py").write_text(
                "\n".join(
                    [
                        "def iterator_sort(items):",
                        "    for item in sorted(items):",
                        "        pass",
                        "",
                        "def body_sort(groups):",
                        "    for group in groups:",
                        "        sorted(group)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--profile", "complexity")

        sort_findings = [finding for finding in payload["findings"] if finding["title"] == "Sort happens inside a loop"]
        self.assertEqual(len(sort_findings), 1, payload["findings"])
        self.assertEqual(sort_findings[0]["location"]["line"], 7)

    def test_text_complexity_scanner_ignores_comments_and_string_braces(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-comment-aware-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text(
                "\n".join(
                    [
                        "const ignored = 'for (const x of y) { users.find(x) }';",
                        "// for (const x of y) { fetch(x); }",
                        "for (const group of groups) {",
                        "  const literal = '}';",
                        "  for (const item of group.items) {",
                        "    process(item);",
                        "  }",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            payload = run_scan(repo, "--profile", "complexity")

        self.assertEqual(len([finding for finding in payload["findings"] if finding["title"] == "Nested loop candidate"]), 1, payload["findings"])

    def test_markdown_report_escapes_scanned_table_and_html_content(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-markdown-escape-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "package.json").write_text(
                json.dumps({"dependencies": {"evil|pkg`<script>": "1.0.0"}}),
                encoding="utf-8",
            )
            _payload, markdown = run_scan_outputs(repo, "--profile", "security", "--offline")

        self.assertNotIn("<script>", markdown)
        self.assertNotIn("&lt;script>", markdown)
        self.assertIn("evil\\|pkg\\`&lt;script&gt;", markdown)

    def test_html_report_links_findings_to_source_references(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-html-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            (repo / "app.js").write_text(
                "\n".join(
                    [
                        "const users = [];",
                        "const orders = [];",
                        "function rows() {",
                        "  return users.map((user) => orders.find((order) => order.userId === user.id));",
                        "}",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            html_path = Path(temp_dir) / "audit.html"
            json_path = Path(temp_dir) / "audit.json"
            md_path = Path(temp_dir) / "audit.md"
            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--profile", "quick-static", "--offline", "--out", str(html_path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            html = html_path.read_text(encoding="utf-8") if html_path.exists() else ""
            json_exists = json_path.exists()
            md_exists = md_path.exists()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json_exists)
        self.assertFalse(md_exists)
        self.assertIn("<!doctype html>", html)
        self.assertIn("Source References", html)
        self.assertIn("Lines of code scanned", html)
        self.assertIn("Scan duration", html)
        self.assertNotIn("Primary language</div>", html)
        self.assertIn('class="source-link" href="#src-', html)
        self.assertIn('id="src-', html)

    def test_html_report_only_links_rendered_source_anchors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-html-many-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            for index in range(81):
                (repo / f"f{index}.js").write_text(
                    "\n".join(
                        [
                            "const users = [];",
                            "const orders = [];",
                            "function rows() {",
                            "  return users.map((user) => orders.find((order) => order.userId === user.id));",
                            "}",
                            "",
                        ]
                    ),
                    encoding="utf-8",
                )
            html_path = Path(temp_dir) / "audit.html"
            result = subprocess.run(
                ["node", str(BIN), "scan", str(repo), "--profile", "complexity", "--max-findings", "all", "--out", str(html_path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            html = html_path.read_text(encoding="utf-8") if html_path.exists() else ""

        self.assertEqual(result.returncode, 0, result.stderr)
        source_links = set(re.findall(r'href="#(src-[^"]+)"', html))
        source_anchors = set(re.findall(r'id="(src-[^"]+)"', html))
        self.assertEqual(len(source_links), 80)
        self.assertEqual(source_links - source_anchors, set())

    def test_section_results_reference_global_findings_without_duplicates(self) -> None:
        payload = run_scan(ROOT / "tests" / "fixtures" / "architecture-multiservice", "--profile", "architecture")
        self.assertNotIn("findings", payload["architecture"])
        self.assertIn("findingIds", payload["architecture"])

    def test_repo_local_config_ignores_unsupported_shapes_without_traceback(self) -> None:
        cases = [
            (
                "security-list",
                {"security": []},
                ("--profile", "security", "--offline"),
            ),
            (
                "performance-lists",
                {"frontend": [], "performance": []},
                ("--profile", "performance", "--allow-perf"),
            ),
            (
                "architecture-bad-values",
                {"architecture": {"maxGraphEdges": "bad"}, "report": []},
                ("--profile", "architecture"),
            ),
        ]
        for name, repo_config, args in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix=f"auditor-{name}-") as temp_dir:
                repo = Path(temp_dir)
                (repo / "app.js").write_text("const value = eval(req.query.value);\n", encoding="utf-8")
                (repo / ".codebase-auditor.json").write_text(json.dumps(repo_config), encoding="utf-8")

                result, payload, _markdown = run_scan_process(repo, *args)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertIn("ignoring unsupported repo-local config keys", result.stderr)
                self.assertIn("summary", payload)

    def test_repo_local_report_booleans_must_be_json_booleans(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-report-bool-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("import './dep.js';\n", encoding="utf-8")
            (repo / "dep.js").write_text("export const value = 1;\n", encoding="utf-8")
            (repo / ".codebase-auditor.json").write_text(
                json.dumps({"report": {"includeMermaidDiagrams": "false"}}),
                encoding="utf-8",
            )

            result, payload, _markdown = run_scan_process(repo, "--profile", "architecture")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("report.includeMermaidDiagrams", result.stderr)
        self.assertIsNone(payload["architecture"]["diagrams"]["moduleGraph"])

    def test_repo_local_report_booleans_are_honored_when_valid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-report-bool-valid-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("import './dep.js';\n", encoding="utf-8")
            (repo / "dep.js").write_text("export const value = 1;\n", encoding="utf-8")
            (repo / ".codebase-auditor.json").write_text(
                json.dumps({"report": {"includeMermaidDiagrams": True}}),
                encoding="utf-8",
            )

            result, payload, _markdown = run_scan_process(repo, "--profile", "architecture")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("warning: ignoring", result.stderr)
        self.assertIsNotNone(payload["architecture"]["diagrams"]["moduleGraph"])

    def test_repo_local_config_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-repo-config-symlink-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            (repo / "app.js").write_text("import './dep.js';\n", encoding="utf-8")
            (repo / "dep.js").write_text("export const value = 1;\n", encoding="utf-8")
            outside = temp / "outside.json"
            outside.write_text(json.dumps({"report": {"includeMermaidDiagrams": True}}), encoding="utf-8")
            try:
                os.symlink(outside, repo / ".codebase-auditor.json")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")

            result, payload, _markdown = run_scan_process(repo, "--profile", "architecture")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(payload, {})
        self.assertIn("config could not be read", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_deep_unsupported_repo_local_config_does_not_traceback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-deep-config-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            config = "0"
            for _ in range(200):
                config = f'{{"nested":{config}}}'
            (repo / ".codebase-auditor.json").write_text(config, encoding="utf-8")

            result, payload, _markdown = run_scan_process(repo, "--profile", "architecture")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("ignoring unsupported repo-local config keys", result.stderr)
        self.assertIn("summary", payload)

    def test_too_deep_repo_local_config_error_is_user_facing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-too-deep-config-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            config = "0"
            for _ in range(10000):
                config = f'{{"nested":{config}}}'
            (repo / ".codebase-auditor.json").write_text(config, encoding="utf-8")

            result, _payload, _markdown = run_scan_process(repo, "--profile", "architecture")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("config nesting is too deep", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_too_deep_explicit_config_error_is_user_facing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-too-deep-explicit-config-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            config = "0"
            for _ in range(5000):
                config = f'{{"nested":{config}}}'
            config_path = temp / "config.json"
            config_path.write_text(config, encoding="utf-8")

            result, _payload, _markdown = run_scan_process(repo, "--profile", "architecture", "--config", str(config_path))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("config nesting is too deep", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
