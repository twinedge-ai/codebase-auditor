from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "codex-codebase-auditor.js"
FIXTURE = ROOT / "tests" / "fixtures" / "remediation-python"


def run_node(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["node", str(BIN), *args], cwd=cwd, text=True, capture_output=True, check=False)


def scan_json(repo: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="auditor-remediation-scan-") as temp_dir:
        json_path = Path(temp_dir) / "audit.json"
        md_path = Path(temp_dir) / "audit.md"
        result = run_node(["scan", str(repo), "--profile", "complexity", "--out", str(md_path), "--json-out", str(json_path)])
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        return json.loads(json_path.read_text(encoding="utf-8"))


class RemediationPhase5Test(unittest.TestCase):
    def test_report_only_scan_does_not_edit_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            shutil.copytree(FIXTURE, repo)
            target = repo / "src" / "classifier.py"
            before = target.read_text(encoding="utf-8")
            payload = scan_json(repo)
            after = target.read_text(encoding="utf-8")

        self.assertEqual(before, after)
        self.assertTrue(any(finding.get("fix", {}).get("kind") == "python-membership-literal-set-hoist" for finding in payload["findings"]))

    def test_explicit_fix_patches_selected_finding_and_reports_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            shutil.copytree(FIXTURE, repo)
            payload = scan_json(repo)
            finding = next(
                finding
                for finding in payload["findings"]
                if finding.get("fix", {}).get("kind") == "python-membership-literal-set-hoist"
            )

            result = run_node(["fix", str(repo), "--finding", finding["id"], "--json"])
            self.assertEqual(result.returncode, 0, result.stderr)
            fix_result = json.loads(result.stdout)
            target_text = (repo / "src" / "classifier.py").read_text(encoding="utf-8")

        self.assertEqual(fix_result["status"], "patched")
        self.assertEqual(fix_result["changedFiles"], ["src/classifier.py"])
        self.assertTrue(fix_result["verification"])
        self.assertTrue(all(item["status"] == "passed" for item in fix_result["verification"]))
        self.assertIn("_auditor_membership_set_", target_text)
        self.assertIn('if status in _auditor_membership_set_', target_text)

    def test_repeated_test_command_flags_are_preserved_by_node_wrapper(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            shutil.copytree(FIXTURE, repo)
            payload = scan_json(repo)
            finding = next(
                finding
                for finding in payload["findings"]
                if finding.get("fix", {}).get("kind") == "python-membership-literal-set-hoist"
            )

            result = run_node(
                [
                    "fix",
                    str(repo),
                    "--finding",
                    finding["id"],
                    "--test-command",
                    "python -c \"print('one')\"",
                    "--test-command",
                    "python -c \"print('two')\"",
                    "--json",
                ]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            fix_result = json.loads(result.stdout)

        commands = [item["command"] for item in fix_result["verification"]]
        self.assertTrue(any("print('one')" in command for command in commands), commands)
        self.assertTrue(any("print('two')" in command for command in commands), commands)

    def test_fix_can_read_finding_from_report_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            shutil.copytree(FIXTURE, repo)
            report_path = Path(temp_dir) / "audit.json"
            md_path = Path(temp_dir) / "audit.md"
            scan = run_node(["scan", str(repo), "--profile", "complexity", "--out", str(md_path), "--json-out", str(report_path)])
            self.assertEqual(scan.returncode, 0, scan.stderr)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            finding = next(
                finding
                for finding in payload["findings"]
                if finding.get("fix", {}).get("kind") == "python-membership-literal-set-hoist"
            )

            result = run_node(["fix", str(repo), "--finding", finding["id"], "--from-report", str(report_path), "--json"])
            self.assertEqual(result.returncode, 0, result.stderr)
            fix_result = json.loads(result.stdout)

        self.assertEqual(fix_result["status"], "patched")

    def test_report_finding_rejects_malicious_variable_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-varname-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            target = repo / "victim.py"
            original = "\n".join(
                [
                    "def f(items):",
                    "    for status in items:",
                    '        if status in ["a", "b", "c", "d"]:',
                    "            pass",
                    "",
                ]
            )
            target.write_text(original, encoding="utf-8")
            literal = '["a", "b", "c", "d"]'
            source_line = '        if status in ["a", "b", "c", "d"]:'
            report_path = temp / "audit.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "crafted-finding",
                                "location": {"path": "victim.py", "line": 3, "symbol": None},
                                "fix": {
                                    "kind": "python-membership-literal-set-hoist",
                                    "loopLine": 2,
                                    "literalLine": 3,
                                    "literalColumnStart": source_line.index(literal),
                                    "literalColumnEnd": source_line.index(literal) + len(literal),
                                    "literalSource": literal,
                                    "setSource": '{"a", "b", "c", "d"}',
                                    "variableName": "x\nimport os\nos.system('echo pwned')\n_y",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = run_node(["fix", str(repo), "--finding", "crafted-finding", "--from-report", str(report_path), "--json"])
            self.assertNotEqual(result.returncode, 0)
            fix_result = json.loads(result.stdout)
            target_after = target.read_text(encoding="utf-8")

        self.assertEqual(fix_result["status"], "unsupported")
        self.assertIn("variableName", fix_result["reason"])
        self.assertEqual(target_after, original)

    def test_report_finding_rejects_malicious_set_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-setsource-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            target = repo / "victim.py"
            original = "\n".join(
                [
                    "def f(items):",
                    "    for status in items:",
                    '        if status in ["a", "b", "c", "d"]:',
                    "            pass",
                    "",
                ]
            )
            target.write_text(original, encoding="utf-8")
            literal = '["a", "b", "c", "d"]'
            source_line = '        if status in ["a", "b", "c", "d"]:'
            report_path = temp / "audit.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "crafted-finding",
                                "location": {"path": "victim.py", "line": 3, "symbol": None},
                                "fix": {
                                    "kind": "python-membership-literal-set-hoist",
                                    "loopLine": 2,
                                    "literalLine": 3,
                                    "literalColumnStart": source_line.index(literal),
                                    "literalColumnEnd": source_line.index(literal) + len(literal),
                                    "literalSource": literal,
                                    "setSource": "__import__('os').system('echo pwned')",
                                    "variableName": "_auditor_membership_set_3",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = run_node(["fix", str(repo), "--finding", "crafted-finding", "--from-report", str(report_path), "--json"])
            self.assertNotEqual(result.returncode, 0)
            fix_result = json.loads(result.stdout)
            target_after = target.read_text(encoding="utf-8")

        self.assertEqual(fix_result["status"], "unsupported")
        self.assertIn("setSource", fix_result["reason"])
        self.assertEqual(target_after, original)

    def test_report_finding_path_cannot_escape_repository(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-escape-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            outside = temp / "outside.py"
            original = "\n".join(
                [
                    "def f(items):",
                    "    for status in items:",
                    '        if status in ["a", "b", "c", "d"]:',
                    "            pass",
                    "",
                ]
            )
            outside.write_text(original, encoding="utf-8")
            literal = '["a", "b", "c", "d"]'
            source_line = '        if status in ["a", "b", "c", "d"]:'
            report_path = temp / "audit.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "crafted-finding",
                                "location": {"path": "../outside.py", "line": 3, "symbol": None},
                                "fix": {
                                    "kind": "python-membership-literal-set-hoist",
                                    "loopLine": 2,
                                    "literalLine": 3,
                                    "literalColumnStart": source_line.index(literal),
                                    "literalColumnEnd": source_line.index(literal) + len(literal),
                                    "literalSource": literal,
                                    "setSource": '{"a", "b", "c", "d"}',
                                    "variableName": "_auditor_membership_set_3",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = run_node(["fix", str(repo), "--finding", "crafted-finding", "--from-report", str(report_path), "--json"])
            self.assertNotEqual(result.returncode, 0)
            fix_result = json.loads(result.stdout)
            outside_after = outside.read_text(encoding="utf-8")

        self.assertEqual(fix_result["status"], "unsupported")
        self.assertIn("escapes the repository", fix_result["reason"])
        self.assertEqual(outside_after, original)

    def test_report_finding_rejects_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-symlink-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            outside = temp / "outside.py"
            original = "\n".join(
                [
                    "def f(items):",
                    "    for status in items:",
                    '        if status in ["a", "b", "c", "d"]:',
                    "            pass",
                    "",
                ]
            )
            outside.write_text(original, encoding="utf-8")
            try:
                os.symlink(outside, repo / "victim.py")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            literal = '["a", "b", "c", "d"]'
            source_line = '        if status in ["a", "b", "c", "d"]:'
            report_path = temp / "audit.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "crafted-finding",
                                "location": {"path": "victim.py", "line": 3, "symbol": None},
                                "fix": {
                                    "kind": "python-membership-literal-set-hoist",
                                    "loopLine": 2,
                                    "literalLine": 3,
                                    "literalColumnStart": source_line.index(literal),
                                    "literalColumnEnd": source_line.index(literal) + len(literal),
                                    "literalSource": literal,
                                    "setSource": '{"a", "b", "c", "d"}',
                                    "variableName": "_auditor_membership_set_3",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = run_node(["fix", str(repo), "--finding", "crafted-finding", "--from-report", str(report_path), "--json"])
            self.assertNotEqual(result.returncode, 0)
            fix_result = json.loads(result.stdout)
            outside_after = outside.read_text(encoding="utf-8")

        self.assertEqual(fix_result["status"], "unsupported")
        self.assertIn("must not be a symlink", fix_result["reason"])
        self.assertEqual(outside_after, original)

    def test_report_finding_hardlink_target_is_replaced_without_clobbering_peer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-remediation-hardlink-") as temp_dir:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            outside = temp / "outside.py"
            original = "\n".join(
                [
                    "def f(items):",
                    "    for status in items:",
                    '        if status in ["a", "b", "c", "d"]:',
                    "            pass",
                    "",
                ]
            )
            outside.write_text(original, encoding="utf-8")
            target = repo / "victim.py"
            try:
                os.link(outside, target)
            except OSError as error:
                self.skipTest(f"hardlinks unavailable: {error}")
            literal = '["a", "b", "c", "d"]'
            source_line = '        if status in ["a", "b", "c", "d"]:'
            report_path = temp / "audit.json"
            report_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "crafted-finding",
                                "location": {"path": "victim.py", "line": 3, "symbol": None},
                                "fix": {
                                    "kind": "python-membership-literal-set-hoist",
                                    "loopLine": 2,
                                    "literalLine": 3,
                                    "literalColumnStart": source_line.index(literal),
                                    "literalColumnEnd": source_line.index(literal) + len(literal),
                                    "literalSource": literal,
                                    "setSource": '{"a", "b", "c", "d"}',
                                    "variableName": "_auditor_membership_set_3",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = run_node(["fix", str(repo), "--finding", "crafted-finding", "--from-report", str(report_path), "--json"])
            self.assertEqual(result.returncode, 0, result.stderr)
            fix_result = json.loads(result.stdout)
            outside_after = outside.read_text(encoding="utf-8")
            target_after = target.read_text(encoding="utf-8")

        self.assertEqual(fix_result["status"], "patched")
        self.assertEqual(outside_after, original)
        self.assertIn("_auditor_membership_set_3", target_after)


if __name__ == "__main__":
    unittest.main()
