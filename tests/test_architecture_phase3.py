from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "codex-codebase-auditor.js"
FIXTURE = ROOT / "tests" / "fixtures" / "architecture-multiservice"
AUDITOR_SCRIPTS = ROOT / "skill" / "codebase-auditor" / "scripts"
if str(AUDITOR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(AUDITOR_SCRIPTS))


class ArchitecturePhase3Test(unittest.TestCase):
    def test_architecture_profile_maps_services_cycles_and_diagrams(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-architecture-") as temp_dir:
            temp = Path(temp_dir)
            md_path = temp / "audit.md"
            json_path = temp / "audit.json"
            result = subprocess.run(
                [
                    "node",
                    str(BIN),
                    "scan",
                    str(FIXTURE),
                    "--profile",
                    "architecture",
                    "--include-diagrams",
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

            markdown = md_path.read_text(encoding="utf-8")
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            architecture = payload["architecture"]

            service_names = {service["name"] for service in architecture["services"]}
            self.assertTrue({"web", "api", "db"}.issubset(service_names), service_names)
            self.assertGreaterEqual(architecture["summary"]["serviceCount"], 3)
            self.assertGreaterEqual(architecture["summary"]["edgeCount"], 2)
            self.assertGreaterEqual(architecture["summary"]["cycleCount"], 1)
            self.assertIn("```mermaid", markdown)
            self.assertIsNotNone(architecture["diagrams"]["serviceTopology"])
            self.assertIsNotNone(architecture["diagrams"]["moduleGraph"])
            self.assertTrue(any(finding["category"] == "architecture" for finding in payload["findings"]))

    def test_mermaid_label_escapes_backticks_and_newlines(self) -> None:
        from auditor.map_architecture import mermaid_label

        label = "foo\n```\n# header\n.py"
        rendered = mermaid_label(label)
        self.assertNotIn("`", rendered)
        self.assertNotIn("\n", rendered)
        self.assertNotIn("\r", rendered)

    def test_kubernetes_parser_anchors_name_to_metadata_block(self) -> None:
        from auditor.architecture_services import parse_kubernetes_service

        with tempfile.TemporaryDirectory(prefix="auditor-k8s-anchor-") as temp_dir:
            repo = Path(temp_dir)
            manifest = repo / "deploy.yaml"
            manifest.write_text(
                "\n".join(
                    [
                        "apiVersion: apps/v1",
                        "kind: Deployment",
                        "metadata:",
                        "  name: real-service",
                        "  labels:",
                        "    name: not-the-service",
                        "spec:",
                        "  template:",
                        "    spec:",
                        "      containers:",
                        "        - name: app-container",
                        "          ports:",
                        "            - containerPort: 8080",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            service = parse_kubernetes_service(repo, manifest)

        self.assertIsNotNone(service)
        assert service is not None
        self.assertEqual(service["name"], "real-service")
        self.assertEqual(service["type"], "kubernetes-deployment")

    def test_kubernetes_parser_handles_multi_document_manifests(self) -> None:
        from auditor.architecture_services import parse_kubernetes_services

        with tempfile.TemporaryDirectory(prefix="auditor-k8s-multidoc-") as temp_dir:
            repo = Path(temp_dir)
            manifest = repo / "stack.yaml"
            manifest.write_text(
                "\n".join(
                    [
                        "apiVersion: v1",
                        "kind: ConfigMap",
                        "metadata:",
                        "  name: config-only",
                        "---",
                        "apiVersion: apps/v1",
                        "kind: Deployment",
                        "metadata:",
                        "  name: web-deploy",
                        "spec:",
                        "  template:",
                        "    spec:",
                        "      containers:",
                        "        - name: web",
                        "          ports:",
                        "            - containerPort: 8080",
                        "---",
                        "apiVersion: v1",
                        "kind: Service",
                        "metadata:",
                        "  name: web-service",
                        "spec:",
                        "  ports:",
                        "    - port: 80",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            services = parse_kubernetes_services(repo, manifest)

        service_rows = {(service["name"], service["type"], tuple(service["ports"])) for service in services}
        self.assertEqual(
            service_rows,
            {
                ("web-deploy", "kubernetes-deployment", ("8080",)),
                ("web-service", "kubernetes-service", ("80",)),
            },
        )


if __name__ == "__main__":
    unittest.main()
