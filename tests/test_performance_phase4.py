from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "codex-codebase-auditor.js"
LIGHTHOUSE_FIXTURE = ROOT / "tests" / "fixtures" / "performance" / "lighthouse-response.json"
AUDITOR_SCRIPTS = ROOT / "skill" / "codebase-auditor" / "scripts"
if str(AUDITOR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(AUDITOR_SCRIPTS))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/missing":
            payload = b"missing"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


class LocalServer:
    def __enter__(self) -> "LocalServer":
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def fake_tool_path(directory: Path, name: str) -> Path:
    suffix = ".cmd" if os.name == "nt" else ""
    return directory / f"{name}{suffix}"


def sh_quote(value: Path) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def write_fake_lighthouse(path: Path, marker: Path) -> None:
    if os.name == "nt":
        path.write_text(
            f"@echo off\n"
            f'echo %* > "{marker}"\n'
            f'echo {{"categories":{{"performance":{{"score":1}}}},"audits":{{}}}}\n',
            encoding="utf-8",
        )
    else:
        path.write_text(
            f"#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" > {sh_quote(marker)}\n"
            f"printf '{{\"categories\":{{\"performance\":{{\"score\":1}}}},\"audits\":{{}}}}'\n",
            encoding="utf-8",
        )
    path.chmod(0o755)


def scan_repo(repo: Path, *args: str, env: dict[str, str] | None = None) -> tuple[dict, str]:
    with tempfile.TemporaryDirectory(prefix="auditor-performance-") as temp_dir:
        temp = Path(temp_dir)
        md_path = temp / "audit.md"
        json_path = temp / "audit.json"
        result = subprocess.run(
            ["node", str(BIN), "scan", str(repo), "--out", str(md_path), "--json-out", str(json_path), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env={**os.environ, **(env or {})},
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        return json.loads(json_path.read_text(encoding="utf-8")), md_path.read_text(encoding="utf-8")


def scan(*args: str, env: dict[str, str] | None = None) -> tuple[dict, str]:
    return scan_repo(ROOT, *args, env=env)


class PerformancePhase4Test(unittest.TestCase):
    def test_runtime_checks_are_skipped_by_default(self) -> None:
        payload, _markdown = scan("--profile", "performance")
        self.assertFalse(payload["performance"]["enabled"])
        self.assertEqual(payload["performance"]["summary"]["status"], "skipped")

    def test_configured_local_url_produces_frontend_and_lighthouse_metrics(self) -> None:
        with LocalServer() as server:
            payload, markdown = scan(
                "--profile",
                "performance",
                "--allow-perf",
                "--allow-private-network",
                "--frontend-url",
                server.url,
                "--run-lighthouse",
                "--allow-mocks",
                env={"CODEX_AUDITOR_LIGHTHOUSE_RESPONSE_FILE": str(LIGHTHOUSE_FIXTURE)},
            )
        performance = payload["performance"]
        self.assertTrue(performance["enabled"])
        self.assertEqual(performance["frontend"]["probe"]["status"], "completed")
        self.assertEqual(performance["frontend"]["lighthouse"]["status"], "completed")
        self.assertEqual(performance["frontend"]["lighthouse"]["metrics"]["performanceScore"], 72)
        self.assertIn("## Runtime Performance Results", markdown)

    def test_explicit_operator_config_can_enable_runtime_gates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-runtime-config-") as temp_dir, LocalServer() as server:
            temp = Path(temp_dir)
            repo = temp / "repo"
            repo.mkdir()
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps(
                    {
                        "allowPerfTests": True,
                        "allowPrivateNetwork": True,
                        "allowMocks": True,
                        "frontend": {"url": server.url, "runLighthouse": True},
                        "performance": {"lighthouseMockPath": str(LIGHTHOUSE_FIXTURE)},
                    }
                ),
                encoding="utf-8",
            )
            payload, _markdown = scan_repo(repo, "--profile", "performance", "--config", str(operator_config))

        performance = payload["performance"]
        self.assertTrue(performance["enabled"])
        self.assertEqual(performance["frontend"]["probe"]["status"], "completed")
        self.assertEqual(performance["frontend"]["lighthouse"]["status"], "completed")
        self.assertEqual(performance["frontend"]["lighthouse"]["source"], "mock")

    def test_lighthouse_uses_sandboxed_chrome_flags_by_default(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-lighthouse-flags-") as temp_dir:
            temp = Path(temp_dir)
            tools = temp / "tools"
            repo = temp / "repo"
            tools.mkdir()
            repo.mkdir()
            marker = temp / "lighthouse-args"
            fake_lighthouse = fake_tool_path(tools, "lighthouse")
            write_fake_lighthouse(fake_lighthouse, marker)
            operator_config = temp / "operator.json"
            operator_config.write_text(
                json.dumps({"externalTools": {"lighthouse": str(fake_lighthouse)}}),
                encoding="utf-8",
            )
            with LocalServer() as server:
                payload, _markdown = scan_repo(
                    repo,
                    "--profile",
                    "performance",
                    "--allow-perf",
                    "--allow-private-network",
                    "--frontend-url",
                    server.url,
                    "--run-lighthouse",
                    "--config",
                    str(operator_config),
                )
                args = marker.read_text(encoding="utf-8")
                payload_no_sandbox, _markdown = scan_repo(
                    repo,
                    "--profile",
                    "performance",
                    "--allow-perf",
                    "--allow-private-network",
                    "--frontend-url",
                    server.url,
                    "--run-lighthouse",
                    "--lighthouse-no-sandbox",
                    "--config",
                    str(operator_config),
                )
                args_no_sandbox = marker.read_text(encoding="utf-8")

        self.assertEqual(payload["performance"]["frontend"]["lighthouse"]["status"], "completed")
        self.assertIn("--chrome-flags=--headless", args)
        self.assertNotIn("--no-sandbox", args)
        self.assertEqual(payload_no_sandbox["performance"]["frontend"]["lighthouse"]["status"], "completed")
        self.assertIn("--chrome-flags=--headless --no-sandbox", args_no_sandbox)

    def test_load_test_reports_latency_percentiles_and_error_rate(self) -> None:
        with LocalServer() as server:
            payload, _markdown = scan(
                "--profile",
                "performance",
                "--allow-perf",
                "--allow-private-network",
                "--load-url",
                server.url,
                "--run-load-test",
                "--perf-requests",
                "8",
                "--perf-concurrency",
                "2",
            )
        load_tests = payload["performance"]["loadTests"]
        self.assertEqual(len(load_tests), 1)
        metrics = load_tests[0]["metrics"]
        self.assertEqual(metrics["requests"], 8)
        self.assertEqual(metrics["errorRate"], 0)
        self.assertIsNotNone(metrics["totalMs"]["p50"])
        self.assertIsNotNone(metrics["totalMs"]["p95"])
        self.assertIsNotNone(metrics["totalMs"]["p99"])

    def test_frontend_probe_reports_http_error_status_codes(self) -> None:
        with LocalServer() as server:
            payload, _markdown = scan(
                "--profile",
                "performance",
                "--allow-perf",
                "--allow-private-network",
                "--frontend-url",
                f"{server.url}missing",
            )
        probe = payload["performance"]["frontend"]["probe"]
        self.assertEqual(probe["metrics"]["statusCodes"], [404])
        self.assertEqual(probe["metrics"]["errorRate"], 1)
        self.assertTrue(any(finding["title"] == "Frontend URL probe returned errors" for finding in payload["findings"]))

    def test_repeated_load_url_flags_are_preserved_by_node_wrapper(self) -> None:
        with LocalServer() as server:
            payload, _markdown = scan(
                "--profile",
                "performance",
                "--allow-perf",
                "--allow-private-network",
                "--load-url",
                server.url,
                "--load-url",
                server.url,
                "--run-load-test",
                "--perf-requests",
                "2",
                "--perf-concurrency",
                "1",
            )
        self.assertEqual(len(payload["performance"]["loadTests"]), 2)

    def test_repo_local_config_cannot_set_runtime_perf_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-perf-config-trust-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            with LocalServer() as server:
                (repo / ".codebase-auditor.json").write_text(
                    json.dumps(
                        {
                            "frontend": {"url": server.url, "runLighthouse": True, "probeRequests": 1},
                            "performance": {"targets": [server.url], "runLoadTests": True},
                        }
                    ),
                    encoding="utf-8",
                )
                payload, _markdown = scan_repo(
                    repo,
                    "--profile",
                    "performance",
                    "--allow-perf",
                    "--allow-private-network",
                    "--run-load-test",
                )

        performance = payload["performance"]
        self.assertEqual(performance["frontend"]["probe"]["status"], "skipped")
        self.assertEqual(performance["frontend"]["lighthouse"]["status"], "skipped")
        self.assertEqual(performance["loadTests"], [])

    def test_repo_local_config_cannot_amplify_runtime_perf_limits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditor-perf-limit-trust-") as temp_dir:
            repo = Path(temp_dir)
            (repo / "app.js").write_text("const ok = 1;\n", encoding="utf-8")
            (repo / ".codebase-auditor.json").write_text(
                json.dumps(
                    {
                        "frontend": {"probeRequests": 999},
                        "performance": {
                            "requests": 999,
                            "concurrency": 999,
                            "timeoutSeconds": 999,
                            "maxDurationSeconds": 999,
                        },
                    }
                ),
                encoding="utf-8",
            )
            with LocalServer() as server:
                payload, _markdown = scan_repo(
                    repo,
                    "--profile",
                    "performance",
                    "--allow-perf",
                    "--allow-private-network",
                    "--frontend-url",
                    server.url,
                    "--load-url",
                    server.url,
                    "--run-load-test",
                )

        probe_metrics = payload["performance"]["frontend"]["probe"]["metrics"]
        load_metrics = payload["performance"]["loadTests"][0]["metrics"]
        self.assertEqual(probe_metrics["requests"], 3)
        self.assertEqual(load_metrics["requests"], 20)
        self.assertEqual(load_metrics["concurrency"], 4)

    def test_runtime_perf_limits_are_clamped(self) -> None:
        from auditor.run_perf_checks import MAX_BUILTIN_LOAD_REQUESTS, MAX_LOAD_CONCURRENCY, bounded_float, bounded_int

        self.assertEqual(bounded_int(9999, 20, 1, MAX_BUILTIN_LOAD_REQUESTS), MAX_BUILTIN_LOAD_REQUESTS)
        self.assertEqual(bounded_int(9999, 4, 1, MAX_LOAD_CONCURRENCY), MAX_LOAD_CONCURRENCY)
        self.assertEqual(bounded_float(9999, 5.0, 0.1, 30.0), 30.0)
        self.assertEqual(bounded_int("not-a-number", 20, 1, MAX_BUILTIN_LOAD_REQUESTS), 20)

    def test_file_url_is_rejected_by_frontend_probe(self) -> None:
        payload, _markdown = scan(
            "--profile",
            "performance",
            "--allow-perf",
            "--frontend-url",
            "file:///etc/passwd",
        )
        probe = payload["performance"]["frontend"]["probe"]
        self.assertEqual(probe["status"], "failed")
        self.assertIn("http or https", probe["reason"])

    def test_malformed_url_is_rejected_without_traceback(self) -> None:
        payload, _markdown = scan(
            "--profile",
            "performance",
            "--allow-perf",
            "--frontend-url",
            "http://example.com:bad/",
        )
        probe = payload["performance"]["frontend"]["probe"]
        self.assertEqual(probe["status"], "failed")
        self.assertEqual(probe["reason"], "URL is malformed")

    def test_malformed_url_policy_errors_are_user_facing(self) -> None:
        from auditor.network_policy import UrlPolicyError, open_url, validate_http_url

        for url in ["http://example.com:bad/", "http://127.0.0.1:999999/", "http://[::1"]:
            self.assertEqual(validate_http_url(url), "URL is malformed")
            with self.assertRaises(UrlPolicyError):
                open_url(url, timeout=1.0)

    def test_private_url_is_rejected_without_confirmation(self) -> None:
        with LocalServer() as server:
            payload, _markdown = scan(
                "--profile",
                "performance",
                "--allow-perf",
                "--frontend-url",
                server.url,
            )
        probe = payload["performance"]["frontend"]["probe"]
        self.assertEqual(probe["status"], "failed")
        self.assertIn("private", probe["reason"])

    def test_pinned_ip_fetch_rejects_private_address_resolution(self) -> None:
        from auditor.network_policy import UrlPolicyError, open_url, validate_http_url

        self.assertEqual(
            validate_http_url("http://localhost/"),
            "private, loopback, reserved, and link-local hosts require --allow-private-network",
        )
        with self.assertRaises(UrlPolicyError):
            open_url("http://localhost/", allow_private_network=False, timeout=1.0)

    def test_ipv6_classification_normalizes_mapped_and_blocks_tunnels(self) -> None:
        from auditor.network_policy import is_restricted_ip

        self.assertTrue(is_restricted_ip("::ffff:127.0.0.1"))
        self.assertTrue(is_restricted_ip("::ffff:10.0.0.1"))
        self.assertTrue(is_restricted_ip("::ffff:169.254.1.1"))
        self.assertTrue(is_restricted_ip("2002:7f00:0001::"))
        self.assertTrue(is_restricted_ip("2001:0000:4136:e378::"))
        self.assertFalse(is_restricted_ip("2606:4700:4700::1111"))

    def test_pinned_ip_fetch_completes_against_local_server(self) -> None:
        from auditor.network_policy import open_url

        with LocalServer() as server:
            response = open_url(server.url, allow_private_network=True, timeout=2.0)
            try:
                body = response.read(1024)
                status = response.status
            finally:
                response.close()
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")

    def test_benchmark_commands_are_skipped_without_confirmation(self) -> None:
        payload, _markdown = scan(
            "--profile",
            "performance",
            "--allow-perf",
            "--run-benchmarks",
        )
        benchmarks = payload["performance"]["benchmarks"]
        self.assertTrue(benchmarks)
        self.assertTrue(all(item["status"] == "skipped" for item in benchmarks), benchmarks)


if __name__ == "__main__":
    unittest.main()
