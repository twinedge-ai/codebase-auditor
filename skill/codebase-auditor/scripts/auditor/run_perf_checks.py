from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .external_tools import resolve_external_tool
from .network_policy import UrlPolicyError, open_url, validate_http_url
from .performance_findings import performance_findings


USER_AGENT = "codex-codebase-auditor/1.0"
MAX_FRONTEND_PROBE_REQUESTS = 20
MAX_BUILTIN_LOAD_REQUESTS = 100
MAX_LOAD_CONCURRENCY = 20
MAX_HTTP_TIMEOUT_SECONDS = 30.0
MAX_RUNTIME_DURATION_SECONDS = 300
MAX_AUTOCANNON_DURATION_SECONDS = 60


def bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def bounded_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def lighthouse_chrome_flags(config: dict[str, Any]) -> str:
    flags = ["--headless"]
    if config.get("performance", {}).get("lighthouseNoSandbox"):
        flags.append("--no-sandbox")
    return " ".join(flags)


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 2)
    rank = (len(ordered) - 1) * pct
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    weight = rank - low
    return round(ordered[low] * (1 - weight) + ordered[high] * weight, 2)


def latency_summary(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"min": None, "p50": None, "p95": None, "p99": None, "max": None, "avg": None}
    return {
        "min": round(min(values), 2),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": round(max(values), 2),
        "avg": round(sum(values) / len(values), 2),
    }


def unsupported_url_sample(reason: str) -> dict[str, Any]:
    return {
        "ok": False,
        "statusCode": None,
        "headersMs": None,
        "totalMs": 0,
        "bytes": 0,
        "error": reason,
    }


def fetch_once(url: str, timeout_seconds: float, allow_private_network: bool = False) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response = open_url(
            url,
            allow_private_network=allow_private_network,
            timeout=timeout_seconds,
            headers={"User-Agent": USER_AGENT},
        )
    except UrlPolicyError as error:
        return unsupported_url_sample(str(error))
    except (OSError, TimeoutError) as error:
        total_ms = (time.perf_counter() - started) * 1000
        return {
            "ok": False,
            "statusCode": None,
            "headersMs": None,
            "totalMs": round(total_ms, 2),
            "bytes": 0,
            "error": error.__class__.__name__,
        }
    try:
        headers_ms = (time.perf_counter() - started) * 1000
        body = response.read(2_000_000)
        total_ms = (time.perf_counter() - started) * 1000
        ok = 200 <= response.status < 400
        return {
            "ok": ok,
            "statusCode": response.status,
            "headersMs": round(headers_ms, 2),
            "totalMs": round(total_ms, 2),
            "bytes": len(body),
            "error": None if ok else "HTTPError",
        }
    finally:
        response.close()


def summarize_http_samples(samples: list[dict[str, Any]]) -> dict[str, Any]:
    latencies = [sample["totalMs"] for sample in samples if sample.get("totalMs") is not None]
    header_latencies = [sample["headersMs"] for sample in samples if sample.get("headersMs") is not None]
    errors = [sample for sample in samples if not sample.get("ok")]
    total_bytes = sum(int(sample.get("bytes") or 0) for sample in samples)
    return {
        "requests": len(samples),
        "errors": len(errors),
        "errorRate": round(len(errors) / len(samples), 4) if samples else None,
        "statusCodes": sorted({sample["statusCode"] for sample in samples if sample.get("statusCode") is not None}),
        "totalMs": latency_summary(latencies),
        "headersMs": latency_summary(header_latencies),
        "bytesAvg": round(total_bytes / len(samples), 2) if samples else None,
    }


def frontend_probe(config: dict[str, Any]) -> dict[str, Any]:
    frontend = config.get("frontend", {})
    url = frontend.get("url")
    if not url:
        return {"status": "skipped", "reason": "frontend.url not configured", "url": None, "metrics": None}
    validation_error = validate_http_url(str(url), bool(config.get("allowPrivateNetwork")))
    if validation_error:
        return {"status": "failed", "reason": validation_error, "url": url, "samples": [], "metrics": None}
    requests = bounded_int(frontend.get("probeRequests", 3), 3, 1, MAX_FRONTEND_PROBE_REQUESTS)
    timeout_seconds = bounded_float(config.get("performance", {}).get("timeoutSeconds", 5), 5.0, 0.1, MAX_HTTP_TIMEOUT_SECONDS)
    samples = [fetch_once(url, timeout_seconds, bool(config.get("allowPrivateNetwork"))) for _ in range(requests)]
    return {"status": "completed", "url": url, "samples": samples, "metrics": summarize_http_samples(samples)}


def extract_lighthouse_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    categories = payload.get("categories", {})
    audits = payload.get("audits", {})

    def numeric_audit(name: str) -> float | None:
        value = audits.get(name, {}).get("numericValue")
        return round(float(value), 2) if isinstance(value, (int, float)) else None

    performance_score = categories.get("performance", {}).get("score")
    return {
        "performanceScore": round(float(performance_score) * 100, 2) if isinstance(performance_score, (int, float)) else None,
        "firstContentfulPaintMs": numeric_audit("first-contentful-paint"),
        "largestContentfulPaintMs": numeric_audit("largest-contentful-paint"),
        "totalBlockingTimeMs": numeric_audit("total-blocking-time"),
        "speedIndexMs": numeric_audit("speed-index"),
        "cumulativeLayoutShift": numeric_audit("cumulative-layout-shift"),
    }


def run_lighthouse(repo: Path, config: dict[str, Any]) -> dict[str, Any]:
    frontend = config.get("frontend", {})
    url = frontend.get("url")
    if not frontend.get("runLighthouse"):
        return {"status": "skipped", "reason": "frontend.runLighthouse is false", "url": url, "metrics": None}
    if not url:
        return {"status": "skipped", "reason": "frontend.url not configured", "url": None, "metrics": None}
    validation_error = validate_http_url(str(url), bool(config.get("allowPrivateNetwork")))
    if validation_error:
        return {"status": "failed", "reason": validation_error, "url": url, "metrics": None}

    allow_mocks = bool(config.get("allowMocks"))
    mock_value = config.get("performance", {}).get("lighthouseMockPath") if allow_mocks else None
    mock_path = Path(str(mock_value)) if mock_value else None
    if mock_path and mock_path.exists():
        payload = json.loads(mock_path.read_text(encoding="utf-8"))
        return {"status": "completed", "url": url, "metrics": extract_lighthouse_metrics(payload), "source": "mock"}

    env_value = os.environ.get("CODEX_AUDITOR_LIGHTHOUSE_RESPONSE_FILE") if allow_mocks else None
    env_mock = Path(env_value) if env_value else None
    if env_mock and env_mock.exists():
        payload = json.loads(env_mock.read_text(encoding="utf-8"))
        return {"status": "completed", "url": url, "metrics": extract_lighthouse_metrics(payload), "source": "mock"}

    lighthouse = resolve_external_tool(config, "lighthouse")
    if not lighthouse:
        return {"status": "skipped", "reason": "lighthouse executable not found", "url": url, "metrics": None}

    timeout = bounded_int(config.get("performance", {}).get("maxDurationSeconds", 60), 60, 1, MAX_RUNTIME_DURATION_SECONDS)
    command = [
        lighthouse,
        url,
        "--quiet",
        "--output=json",
        f"--chrome-flags={lighthouse_chrome_flags(config)}",
    ]
    try:
        result = subprocess.run(command, cwd=repo, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "failed", "reason": error.__class__.__name__, "url": url, "metrics": None}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "failed", "reason": "invalid lighthouse JSON", "url": url, "metrics": None}
    return {"status": "completed", "url": url, "metrics": extract_lighthouse_metrics(payload), "source": "lighthouse"}


def load_targets(config: dict[str, Any]) -> list[str]:
    performance = config.get("performance", {})
    targets = performance.get("targets", [])
    if isinstance(targets, str):
        targets = [targets]
    values = [str(target) for target in targets if target]
    frontend_url = config.get("frontend", {}).get("url")
    if frontend_url and not values:
        values.append(str(frontend_url))
    return values


def built_in_load_test(url: str, config: dict[str, Any]) -> dict[str, Any]:
    validation_error = validate_http_url(url, bool(config.get("allowPrivateNetwork")))
    if validation_error:
        return {"status": "failed", "url": url, "adapter": "built-in", "reason": validation_error, "metrics": None}
    performance = config.get("performance", {})
    total_requests = bounded_int(performance.get("requests", 20), 20, 1, MAX_BUILTIN_LOAD_REQUESTS)
    concurrency = bounded_int(performance.get("concurrency", 4), 4, 1, min(MAX_LOAD_CONCURRENCY, total_requests))
    timeout_seconds = bounded_float(performance.get("timeoutSeconds", 5), 5.0, 0.1, MAX_HTTP_TIMEOUT_SECONDS)
    started = time.perf_counter()
    samples: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(fetch_once, url, timeout_seconds, bool(config.get("allowPrivateNetwork"))) for _ in range(total_requests)]
        for future in as_completed(futures):
            samples.append(future.result())
    elapsed = time.perf_counter() - started
    metrics = summarize_http_samples(samples)
    metrics["throughputRps"] = round(total_requests / elapsed, 2) if elapsed > 0 else None
    metrics["durationSeconds"] = round(elapsed, 3)
    metrics["concurrency"] = concurrency
    return {"status": "completed", "url": url, "adapter": "built-in", "metrics": metrics}


def run_autocannon(repo: Path, url: str, config: dict[str, Any]) -> dict[str, Any] | None:
    performance = config.get("performance", {})
    autocannon = resolve_external_tool(config, "autocannon")
    if not performance.get("runAutocannon") or not autocannon:
        return None
    validation_error = validate_http_url(url, bool(config.get("allowPrivateNetwork")))
    if validation_error:
        return {"status": "failed", "url": url, "adapter": "autocannon", "reason": validation_error, "metrics": None}
    duration = bounded_int(performance.get("maxDurationSeconds", 10), 10, 1, MAX_AUTOCANNON_DURATION_SECONDS)
    concurrency = bounded_int(performance.get("concurrency", 4), 4, 1, MAX_LOAD_CONCURRENCY)
    command = [autocannon, "-j", "-d", str(duration), "-c", str(concurrency), url]
    try:
        result = subprocess.run(command, cwd=repo, text=True, capture_output=True, timeout=duration + 10, check=False)
        payload = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {"status": "failed", "url": url, "adapter": "autocannon", "metrics": None}
    latency = payload.get("latency", {})
    requests = payload.get("requests", {})
    errors = int(payload.get("errors") or 0)
    total = int(requests.get("total") or 0)
    return {
        "status": "completed",
        "url": url,
        "adapter": "autocannon",
        "metrics": {
            "requests": total,
            "errors": errors,
            "errorRate": round(errors / total, 4) if total else None,
            "totalMs": {
                "min": latency.get("min"),
                "p50": latency.get("p50"),
                "p95": latency.get("p95"),
                "p99": latency.get("p99"),
                "max": latency.get("max"),
                "avg": latency.get("average"),
            },
            "throughputRps": requests.get("average"),
            "durationSeconds": duration,
            "concurrency": concurrency,
        },
    }


def run_k6(repo: Path, config: dict[str, Any]) -> dict[str, Any] | None:
    performance = config.get("performance", {})
    script = performance.get("k6Script")
    k6 = resolve_external_tool(config, "k6")
    if not performance.get("runK6") or not script or not k6:
        return None
    with tempfile.TemporaryDirectory(prefix="auditor-k6-") as temp_dir:
        summary_path = Path(temp_dir) / "k6-summary.json"
        command = [k6, "run", "--summary-export", str(summary_path), str(script)]
        try:
            timeout = bounded_int(performance.get("maxDurationSeconds", 60), 60, 1, MAX_RUNTIME_DURATION_SECONDS)
            result = subprocess.run(command, cwd=repo, text=True, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return {"status": "failed", "adapter": "k6", "metrics": None}
        if not summary_path.exists() or result.returncode not in {0, 99}:
            return {"status": "failed", "adapter": "k6", "metrics": None}
        try:
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {"status": "failed", "adapter": "k6", "metrics": None}
    metrics = payload.get("metrics", {})
    http_duration = metrics.get("http_req_duration", {}).get("percentiles", {})
    http_reqs = metrics.get("http_reqs", {}).get("count")
    failed = metrics.get("http_req_failed", {}).get("rate")
    return {
        "status": "completed",
        "adapter": "k6",
        "metrics": {
            "requests": http_reqs,
            "errors": None,
            "errorRate": failed,
            "totalMs": {"min": None, "p50": http_duration.get("p(50)"), "p95": http_duration.get("p(95)"), "p99": http_duration.get("p(99)"), "max": None, "avg": None},
            "throughputRps": None,
        },
    }


def run_load_tests(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    performance = config.get("performance", {})
    if not performance.get("runLoadTests"):
        return []
    results = []
    for url in load_targets(config):
        external = run_autocannon(repo, url, config)
        results.append(external or built_in_load_test(url, config))
    k6_result = run_k6(repo, config)
    if k6_result:
        results.append(k6_result)
    return results


def run_benchmarks(repo: Path, config: dict[str, Any], discovery: dict[str, Any]) -> list[dict[str, Any]]:
    performance = config.get("performance", {})
    if not performance.get("runBenchmarks"):
        return []
    commands = list(config.get("testCommands", []))
    discovered = discovery.get("commands", {})
    if isinstance(discovered, dict):
        for key in ["bench", "benchmark", "test"]:
            if key in discovered:
                commands.append(discovered[key])
    unique_commands = []
    for command in commands:
        if command and command not in unique_commands:
            unique_commands.append(command)

    if not performance.get("confirmBenchmarks"):
        return [
            {
                "command": command,
                "status": "skipped",
                "returnCode": None,
                "durationMs": None,
                "reason": "benchmark commands require --confirm-benchmarks",
            }
            for command in unique_commands[:5]
        ]

    results = []
    timeout = bounded_int(performance.get("maxDurationSeconds", 60), 60, 1, MAX_RUNTIME_DURATION_SECONDS)
    for command in unique_commands[:5]:
        started = time.perf_counter()
        try:
            result = subprocess.run(shlex.split(command), cwd=repo, text=True, capture_output=True, timeout=timeout, check=False)
            status = "completed" if result.returncode == 0 else "failed"
            return_code = result.returncode
        except (OSError, ValueError):
            status = "failed"
            return_code = None
        except subprocess.TimeoutExpired:
            status = "timeout"
            return_code = None
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        results.append({"command": command, "status": status, "returnCode": return_code, "durationMs": duration_ms})
    return results


def run_perf_checks(repo: Path, config: dict[str, Any], discovery: dict[str, Any]) -> dict[str, Any]:
    if not config.get("allowPerfTests"):
        return {
            "enabled": False,
            "skippedReason": "allowPerfTests is false; pass --allow-perf or set config allowPerfTests=true",
            "frontend": {"probe": {"status": "skipped"}, "lighthouse": {"status": "skipped"}},
            "loadTests": [],
            "benchmarks": [],
            "summary": {"status": "skipped", "frontendMetrics": False, "loadTestCount": 0, "benchmarkCount": 0},
            "findings": [],
        }

    probe = frontend_probe(config)
    lighthouse = run_lighthouse(repo, config)
    load_tests = run_load_tests(repo, config)
    benchmarks = run_benchmarks(repo, config, discovery)
    result = {
        "enabled": True,
        "skippedReason": None,
        "frontend": {"probe": probe, "lighthouse": lighthouse},
        "loadTests": load_tests,
        "benchmarks": benchmarks,
        "summary": {
            "status": "completed",
            "frontendMetrics": bool(probe.get("metrics") or lighthouse.get("metrics")),
            "loadTestCount": len(load_tests),
            "benchmarkCount": len(benchmarks),
        },
    }
    result["findings"] = performance_findings(result)
    return result
