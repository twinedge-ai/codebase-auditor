from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditor.config import ConfigError, load_config
from auditor.discover_repo import discover_repo, prime_repo_cache
from auditor.map_architecture import map_architecture
from auditor.merge_findings import sort_findings, summarize_findings
from auditor.render_report import render_html, render_markdown
from auditor.remediate import remediate_finding
from auditor.run_perf_checks import run_perf_checks
from auditor.scan_complexity import scan_complexity
from auditor.scan_dependencies import scan_dependencies
from auditor.scan_secrets import external_secret_redactions, redact_findings_evidence, scan_secrets
from auditor.scan_static_security import scan_static_security


def require_supported_python() -> None:
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or newer is required.")


def parse_formats(value: str) -> set[str]:
    formats = {part.strip().lower() for part in value.split(",") if part.strip()}
    invalid = formats - {"markdown", "json", "html"}
    if invalid:
        raise argparse.ArgumentTypeError(f"Unsupported format(s): {', '.join(sorted(invalid))}")
    return formats or {"markdown"}


def parse_max_findings(value: str) -> int | str:
    if value.lower() == "all":
        return "all"
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("max findings must be a non-negative integer or 'all'") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("max findings must be a non-negative integer or 'all'")
    return parsed


def cap_findings(findings: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    raw_value = config.get("maxFindings", 50)
    if isinstance(raw_value, str) and raw_value.lower() == "all":
        return findings
    try:
        max_findings = int(raw_value)
    except (TypeError, ValueError) as error:
        raise SystemExit("maxFindings must be a non-negative integer or 'all'") from error
    if max_findings < 0:
        raise SystemExit("maxFindings must be a non-negative integer or 'all'")
    return findings[:max_findings]


def reject_duplicate_flags(argv: list[str], repeatable: set[str] | None = None) -> None:
    repeatable = repeatable or set()
    seen: set[str] = set()
    for value in argv:
        if value == "--":
            return
        if not value.startswith("--"):
            continue
        flag = value.split("=", 1)[0]
        if flag in repeatable:
            continue
        if flag in seen:
            raise SystemExit(f"Duplicate flag is not allowed: {flag}")
        seen.add(flag)


def build_scan_result(
    repo: Path,
    profile: str,
    config_path: Path | None,
    max_findings: int | None,
    allow_network: bool | None = None,
    include_diagrams: bool | None = None,
    allow_perf: bool | None = None,
    frontend_url: str | None = None,
    run_lighthouse: bool | None = None,
    load_urls: list[str] | None = None,
    run_load_test: bool | None = None,
    perf_requests: int | None = None,
    perf_concurrency: int | None = None,
    max_duration_seconds: int | None = None,
    run_benchmarks: bool | None = None,
    confirm_benchmarks: bool | None = None,
    lighthouse_no_sandbox: bool | None = None,
    allow_mocks: bool | None = None,
    allow_private_network: bool | None = None,
) -> dict[str, Any]:
    scan_started = time.perf_counter()
    config = load_config(repo, config_path)
    config["profile"] = profile or config.get("profile", "quick-static")
    if max_findings is not None:
        config["maxFindings"] = max_findings
    if allow_network is not None:
        config["allowNetwork"] = allow_network
    if allow_mocks is not None:
        config["allowMocks"] = allow_mocks
    if allow_private_network is not None:
        config["allowPrivateNetwork"] = allow_private_network
    if include_diagrams is not None:
        config.setdefault("report", {})["includeMermaidDiagrams"] = include_diagrams
    if allow_perf is not None:
        config["allowPerfTests"] = allow_perf
    if frontend_url:
        config.setdefault("frontend", {})["url"] = frontend_url
    if run_lighthouse is not None:
        config.setdefault("frontend", {})["runLighthouse"] = run_lighthouse
    if load_urls:
        config.setdefault("performance", {})["targets"] = load_urls
    if run_load_test is not None:
        config.setdefault("performance", {})["runLoadTests"] = run_load_test
    if perf_requests is not None:
        config.setdefault("performance", {})["requests"] = perf_requests
    if perf_concurrency is not None:
        config.setdefault("performance", {})["concurrency"] = perf_concurrency
    if max_duration_seconds is not None:
        config.setdefault("performance", {})["maxDurationSeconds"] = max_duration_seconds
    if run_benchmarks is not None:
        config.setdefault("performance", {})["runBenchmarks"] = run_benchmarks
    if confirm_benchmarks is not None:
        config.setdefault("performance", {})["confirmBenchmarks"] = confirm_benchmarks
    if lighthouse_no_sandbox is not None:
        config.setdefault("performance", {})["lighthouseNoSandbox"] = lighthouse_no_sandbox

    prime_repo_cache(repo, config)
    discovery = discover_repo(repo, config)
    findings: list[dict[str, Any]] = []
    dependency_result = {"inventory": [], "summary": {"totalDependencies": 0, "osvStatus": "not_run", "managers": []}}
    architecture_result = {
        "modules": [],
        "edges": [],
        "cycles": [],
        "services": [],
        "diagrams": {"moduleGraph": None, "serviceTopology": None},
        "summary": {"moduleCount": 0, "edgeCount": 0, "cycleCount": 0, "serviceCount": 0, "routeCount": 0},
        "findingIds": [],
    }
    performance_result = {
        "enabled": False,
        "skippedReason": "skipped because profile does not include performance",
        "frontend": {"probe": {"status": "skipped"}, "lighthouse": {"status": "skipped"}},
        "loadTests": [],
        "benchmarks": [],
        "summary": {"status": "skipped", "frontendMetrics": False, "loadTestCount": 0, "benchmarkCount": 0},
        "findingIds": [],
    }
    profile_name = config["profile"]

    if profile_name in {"quick-static", "complexity", "full"}:
        findings.extend(scan_complexity(repo, config))
    if profile_name in {"quick-static", "security", "full"}:
        dependency_result = scan_dependencies(repo, config)
        findings.extend(dependency_result["findings"])
        findings.extend(scan_secrets(repo, config))
        findings.extend(scan_static_security(repo, config))
    if profile_name in {"architecture", "full"}:
        architecture_result = map_architecture(repo, config)
        architecture_findings = architecture_result.pop("findings", [])
        architecture_result["findingIds"] = [finding["id"] for finding in architecture_findings]
        findings.extend(architecture_findings)
    if profile_name in {"performance", "full"}:
        performance_result = run_perf_checks(repo, config, discovery)
        performance_findings = performance_result.pop("findings", [])
        performance_result["findingIds"] = [finding["id"] for finding in performance_findings]
        findings.extend(performance_findings)

    findings = redact_findings_evidence(findings)
    source_redactions = {"externalSecrets": external_secret_redactions(findings)}
    findings = cap_findings(sort_findings(findings), config)
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    scan_duration_ms = round((time.perf_counter() - scan_started) * 1000, 2)
    summary = summarize_findings(findings)

    return {
        "schemaVersion": "1.0.0",
        "generatedAt": generated_at,
        "scanDurationMs": scan_duration_ms,
        "profile": config["profile"],
        "allowNetwork": config.get("allowNetwork", False),
        "repository": repo.resolve().as_posix(),
        "discovery": discovery,
        "dependencies": dependency_result["inventory"],
        "dependencySummary": dependency_result["summary"],
        "architecture": architecture_result,
        "performance": performance_result,
        "sourceRedactions": source_redactions,
        "findings": findings,
        "summary": summary,
    }


def absolute_without_resolving(path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def reject_symlinked_output_path(path: Path) -> None:
    for parent in [path.parent, *path.parent.parents]:
        if parent.exists() and parent.is_symlink():
            raise SystemExit(f"refusing to write output through symlinked directory: {parent}")
    if not path.exists():
        return
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"could not inspect output path: {path}: {error.strerror}") from None
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"refusing to overwrite unsafe output path: {path}")


def write_text(path: Path, content: str) -> None:
    path = absolute_without_resolving(path)
    reject_symlinked_output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temp_path: Path | None = None
    try:
        for _attempt in range(100):
            candidate = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}"
            try:
                descriptor = os.open(candidate, flags, 0o666)
                temp_path = candidate
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate a temporary output file")
    except OSError as error:
        raise SystemExit(f"could not write output file safely: {path}: {error.strerror}") from None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp_path, path)
    except OSError as error:
        if temp_path:
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise SystemExit(f"could not write output file safely: {path}: {error.strerror}") from None


def scan_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists() or not repo.is_dir():
        raise SystemExit(f"Repository path does not exist or is not a directory: {repo}")

    formats = args.format
    if formats is None:
        out_suffix = Path(args.out).suffix.lower() if args.out else ""
        formats = {"html", "json"} if out_suffix in {".html", ".htm"} else {"markdown", "json"}
    allow_network = None
    if args.offline:
        allow_network = False
    elif args.allow_network:
        allow_network = True

    include_diagrams = None
    if args.no_diagrams:
        include_diagrams = False
    elif args.include_diagrams:
        include_diagrams = True

    try:
        result = build_scan_result(
            repo=repo,
            profile=args.profile,
            config_path=absolute_without_resolving(Path(args.config)) if args.config else None,
            max_findings=args.max_findings,
            allow_network=allow_network,
            include_diagrams=include_diagrams,
            allow_perf=True if args.allow_perf else None,
            allow_mocks=True if args.allow_mocks else None,
            allow_private_network=True if args.allow_private_network else None,
            frontend_url=args.frontend_url,
            run_lighthouse=True if args.run_lighthouse else None,
            load_urls=args.load_url,
            run_load_test=True if args.run_load_test else None,
            perf_requests=args.perf_requests,
            perf_concurrency=args.perf_concurrency,
            max_duration_seconds=args.max_duration_seconds,
            run_benchmarks=True if args.run_benchmarks else None,
            confirm_benchmarks=True if args.confirm_benchmarks else None,
            lighthouse_no_sandbox=True if args.lighthouse_no_sandbox else None,
        )
    except ConfigError as error:
        raise SystemExit(str(error)) from None

    markdown = render_markdown(result) if "markdown" in formats else ""
    html = render_html(result) if "html" in formats else ""
    json_payload = json.dumps(result, indent=2, sort_keys=True)

    if "markdown" in formats:
        if args.out and Path(args.out).suffix.lower() not in {".html", ".htm"}:
            write_text(Path(args.out), markdown)
        elif args.out:
            write_text(Path(args.out).with_suffix(".md"), markdown)
        else:
            print(markdown)

    if "html" in formats:
        if args.out:
            html_out = Path(args.out)
            if html_out.suffix.lower() not in {".html", ".htm"}:
                html_out = html_out.with_suffix(".html")
            write_text(html_out, html)
        else:
            print(html)

    if "json" in formats:
        json_out = Path(args.json_out) if args.json_out else None
        if not json_out and args.out:
            json_out = Path(args.out).with_suffix(".json")
        if json_out:
            write_text(json_out, json_payload + "\n")
        else:
            print(json_payload)

    return 0


def fix_command(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists() or not repo.is_dir():
        raise SystemExit(f"Repository path does not exist or is not a directory: {repo}")

    try:
        result = remediate_finding(
            repo,
            args.finding,
            config_path=Path(args.config).resolve() if args.config else None,
            report_path=Path(args.from_report).resolve() if args.from_report else None,
            dry_run=args.dry_run,
            test_commands=args.test_command or [],
        )
    except ConfigError as error:
        raise SystemExit(str(error)) from None
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Status: {result['status']}")
        print(f"Finding: {result['findingId']}")
        if result.get("reason"):
            print(f"Reason: {result['reason']}")
        if result.get("changedFiles"):
            print("Changed files:")
            for path in result["changedFiles"]:
                print(f"- {path}")
        if result.get("diff"):
            print("\nDiff:")
            print(result["diff"])
        if result.get("verification"):
            print("Verification:")
            for item in result["verification"]:
                print(f"- {item['status']}: {item['command']}")
    return 0 if result["status"] in {"patched", "dry_run"} else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a repository and emit audit reports.")
    scan.add_argument("repo", nargs="?", default=".", help="Repository path to scan.")
    scan.add_argument("--profile", default="quick-static", choices=["quick-static", "complexity", "security", "architecture", "performance", "full"])
    scan.add_argument("--format", type=parse_formats, help="Comma-separated output formats: markdown,json,html")
    scan.add_argument("--out", help="Markdown output path.")
    scan.add_argument("--json-out", help="JSON output path.")
    scan.add_argument("--config", help="Path to .codebase-auditor.json.")
    scan.add_argument("--max-findings", type=parse_max_findings, help="Maximum findings to include, or 'all'.")
    network = scan.add_mutually_exclusive_group()
    network.add_argument("--allow-network", action="store_true", help="Allow online vulnerability lookup and enabled online adapters.")
    network.add_argument("--offline", action="store_true", help="Disable online vulnerability lookup even if config allows it.")
    diagrams = scan.add_mutually_exclusive_group()
    diagrams.add_argument("--include-diagrams", action="store_true", help="Include Mermaid diagrams in Markdown and JSON output.")
    diagrams.add_argument("--no-diagrams", action="store_true", help="Disable Mermaid diagrams even if config enables them.")
    scan.add_argument("--allow-perf", action="store_true", help="Allow runtime performance checks.")
    scan.add_argument("--allow-mocks", action="store_true", help="Honor CODEX_AUDITOR_* mock response files and mock paths from config.")
    scan.add_argument("--allow-private-network", action="store_true", help="Allow runtime probes against loopback, private, reserved, and link-local hosts.")
    scan.add_argument("--frontend-url", help="Frontend URL to probe or pass to Lighthouse.")
    scan.add_argument("--run-lighthouse", action="store_true", help="Run Lighthouse when available or when a mock response is configured.")
    scan.add_argument("--load-url", action="append", help="URL to load test. Can be repeated.")
    scan.add_argument("--run-load-test", action="store_true", help="Run configured HTTP load tests.")
    scan.add_argument("--perf-requests", type=int, help="Total built-in load-test requests.")
    scan.add_argument("--perf-concurrency", type=int, help="Built-in load-test concurrency.")
    scan.add_argument("--max-duration-seconds", type=int, help="Maximum seconds for runtime adapters.")
    scan.add_argument("--run-benchmarks", action="store_true", help="Time discovered benchmark/test commands.")
    scan.add_argument("--confirm-benchmarks", action="store_true", help="Confirm benchmark/test command execution from config or repository discovery.")
    scan.add_argument("--lighthouse-no-sandbox", action="store_true", help="Pass --no-sandbox to Chrome for Lighthouse in trusted CI environments.")
    scan.set_defaults(func=scan_command)

    fix = subparsers.add_parser("fix", help="Apply an explicit supported remediation for one finding.")
    fix.add_argument("repo", nargs="?", default=".", help="Repository path to patch.")
    fix.add_argument("--finding", required=True, help="Finding ID to remediate.")
    fix.add_argument("--config", help="Path to .codebase-auditor.json.")
    fix.add_argument("--from-report", help="Read the finding from an existing JSON audit report.")
    fix.add_argument("--dry-run", action="store_true", help="Preview the patch without editing files.")
    fix.add_argument("--json", action="store_true", help="Emit JSON result.")
    fix.add_argument("--test-command", action="append", help="Additional verification command to run after patching.")
    fix.set_defaults(func=fix_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    require_supported_python()
    argv = list(sys.argv[1:] if argv is None else argv)
    reject_duplicate_flags(argv, repeatable={"--load-url", "--test-command"})
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
