from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any

from .discover_repo import SOURCE_EXTENSIONS, iter_repo_files, read_text, rel
from .source_sanitize import sanitize_code_lines


LOOP_RE = re.compile(r"\b(for|while)\b|\.forEach\s*\(")
QUERY_RE = re.compile(
    r"\baxios(?:\.[A-Za-z_]\w*)?\s*\(|"
    r"(?:\b|\.)(?:fetch|request|execute|query|findMany|findUnique|find_one|findAll|select)\s*\(|"
    r"\b(SELECT|INSERT|UPDATE|DELETE)\b",
    re.IGNORECASE,
)
SORT_RE = re.compile(r"\.sort\s*\(|\bsorted\s*\(")
MAP_FIND_RE = re.compile(r"\.(map|forEach)\s*\([^;\n]*(\.find\s*\(|\.filter\s*\()", re.DOTALL)
RENDER_CHAIN_RE = re.compile(r"\.(filter|map|sort)\s*\([^;\n]*\.(filter|map|sort)\s*\(", re.DOTALL)


def finding_id(path: str, line: int, tag: str) -> str:
    digest = hashlib.sha256(f"{path}:{line}:{tag}".encode("utf-8")).hexdigest()[:8]
    return f"complexity-{tag}-{digest}"


def make_finding(
    *,
    path: str,
    line: int,
    tag: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: str,
    performance: str,
    recommendation: str,
    effort: str = "small",
    roi: str = "medium",
    symbol: str | None = None,
    fix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finding = {
        "id": finding_id(path, line, tag),
        "category": "complexity",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "location": {
            "path": path,
            "line": line,
            "symbol": symbol,
        },
        "evidence": evidence.strip(),
        "impact": {
            "performance": performance,
            "security": None,
            "architecture": None,
        },
        "recommendation": recommendation,
        "estimatedEffort": effort,
        "estimatedRoi": roi,
        "verification": ["unit test", "benchmark if input size is large"],
        "source": "scan_complexity",
    }
    if fix:
        finding["fix"] = fix
    return finding


class PythonComplexityVisitor(ast.NodeVisitor):
    def __init__(self, repo: Path, path: Path, source_text: str) -> None:
        self.repo = repo
        self.path = path
        self.rel_path = rel(path, repo)
        self.source_text = source_text
        self.findings: list[dict[str, Any]] = []
        self.loop_stack: list[ast.AST] = []

    def visit_For(self, node: ast.For) -> Any:
        self.visit(node.target)
        self.visit(node.iter)
        self._enter_loop(node)
        for statement in node.body:
            self.visit(statement)
        self.loop_stack.pop()
        for statement in node.orelse:
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.visit(node.target)
        self.visit(node.iter)
        self._enter_loop(node)
        for statement in node.body:
            self.visit(statement)
        self.loop_stack.pop()
        for statement in node.orelse:
            self.visit(statement)

    def visit_While(self, node: ast.While) -> Any:
        self._enter_loop(node)
        self.generic_visit(node)
        self.loop_stack.pop()

    def visit_Call(self, node: ast.Call) -> Any:
        if self.loop_stack:
            name = call_name(node)
            if name in {"sorted", "sort"} or name.endswith(".sort"):
                self.findings.append(
                    make_finding(
                        path=self.rel_path,
                        line=getattr(node, "lineno", 1),
                        tag="py-sort-loop",
                        severity="medium",
                        confidence="high",
                        title="Sort happens inside a loop",
                        evidence=f"{name}(...) inside loop",
                        performance="Repeated O(n log n) work inside an outer loop",
                        recommendation="Move sorting outside the loop when the sorted input is loop-invariant.",
                        roi="medium",
                    )
                )
            elif looks_like_query_call(name):
                self.findings.append(
                    make_finding(
                        path=self.rel_path,
                        line=getattr(node, "lineno", 1),
                        tag="py-query-loop",
                        severity="high",
                        confidence="medium",
                        title="I/O or query-like call happens inside a loop",
                        evidence=f"{name}(...) inside loop",
                        performance="Potential N+1 query, API fan-out, or serialized I/O",
                        recommendation="Batch, prefetch, or cache the lookup while preserving ordering and error semantics.",
                        roi="high",
                    )
                )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> Any:
        if self.loop_stack and len(node.ops) == 1 and len(node.comparators) == 1:
            op = node.ops[0]
            comparator = node.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)) and safe_string_literal_sequence(comparator):
                literal_source = ast.get_source_segment(self.source_text, comparator)
                loop_node = self.loop_stack[-1]
                if literal_source and can_rewrite_literal(comparator, literal_source, self.source_text):
                    variable_name = f"_auditor_membership_set_{getattr(node, 'lineno', 1)}"
                    set_source = "{" + literal_source[1:-1].strip().rstrip(",") + "}"
                    self.findings.append(
                        make_finding(
                            path=self.rel_path,
                            line=getattr(node, "lineno", 1),
                            tag="py-membership-literal",
                            severity="low",
                            confidence="high",
                            title="Repeated membership check over literal sequence inside loop",
                            evidence=literal_source,
                            performance="Repeated O(m) literal sequence membership check inside an outer loop",
                            recommendation="Hoist the literal strings to a set before the loop for average O(1) membership checks.",
                            roi="medium",
                            fix={
                                "mechanical": True,
                                "kind": "python-membership-literal-set-hoist",
                                "loopLine": getattr(loop_node, "lineno", None),
                                "literalLine": getattr(comparator, "lineno", None),
                                "literalColumnStart": getattr(comparator, "col_offset", None),
                                "literalColumnEnd": getattr(comparator, "end_col_offset", None),
                                "literalSource": literal_source,
                                "setSource": set_source,
                                "variableName": variable_name,
                            },
                        )
                    )
        self.generic_visit(node)

    def _enter_loop(self, node: ast.AST) -> None:
        if self.loop_stack:
            self.findings.append(
                make_finding(
                    path=self.rel_path,
                    line=getattr(node, "lineno", 1),
                    tag="py-nested-loop",
                    severity="medium",
                    confidence="medium",
                    title="Nested loop may scale quadratically",
                    evidence="Loop nested inside another loop",
                    performance="Potential O(n*m) or O(n^2) path",
                    recommendation="Check input sizes; if this is a lookup join, pre-index one side with a dict or set.",
                    roi="high",
                )
            )
        self.loop_stack.append(node)


def call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = call_attr_base(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return "<call>"


def call_attr_base(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_attr_base(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def looks_like_query_call(name: str) -> bool:
    lowered = name.lower()
    parts = lowered.split(".")
    method = parts[-1]
    if method in {"search", "match", "finditer", "findall"} and any(part.endswith("_re") or part in {"re", "regex", "pattern"} for part in parts[:-1]):
        return False
    strong_tokens = {
        "query",
        "execute",
        "fetch",
        "request",
        "select",
        "findmany",
        "findunique",
        "findone",
        "findall",
        "find_all",
    }
    compact = method if len(parts) > 1 else lowered.replace(".", "_")
    token_list = [token for token in re.split(r"[^a-z0-9]+", compact) if token]
    tokens = set(token_list)
    joined = "".join(token_list)
    if tokens & strong_tokens or joined in {token.replace("_", "") for token in strong_tokens}:
        return True
    if lowered.endswith(".get"):
        return any(owner in lowered for owner in ["http", "client", "session", "requests", "api", "db"])
    return False


def safe_string_literal_sequence(node: ast.AST) -> bool:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return False
    values = []
    for element in node.elts:
        if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
            return False
        values.append(element.value)
    return len(values) >= 4 and len(values) == len(set(values))


def can_rewrite_literal(node: ast.AST, literal_source: str, source_text: str) -> bool:
    if getattr(node, "lineno", None) != getattr(node, "end_lineno", None):
        return False
    stripped = literal_source.strip()
    if not ((stripped.startswith("[") and stripped.endswith("]")) or (stripped.startswith("(") and stripped.endswith(")"))):
        return False
    variable_name = f"_auditor_membership_set_{getattr(node, 'lineno', 1)}"
    return variable_name not in source_text


def scan_python(repo: Path, path: Path) -> list[dict[str, Any]]:
    text = read_text(path)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    visitor = PythonComplexityVisitor(repo, path, text)
    visitor.visit(tree)
    return visitor.findings


def brace_delta(line: str) -> int:
    return line.count("{") - line.count("}")


def compact_window(lines: list[str], start: int, width: int = 5) -> str:
    return " ".join(line.strip() for line in lines[start : min(len(lines), start + width)])


def scan_text(repo: Path, path: Path) -> list[dict[str, Any]]:
    text = read_text(path)
    lines = text.splitlines()
    code_lines = sanitize_code_lines(text)
    rel_path = rel(path, repo)
    findings: list[dict[str, Any]] = []
    active_loop_depths: list[int] = []
    depth = 0

    for index, line in enumerate(code_lines):
        line_no = index + 1
        stripped = line.strip()
        evidence_line = lines[index].strip() if index < len(lines) else stripped
        active_loop_depths = [loop_depth for loop_depth in active_loop_depths if loop_depth <= depth]
        in_loop = bool(active_loop_depths)

        if LOOP_RE.search(stripped):
            if in_loop:
                findings.append(
                    make_finding(
                        path=rel_path,
                        line=line_no,
                        tag="nested-loop",
                        severity="medium",
                        confidence="low",
                        title="Nested loop candidate",
                        evidence=evidence_line[:180],
                        performance="Potential O(n*m) or O(n^2) path",
                        recommendation="Check cardinality; if this is a repeated lookup, pre-index one collection.",
                        roi="high",
                    )
                )
            active_loop_depths.append(depth + max(1, line.count("{")))

        if in_loop and SORT_RE.search(stripped):
            findings.append(
                make_finding(
                    path=rel_path,
                    line=line_no,
                    tag="sort-loop",
                    severity="medium",
                    confidence="medium",
                    title="Sort happens inside a loop",
                    evidence=evidence_line[:180],
                    performance="Repeated O(n log n) work inside an outer loop",
                    recommendation="Move sorting outside the loop when the sorted input is loop-invariant.",
                    roi="medium",
                )
            )

        if in_loop and QUERY_RE.search(stripped):
            findings.append(
                make_finding(
                    path=rel_path,
                    line=line_no,
                    tag="io-loop",
                    severity="high",
                    confidence="medium",
                    title="I/O or query-like call happens inside a loop",
                    evidence=evidence_line[:180],
                    performance="Potential N+1 query, API fan-out, or serialized I/O",
                    recommendation="Batch, prefetch, or cache the operation while preserving ordering and errors.",
                    roi="high",
                )
            )

        window = compact_window(code_lines, index)
        evidence_window = compact_window(lines, index)
        if (".map" in stripped or ".forEach" in stripped) and MAP_FIND_RE.search(window):
            findings.append(
                make_finding(
                    path=rel_path,
                    line=line_no,
                    tag="map-find",
                    severity="high",
                    confidence="medium",
                    title="Repeated linear lookup inside collection transform",
                    evidence=evidence_window[:220],
                    performance="Likely O(n*m) lookup pattern",
                    recommendation="Build a Map or dictionary once, then perform O(1) lookups inside the transform.",
                    roi="high",
                )
            )

        if path.suffix.lower() in {".jsx", ".tsx"} and RENDER_CHAIN_RE.search(window):
            findings.append(
                make_finding(
                    path=rel_path,
                    line=line_no,
                    tag="render-chain",
                    severity="medium",
                    confidence="low",
                    title="Chained collection work appears in a render path",
                    evidence=evidence_window[:220],
                    performance="Potential repeated render-time allocation and traversal",
                    recommendation="Measure render frequency; memoize or precompute derived data if this path is hot.",
                    roi="medium",
                )
            )

        depth += brace_delta(line)
        if depth < 0:
            depth = 0

    return findings


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        key = finding["id"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def scan_complexity(repo: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in iter_repo_files(repo, config):
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if path.suffix.lower() == ".py":
            findings.extend(scan_python(repo, path))
        findings.extend(scan_text(repo, path))

    return dedupe_findings(findings)
