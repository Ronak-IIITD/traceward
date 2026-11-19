"""CLI shares the exact result contract with the Python library."""

import argparse
import json
import sys
from importlib.metadata import version
from pathlib import Path

from traceward import __version__
from traceward.models import Detector, ScanResult
from traceward.scanner import scan_path


def exit_code(result: ScanResult, fail_on: str, confidence: str, strict: bool) -> int:
    if result.summary.errors:
        return 2
    if strict and result.coverage.partial:
        return 3
    # Current registry only emits high severity / medium confidence candidates.
    if result.findings and fail_on not in {"none", "critical"} and confidence != "high":
        return 1
    return 0


def render_text(result: ScanResult) -> str:
    lines = [
        f"TraceWard {__version__} · experimental Java CWE-89",
        "PARTIAL COVERAGE — no supported findings does not certify security.",
    ]
    for finding in result.findings:
        loc = finding.location
        lines.extend(
            [
                f"{loc.path}:{loc.start_line}:{loc.start_column}: HIGH CWE-89 {finding.title}",
                f"  {finding.rule_id} · {finding.confidence} confidence · {finding.evidence_level}",
            ]
        )
        for step in finding.evidence.flow:
            lines.append(f"  {step.kind}: line {step.location.start_line} ({step.symbol})")
        lines.append(f"  {finding.guidance}")
    for diagnostic in result.diagnostics:
        lines.append(f"{diagnostic.level.upper()} {diagnostic.code}: {diagnostic.message}")
    lines.append(
        f"{result.summary.files_analyzed}/{result.summary.files_discovered} files analyzed; "
        f"{len(result.findings)} findings; {result.summary.errors} errors. ML disabled."
    )
    lines.extend(result.coverage.limitations)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="TraceWard experimental static Java scanner")
    parser.add_argument("--version", action="version", version=f"TraceWard {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("path", type=Path)
    scan.add_argument("--language", choices=["java"], default="java")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--output", type=Path)
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high"
    )
    scan.add_argument("--min-confidence", choices=["high", "medium", "low"], default="medium")
    scan.add_argument("--fail-on-partial", action="store_true")
    rules = commands.add_parser("rules")
    rules.add_argument("action", nargs="?", choices=["list"], default="list")
    rules.add_argument("--language", choices=["java"], default="java")
    commands.add_parser("doctor")
    args = parser.parse_args()
    if args.command == "doctor":
        print(f"TraceWard {__version__}; Python {sys.version.split()[0]}")
        for package in ["tree-sitter", "tree-sitter-java", "pydantic"]:
            print(f"{package}: {version(package)}")
        print("Java parser available. ML disabled: no validated model artifact installed.")
        return 0
    if args.command == "rules":
        print(json.dumps(Detector().model_dump(), indent=2))
        return 0
    result = scan_path(args.path, tuple(args.exclude))
    output = (
        result.model_dump_json(indent=2) + "\n" if args.format == "json" else render_text(result)
    )
    if args.output:
        try:
            args.output.write_text(output, encoding="utf-8")
        except OSError:
            print("Cannot write report output.", file=sys.stderr)
            return 2
    else:
        print(output, end="")
    return exit_code(result, args.fail_on, args.min_confidence, args.fail_on_partial)


if __name__ == "__main__":
    raise SystemExit(main())
