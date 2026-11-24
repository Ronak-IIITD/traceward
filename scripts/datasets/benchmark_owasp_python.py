"""Score TraceWard's Python SQL rule on the pinned OWASP BenchmarkPython archive."""

import argparse
import json
from collections import Counter
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path

from traceward import __version__
from traceward.registry import PYTHON_SQL
from traceward.scanner import scan_snippet

from scripts.datasets.owasp_python_source import (
    ARCHIVE_SHA256,
    ARCHIVE_URL,
    REVISION,
    BenchmarkCase,
    load_cases,
)


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate(cases: Sequence[BenchmarkCase]) -> tuple[dict[str, object], int]:
    confusion = {
        "true_positive": 0,
        "false_negative": 0,
        "false_positive": 0,
        "true_negative": 0,
    }
    failed = {"positive": 0, "negative": 0}
    warned = {"positive": 0, "negative": 0}
    diagnostic_counts: Counter[str] = Counter()
    for case in cases:
        result = scan_snippet(case.source, language="python")
        label = "positive" if case.expected_finding else "negative"
        diagnostic_counts.update({diagnostic.code for diagnostic in result.diagnostics})
        if result.summary.errors or result.summary.files_analyzed != 1:
            failed[label] += 1
            continue
        if result.diagnostics:
            warned[label] += 1
        reported = any(
            finding.rule_id == PYTHON_SQL.id and PYTHON_SQL.cwe in finding.cwe
            for finding in result.findings
        )
        outcome = "true" if reported == case.expected_finding else "false"
        prediction = "positive" if reported else "negative"
        confusion[f"{outcome}_{prediction}"] += 1

    tp, fn = confusion["true_positive"], confusion["false_negative"]
    fp, tn = confusion["false_positive"], confusion["true_negative"]
    positives = sum(case.expected_finding for case in cases)
    failure_count = sum(failed.values())
    return (
        {
            "schema_version": 1,
            "benchmark": {
                "name": "OWASP BenchmarkPython",
                "version": "0.1",
                "revision": REVISION,
                "archive_url": ARCHIVE_URL,
                "archive_sha256": ARCHIVE_SHA256,
                "cwe": PYTHON_SQL.cwe,
                "synthetic": True,
            },
            "scanner": {
                "version": __version__,
                "rule_id": PYTHON_SQL.id,
                "rule_version": PYTHON_SQL.version,
                "tree_sitter": version("tree-sitter"),
                "tree_sitter_python": version("tree-sitter-python"),
            },
            "cases": {
                "total": len(cases),
                "labeled_positive": positives,
                "labeled_negative": len(cases) - positives,
                "scored": len(cases) - failure_count,
            },
            "analysis": {
                "scored_with_diagnostics_by_label": warned,
                "scored_without_diagnostics": len(cases) - failure_count - sum(warned.values()),
                "failed_by_label": failed,
                "cases_by_diagnostic_code": dict(sorted(diagnostic_counts.items())),
            },
            "confusion_matrix": confusion,
            "metrics": {
                "precision": ratio(tp, tp + fp),
                "recall": ratio(tp, tp + fn),
                "false_positive_rate": ratio(fp, fp + tn),
            },
        },
        2 if failure_count else 0,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True, help="Checksum-pinned OWASP ZIP")
    args = parser.parse_args()
    try:
        cases = load_cases(args.archive)
    except (OSError, ValueError) as error:
        parser.exit(2, f"Cannot load OWASP benchmark: {error}\n")
    report, status = evaluate(cases)
    print(json.dumps(report, indent=2))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
