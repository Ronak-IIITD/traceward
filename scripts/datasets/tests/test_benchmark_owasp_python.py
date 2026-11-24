"""Exercise file-level benchmark scoring without fetching external source."""

import json
from pathlib import Path

import pytest

from scripts.datasets import benchmark_owasp_python
from scripts.datasets.owasp_python_source import BenchmarkCase

SETUP = 'import sqlite3\ndb = sqlite3.connect(":memory:")\n'
FINDING = SETUP + 'db.execute("SELECT " + input())\n'
BOUND = SETUP + 'name = input()\ndb.execute("SELECT ?", (name,))\n'
UNSUPPORTED = "if unknown:\n    pass\n"


def test_scoring_keeps_diagnostics_separate_from_predictions() -> None:
    report, status = benchmark_owasp_python.evaluate(
        [
            BenchmarkCase("a", True, FINDING + UNSUPPORTED),
            BenchmarkCase("b", False, FINDING + FINDING.removeprefix(SETUP)),
            BenchmarkCase("c", True, UNSUPPORTED),
            BenchmarkCase("d", False, BOUND),
        ]
    )
    assert status == 0
    assert report["confusion_matrix"] == {
        "true_positive": 1,
        "false_negative": 1,
        "false_positive": 1,
        "true_negative": 1,
    }
    assert report["analysis"] == {
        "scored_with_diagnostics_by_label": {"positive": 2, "negative": 0},
        "scored_without_diagnostics": 2,
        "failed_by_label": {"positive": 0, "negative": 0},
        "cases_by_diagnostic_code": {"UNSUPPORTED_FLOW": 2},
    }
    assert report["metrics"] == {"precision": 0.5, "recall": 0.5, "false_positive_rate": 0.5}


def test_parse_failure_is_unscored_and_returns_error() -> None:
    report, status = benchmark_owasp_python.evaluate(
        [BenchmarkCase("a", False, "def broken(:\n"), BenchmarkCase("b", True, UNSUPPORTED)]
    )
    assert status == 2
    assert report["cases"] == {
        "total": 2,
        "labeled_positive": 1,
        "labeled_negative": 1,
        "scored": 1,
    }
    assert report["confusion_matrix"] == {
        "true_positive": 0,
        "false_negative": 1,
        "false_positive": 0,
        "true_negative": 0,
    }
    assert report["analysis"] == {
        "scored_with_diagnostics_by_label": {"positive": 1, "negative": 0},
        "scored_without_diagnostics": 0,
        "failed_by_label": {"positive": 0, "negative": 1},
        "cases_by_diagnostic_code": {"PARSE_ERROR": 1, "UNSUPPORTED_FLOW": 1},
    }
    assert report["metrics"] == {"precision": None, "recall": 0.0, "false_positive_rate": None}


def test_cli_reports_bad_archive_on_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing.zip"
    monkeypatch.setattr("sys.argv", ["benchmark_owasp_python", "--archive", str(missing)])
    with pytest.raises(SystemExit) as failure:
        benchmark_owasp_python.main()
    assert failure.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "Cannot load OWASP benchmark" in output.err


def test_cli_outputs_only_aggregate_results_and_does_not_execute_cases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    marker = tmp_path / "benchmark-executed"
    sample = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    monkeypatch.setattr(
        benchmark_owasp_python, "load_cases", lambda path: [BenchmarkCase("case-a", False, sample)]
    )
    monkeypatch.setattr("sys.argv", ["benchmark_owasp_python", "--archive", "pinned.zip"])
    assert benchmark_owasp_python.main() == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["cases"]["scored"] == 1
    assert output.err == "" and "case-a" not in output.out and str(marker) not in output.out
    assert not marker.exists()
