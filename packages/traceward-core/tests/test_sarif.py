import json
import shutil
import subprocess
from pathlib import Path

import pytest
from traceward import __version__
from traceward.scanner import scan_path

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/java"


def scan_sarif(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["traceward", "scan", str(path), "--format", "sarif", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_export_keeps_rule_fingerprint_and_flow(tmp_path: Path) -> None:
    name = "nested/é #100%?.java"
    source = tmp_path / name
    source.parent.mkdir()
    shutil.copyfile(FIXTURES / "Vulnerable.java", source)
    result = scan_path(tmp_path)
    run = scan_sarif(tmp_path)
    assert run.returncode == 1
    assert run.stderr == ""
    report = json.loads(run.stdout)
    assert report["version"] == "2.1.0"
    (analysis,) = report["runs"]
    driver = analysis["tool"]["driver"]
    assert driver["name"] == "TraceWard"
    assert driver["semanticVersion"] == __version__
    (rule,) = driver["rules"]
    assert "CWE-89" in rule["properties"]["tags"]
    (finding,) = analysis["results"]
    (original,) = result.findings
    assert finding["ruleId"] == rule["id"] == original.rule_id
    assert finding["ruleIndex"] == 0
    assert finding["partialFingerprints"]["tracewardFingerprint/v1"] == original.fingerprint
    assert finding["level"] == "warning"
    assert finding["properties"]["severity"] == "high"
    assert finding["properties"]["evidenceLevel"] == "heuristic_candidate"
    assert finding["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "nested/%C3%A9%20%23100%25%3F.java",
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {"startLine": 8, "endLine": 8},
            }
        }
    ]
    flow = finding["codeFlows"][0]["threadFlows"][0]["locations"]
    assert [item["kinds"][0] for item in flow] == [step.kind for step in original.evidence.flow]
    assert [item["location"]["physicalLocation"]["region"]["startLine"] for item in flow] == [
        step.location.start_line for step in original.evidence.flow
    ]
    assert "snippet" not in run.stdout
    assert str(tmp_path) not in run.stdout


@pytest.mark.parametrize(
    ("file", "args", "expected"),
    [
        ("Safe.java", (), 0),
        ("Safe.java", ("--fail-on-partial",), 3),
        ("Vulnerable.java", ("--fail-on", "none"), 0),
    ],
)
def test_report_preserves_exit_policy(
    file: str, args: tuple[str, ...], expected: int, tmp_path: Path
) -> None:
    output = tmp_path / "traceward.sarif"
    run = scan_sarif(FIXTURES / file, "--output", str(output), *args)
    assert run.returncode == expected
    assert run.stdout == ""
    (analysis,) = json.loads(output.read_text())["runs"]
    (invocation,) = analysis["invocations"]
    assert invocation["executionSuccessful"] is True
    assert invocation["exitCode"] == expected
    assert analysis["properties"]["coverage"]["partial"] is True
    assert len(analysis["results"]) == (1 if file == "Vulnerable.java" else 0)


def test_parse_failure_produces_tool_notification(tmp_path: Path) -> None:
    source = tmp_path / "Broken.java"
    source.write_text("class Broken { void x( {", encoding="utf-8")
    run = scan_sarif(source)
    assert run.returncode == 2
    (analysis,) = json.loads(run.stdout)["runs"]
    (invocation,) = analysis["invocations"]
    assert not invocation["executionSuccessful"]
    assert invocation["exitCode"] == 2
    assert analysis["results"] == []
    (error,) = invocation["toolExecutionNotifications"]
    assert error["level"] == "error"
    assert "PARSE_ERROR" in error["message"]["text"]
    assert error["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == source.name


def test_relative_reports_match_across_checkout_roots(tmp_path: Path) -> None:
    first_root = tmp_path / "one"
    second_root = tmp_path / "two"
    shutil.copytree(FIXTURES, first_root)
    shutil.copytree(FIXTURES, second_root)
    first, second = scan_sarif(first_root), scan_sarif(second_root)
    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout


def test_missing_path_is_an_error_without_a_source_location(tmp_path: Path) -> None:
    run = scan_sarif(tmp_path / "missing.java")
    assert run.returncode == 2
    notification = json.loads(run.stdout)["runs"][0]["invocations"][0][
        "toolExecutionNotifications"
    ][0]
    assert "INVALID_PATH" in notification["message"]["text"]
    assert "locations" not in notification
