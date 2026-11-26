"""Regression checks for installed CLI scans over a mixed-language project."""

import json
import subprocess
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote

import pytest
from traceward.models import ScanResult

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


class Pair(NamedTuple):
    candidate: str
    bound: str
    directory: str
    rule: str
    source_line: int
    sink_line: int

    @property
    def path(self) -> str:
        return f"{self.directory}/{Path(self.candidate).name}"


PAIRS = (
    Pair(
        "java/Vulnerable.java",
        "java/Safe.java",
        "service/入口 #1",
        "java.sql.concatenated-untrusted-input",
        6,
        8,
    ),
    Pair(
        "python/concatenated.py",
        "python/parameterized.py",
        "tools/sqlite",
        "python.sqlite.concatenated-input",
        6,
        8,
    ),
    Pair(
        "flask-sqlite/concatenated.py",
        "flask-sqlite/parameterized.py",
        "service/routes",
        "python.sqlite.concatenated-input",
        10,
        13,
    ),
    Pair(
        "javascript/concatenated.js",
        "javascript/parameterized.js",
        "tools/js",
        "javascript.sqlite.concatenated-argv",
        4,
        6,
    ),
    Pair(
        "typescript/concatenated.ts",
        "typescript/parameterized.ts",
        "tools/ts",
        "typescript.sqlite.concatenated-argv",
        4,
        6,
    ),
)


def write_source(root: Path, path: str, content: bytes) -> None:
    source = root / path
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(content)


def populate_project(root: Path, *, reverse: bool = False) -> None:
    files = {"README.md": b"# Mixed-language regression project\n"}
    for pair in PAIRS:
        candidate = (FIXTURES / pair.candidate).read_bytes()
        bound = (FIXTURES / pair.bound).read_bytes()
        prefix = b"# " if pair.candidate.endswith(".py") else b"// "
        # Include the same source, SQL and sink spellings as a comment on the safe path.
        decoy = b"\n".join(prefix + line for line in candidate.splitlines())
        files[pair.path] = candidate
        files[f"{pair.directory}/{Path(pair.bound).name}"] = bound + b"\n" + decoy + b"\n"
    candidate = (FIXTURES / "javascript/concatenated.js").read_bytes()
    for directory in (".git", "node_modules/db", "vendor/tools", "build", "generated"):
        files[f"{directory}/excluded.js"] = candidate
    for name in sorted(files, reverse=reverse):
        write_source(root, name, files[name])


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    populate_project(root)
    return root


def scan_project(root: Path, output_format: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "traceward",
            "scan",
            root.name,
            "--exclude",
            "generated",
            "--format",
            output_format,
            *args,
        ],
        cwd=root.parent,
        capture_output=True,
        text=True,
        check=False,
    )


def test_project_golden_findings_and_sarif_parity(project: Path) -> None:
    outside = project.parent / "outside.java"
    outside.write_bytes((FIXTURES / "java/Vulnerable.java").read_bytes())
    (project / "linked.java").symlink_to(outside)

    json_run = scan_project(project, "json")
    sarif_run = scan_project(project, "sarif")
    assert json_run.returncode == sarif_run.returncode == 1
    assert json_run.stderr == sarif_run.stderr == ""
    result = ScanResult.model_validate_json(json_run.stdout)
    assert result.source.kind == "directory"
    assert result.summary.model_dump() == {
        "files_discovered": 10,
        "files_analyzed": 10,
        "findings": 5,
        "errors": 0,
    }
    assert result.coverage.partial
    assert result.coverage.languages_detected == ["java", "javascript", "python", "typescript"]
    assert result.coverage.supported_checks == ["CWE-89"]
    assert any(diagnostic.code == "SYMLINK_SKIPPED" for diagnostic in result.diagnostics)

    (report,) = json.loads(sarif_run.stdout)["runs"]
    assert report["properties"]["coverage"] == result.coverage.model_dump()
    assert report["properties"]["summary"] == result.summary.model_dump()
    rules = report["tool"]["driver"]["rules"]
    exported = {r["partialFingerprints"]["tracewardFingerprint/v1"]: r for r in report["results"]}
    findings = {finding.location.path: finding for finding in result.findings}
    assert len(exported) == len(report["results"]) == len(findings) == len(PAIRS)
    assert set(findings) == {pair.path for pair in PAIRS}
    for pair in PAIRS:
        finding = findings[pair.path]
        assert finding.rule_id == pair.rule and finding.cwe == ["CWE-89"]
        assert finding.evidence_level == "heuristic_candidate"
        assert finding.evidence.source.start_line == pair.source_line
        assert finding.evidence.sink.start_line == pair.sink_line
        assert all(step.location.path == pair.path for step in finding.evidence.flow)

        sarif = exported[finding.fingerprint]
        assert sarif["ruleId"] == rules[sarif["ruleIndex"]]["id"] == pair.rule
        physical = sarif["locations"][0]["physicalLocation"]
        assert unquote(physical["artifactLocation"]["uri"]) == pair.path
        assert physical["region"]["startLine"] == pair.sink_line
        flow = sarif["codeFlows"][0]["threadFlows"][0]["locations"]
        assert [
            (node["kinds"][0], node["location"]["physicalLocation"]["region"]["startLine"])
            for node in flow
        ] == [(step.kind, step.location.start_line) for step in finding.evidence.flow]
    assert str(project.parent) not in json_run.stdout + sarif_run.stdout


def test_project_sarif_reproducible_across_checkouts(project: Path) -> None:
    other = project.parent / "another checkout"
    populate_project(other, reverse=True)
    first, second = (scan_project(root, "sarif") for root in (project, other))
    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout


@pytest.mark.parametrize(
    ("suffix", "content", "diagnostic"),
    [
        ("java", b"class Broken { void f( {", "PARSE_ERROR"),
        ("py", b"def broken(:\n", "PARSE_ERROR"),
        ("mjs", b"const missing =", "PARSE_ERROR"),
        ("mts", b"const missing: string =", "PARSE_ERROR"),
        ("py", b"# invalid UTF-8: \xff", "INVALID_ENCODING"),
        ("js", b"// binary content\0", "BINARY_INPUT"),
    ],
)
def test_project_errors_preserve_findings_and_override_exit_policy(
    project: Path, suffix: str, content: bytes, diagnostic: str
) -> None:
    path = f"broken/input.{suffix}"
    write_source(project, path, content)

    run = scan_project(project, "sarif", "--fail-on", "none", "--fail-on-partial")
    assert run.returncode == 2
    (report,) = json.loads(run.stdout)["runs"]
    assert report["properties"]["summary"] == {
        "files_discovered": 11,
        "files_analyzed": 10,
        "findings": 5,
        "errors": 1,
    }
    assert len(report["results"]) == 5
    (invocation,) = report["invocations"]
    assert not invocation["executionSuccessful"] and invocation["exitCode"] == 2
    errors = [item for item in invocation["toolExecutionNotifications"] if item["level"] == "error"]
    (error,) = errors
    assert diagnostic in error["message"]["text"]
    if diagnostic == "PARSE_ERROR":
        physical = error["locations"][0]["physicalLocation"]
        assert unquote(physical["artifactLocation"]["uri"]) == path
    else:
        assert path in error["message"]["text"]
