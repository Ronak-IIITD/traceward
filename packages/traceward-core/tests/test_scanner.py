import json
import os
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from traceward.cli import exit_code
from traceward.java import JavaAnalysis
from traceward.models import ScanResult
from traceward.scanner import MAX_FILE_BYTES, scan_path, scan_snippet

ROOT = Path(__file__).resolve().parents[3]
PARAMS = "HttpServletRequest request, Statement statement, Connection connection"


def snippet(body: str, params: str = PARAMS) -> str:
    return f"class Demo {{ void find({params}) throws Exception {{ {body} }} }}"


@pytest.mark.parametrize(
    "body",
    [
        'statement.executeQuery("SELECT " + request.getParameter("id"));',
        'String id=request.getParameter("id"); String q="SELECT "+id; statement.execute(q);',
        'String id=request.getHeader("X-Id"); String q="SELECT "; q+=id; statement.addBatch(q);',
        'String id=request.getParameter("id"); String a=id; statement.executeUpdate("Q"+a);',
        'connection.prepareStatement("SELECT " + request.getParameter("id"));',
        'String q=("SELECT "+(request.getParameter("id"))); statement.executeQuery(q);',
    ],
)
def test_positive_local_flows(body: str) -> None:
    result = scan_snippet(snippet(body))
    assert result.summary.errors == 0
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.evidence.flow[0].kind == "source"
    assert finding.evidence.flow[-1].kind == "sink"
    assert finding.evidence_level == "heuristic_candidate"
    assert finding.evidence.uncertainties


@pytest.mark.parametrize(
    "body",
    [
        'statement.executeQuery("SELECT " + "constant");',
        'String q="SELECT "+request.getParameter("id");',
        '// statement.executeQuery("SELECT " + request.getParameter("id"));\n',
        'String sql="statement.executeQuery(request.getParameter(id))";',
        'String id=request.getParameter("id"); id="fixed"; statement.executeQuery("Q"+id);',
        'String id=request.getParameter("id"); String q="Q"+id; q="fixed"; statement.execute(q);',
        'PreparedStatement p=connection.prepareStatement("SELECT ?"); '
        'p.setString(1,request.getParameter("id")); p.executeQuery();',
        'return; statement.executeQuery("SELECT "+request.getParameter("id"));',
        'Object other=new Object(); other.executeQuery("Q"+request.getParameter("id"));',
    ],
)
def test_negative_controls(body: str) -> None:
    assert scan_snippet(snippet(body)).findings == []


def test_method_scope_isolation() -> None:
    code = 'class D { void a(HttpServletRequest r){String x=r.getParameter("id");} '
    code += 'void b(Statement s){s.executeQuery("Q"+x);} }'
    assert not scan_snippet(code).findings


def test_call_condition_is_explicitly_unsupported() -> None:
    result = scan_snippet(
        snippet(
            'String id=request.getParameter("id"); if(check()){id="fixed";} '
            'statement.executeQuery("Q"+id);'
        )
    )
    assert not result.findings
    assert any(d.code == "UNSUPPORTED_FLOW" for d in result.diagnostics)
    assert result.coverage.partial


def test_unresolved_call_diagnostic() -> None:
    result = scan_snippet(snippet('String x=escape(request.getParameter("id"));'))
    assert any(d.code == "UNRESOLVED_CALL" for d in result.diagnostics)


def test_fixtures_and_exact_lines() -> None:
    result = scan_path(ROOT / "fixtures/java")
    assert result.summary.files_analyzed == 2
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.location.path == "Vulnerable.java"
    assert finding.location.start_line == 8
    assert finding.location.start_column == 9
    assert finding.evidence.source.start_line == 6


def test_utf8_byte_columns_and_ir() -> None:
    code = snippet('String café="🍵"; statement.executeQuery("Q"+request.getParameter("id"));')
    analysis = JavaAnalysis(code.encode(), "unicode.java")
    analysis.analyze()
    assert len(analysis.units) == 1
    assert len(analysis.calls) == 2
    loc = analysis.findings[0].location
    assert loc.start_column == code.encode().index(b"statement.executeQuery") + 1


def test_parse_error_and_unsupported_language() -> None:
    bad = scan_snippet("class Broken { void x( {")
    assert bad.summary.errors
    assert bad.summary.files_analyzed == 0
    assert any(d.location for d in bad.diagnostics)
    unsupported = scan_snippet("package main", "go")
    assert unsupported.diagnostics[0].code == "UNSUPPORTED_LANGUAGE"
    assert unsupported.summary.files_analyzed == 0


def test_stable_fingerprints_across_roots(tmp_path: Path) -> None:
    code = snippet('statement.executeQuery("Q"+request.getParameter("id"));')
    results = []
    for name in ["a", "b"]:
        directory = tmp_path / name
        directory.mkdir()
        (directory / "D.java").write_text(code)
        results.append(scan_path(directory))
    assert results[0].scan_id != results[1].scan_id
    assert results[0].findings == results[1].findings


def test_schema_matches_committed_contract() -> None:
    schema = json.loads((ROOT / "schemas/scan-result.schema.json").read_text())
    assert schema == ScanResult.model_json_schema()
    Draft202012Validator.check_schema(schema)
    result = scan_path(ROOT / "fixtures/java")
    Draft202012Validator(schema).validate(result.model_dump())


def test_discovery_and_symlink_boundary(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules/ignored.java").write_text("bad")
    (tmp_path / "ok.java").write_text("class D {}")
    (tmp_path / "skip.java").write_text("bad")
    (tmp_path / "external.java").symlink_to(ROOT / "fixtures/java/Vulnerable.java")
    (tmp_path / "other.go").write_text("package main")
    result = scan_path(tmp_path, ("skip.java",))
    assert result.summary.files_analyzed == 1
    assert {d.code for d in result.diagnostics} == {"SYMLINK_SKIPPED", "UNSUPPORTED_LANGUAGE"}
    assert result.coverage.languages_detected == ["go", "java"]
    assert scan_path(tmp_path / "external.java").summary.errors == 1


def test_invalid_bytes_and_size(tmp_path: Path) -> None:
    for value, expected in [
        (b"\xff", "INVALID_ENCODING"),
        (b"\0", "BINARY_INPUT"),
        (b"x" * (MAX_FILE_BYTES + 1), "INPUT_TOO_LARGE"),
    ]:
        file = tmp_path / "D.java"
        file.write_bytes(value)
        assert scan_path(file).diagnostics[0].code == expected
    assert scan_snippet("x" * (MAX_FILE_BYTES + 1)).summary.errors == 1


def test_fifo_never_blocks(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe.java")
    assert scan_path(tmp_path).diagnostics[0].code == "SPECIAL_FILE_SKIPPED"


def test_limits_are_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import traceward.scanner as scanner

    (tmp_path / "D.java").write_text("class D {}")
    monkeypatch.setattr(scanner, "MAX_FILES", 0)
    assert scan_path(tmp_path).diagnostics[0].code == "FILE_LIMIT"
    monkeypatch.setattr(scanner, "MAX_FILES", 10)
    monkeypatch.setattr(scanner, "MAX_TOTAL_BYTES", 1)
    assert scan_path(tmp_path).diagnostics[0].code == "BYTE_LIMIT"


def test_exit_codes() -> None:
    vulnerable = scan_path(ROOT / "fixtures/java/Vulnerable.java")
    safe = scan_path(ROOT / "fixtures/java/Safe.java")
    assert exit_code(vulnerable, "high", "medium", False) == 1
    assert exit_code(vulnerable, "high", "high", False) == 0
    assert exit_code(vulnerable, "none", "medium", False) == 0
    assert exit_code(safe, "high", "medium", True) == 3
    assert exit_code(scan_snippet("class {"), "high", "medium", True) == 2


def test_installed_cli(tmp_path: Path) -> None:
    for command in [["--version"], ["doctor"], ["rules", "list", "--language", "java"]]:
        run = subprocess.run(["traceward", *command], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr
    output = tmp_path / "result.json"
    run = subprocess.run(
        [
            "traceward",
            "scan",
            str(ROOT / "fixtures/java"),
            "--format",
            "json",
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 1
    assert ScanResult.model_validate_json(output.read_text()).summary.findings == 1
    assert run.stdout == ""


def test_cli_shows_locations_and_scan_policy(tmp_path: Path) -> None:
    java = ROOT / "fixtures/java/Vulnerable.java"
    run = subprocess.run(["traceward", "scan", str(java)], capture_output=True, text=True)
    assert run.returncode == 1
    assert "Vulnerable.java:8:9" in run.stdout
    assert "source: line 6" in run.stdout and "sink: line 8" in run.stdout
    assert "PARTIAL COVERAGE" in run.stdout

    missing = subprocess.run(
        ["traceward", "scan", str(tmp_path / "missing.java")], capture_output=True, text=True
    )
    assert missing.returncode == 2 and "INVALID_PATH" in missing.stdout
    strict = subprocess.run(["traceward", "scan", str(java), "--fail-on-partial"])
    assert strict.returncode == 3
    failed_write = subprocess.run(
        ["traceward", "scan", str(java), "--output", str(tmp_path)], capture_output=True, text=True
    )
    assert failed_write.returncode == 2 and "Cannot write report" in failed_write.stderr


def test_unrecognized_file_and_empty_directory(tmp_path: Path) -> None:
    unknown = tmp_path / "only.txt"
    unknown.write_text("unrecognized file")
    assert scan_path(unknown).summary.errors
    result = scan_path(tmp_path)
    assert result.summary.files_analyzed == 0
    assert "NO_SUPPORTED_FILES" in {d.code for d in result.diagnostics}


def test_resource_fixture_evidence() -> None:
    result = scan_path(ROOT / "fixtures/jdbc-resources")
    assert result.summary.files_analyzed == 2
    assert result.diagnostics == []
    (finding,) = result.findings
    assert finding.location.path == "ResourceQuery.java"
    assert [(step.kind, step.location.start_line) for step in finding.evidence.flow] == [
        ("source", 8),
        ("assignment", 8),
        ("concatenation", 10),
        ("concatenation", 10),
        ("sink", 10),
    ]


def test_multiple_resources_in_declaration_order() -> None:
    body = (
        "try (java.sql.Connection c = open(); "
        'PreparedStatement p = c.prepareStatement("Q"+request.getHeader("id"))) { p.execute(); }'
    )
    (finding,) = scan_snippet(snippet(body)).findings
    assert finding.evidence.flow[-1].symbol == "Connection.prepareStatement"


def test_nested_resource_scopes_preserve_only_outer_locals() -> None:
    result = scan_snippet(
        snippet(
            'String outer = ""; try (statement) { { String inner=request.getHeader("id"); '
            'outer="Q"+inner; } } statement.executeQuery(outer); '
            'String inner="constant"; statement.executeQuery("Q"+inner);'
        )
    )
    assert result.diagnostics == []
    assert len(result.findings) == 1


def test_resource_receiver_expires_before_field_use() -> None:
    code = (
        "class D { Other s; void f(Connection c, HttpServletRequest r) {"
        'try (Statement s=c.createStatement()) {} s.executeQuery("Q"+r.getHeader("id")); } }'
    )
    assert not scan_snippet(code).findings


@pytest.mark.parametrize("handler", ["catch(Exception e) {}", "finally {}"])
def test_resource_handlers_stop_continuation(handler: str) -> None:
    query = 'statement.executeQuery("Q"+request.getHeader("id"));'
    code = snippet(f"try (statement) {{ {query} }} {handler} {query}")
    result = scan_snippet(code)
    assert len(result.findings) == 1
    (diagnostic,) = result.diagnostics
    assert diagnostic.code == "UNSUPPORTED_FLOW"
    assert diagnostic.location and diagnostic.location.start_column == code.index(handler) + 1


@pytest.mark.parametrize("stop", ["return;", "throw new RuntimeException();", "if (flag) return;"])
def test_nested_early_stop_reaches_method(stop: str) -> None:
    result = scan_snippet(
        snippet(
            f"try (statement) {{ {{ {stop} }} }} "
            'statement.executeQuery("Q"+request.getHeader("id"));'
        )
    )
    assert not result.findings
    assert bool(result.diagnostics) == stop.startswith("if")


def test_nested_scope_budget() -> None:
    result = scan_snippet(snippet("{" * 100 + "}" * 100))
    assert [d.code for d in result.diagnostics] == ["SCOPE_LIMIT"]


def test_block_field_assignment_is_outside_local_flow() -> None:
    code = (
        "class D {String q; void f(Statement s, HttpServletRequest r) {"
        '{ q = "Q"+r.getHeader("id"); } s.executeQuery(q); } }'
    )
    assert not scan_snippet(code).findings


def test_conditional_fixture_evidence() -> None:
    result = scan_path(ROOT / "fixtures/java-conditionals")
    assert result.summary.files_analyzed == 2
    (finding,) = result.findings
    assert finding.location.path == "ConditionalQuery.java"
    assert finding.evidence.source.start_line == 9
    assert finding.evidence.sink.start_line == 10
    assert finding.evidence_level == "heuristic_candidate"
    assert [d.code for d in result.diagnostics] == ["BRANCH_VALUE_DIVERGENCE"]


QUERY_FROM_INPUT = 'statement.executeQuery("Q"+request.getParameter("id"));'
QUERY_FROM_LOCAL = 'statement.executeQuery("Q"+id);'


@pytest.mark.parametrize(
    ("body", "count", "diagnostics"),
    [
        (f"if (false) {QUERY_FROM_INPUT}", 0, []),
        (f"if (true) {{}} else {QUERY_FROM_INPUT}", 0, []),
        (f"if (false) {{}} else {QUERY_FROM_INPUT}", 1, []),
        (f"boolean off=false; if (/* disabled */ (off)) {QUERY_FROM_INPUT}", 0, []),
        (f"if (flag) {{ if (flag) {{}} else {QUERY_FROM_INPUT} }}", 0, []),
        (f"if (flag) {{}} else return; if (flag) {QUERY_FROM_INPUT}", 1, []),
        (f"if (flag) {{}} else return; if (flag) {{}} else {QUERY_FROM_INPUT}", 0, []),
        (f"if (flag) return; else throw new RuntimeException(); {QUERY_FROM_INPUT}", 0, []),
        (f"if (flag) ; else ; {QUERY_FROM_INPUT}", 1, []),
        (
            f"if (flag) while (other) {{}} else {QUERY_FROM_INPUT} {QUERY_FROM_INPUT}",
            1,
            ["UNSUPPORTED_FLOW"],
        ),
        (
            f'String id=request.getParameter("id"); if (flag) {{}} else {{}} {QUERY_FROM_LOCAL}',
            1,
            [],
        ),
        (
            f'String id=request.getParameter("id"); if (flag) id="fixed"; {QUERY_FROM_LOCAL}',
            0,
            ["BRANCH_VALUE_DIVERGENCE"],
        ),
        (
            f'String id="fixed"; if (flag) id=request.getParameter("id"); else return; '
            f"{QUERY_FROM_LOCAL}",
            1,
            [],
        ),
        (f"if (flag) flag=false; if (flag) {QUERY_FROM_INPUT}", 0, []),
    ],
)
def test_conditional_flow(body: str, count: int, diagnostics: list[str]) -> None:
    result = scan_snippet(snippet(body, f"{PARAMS}, boolean flag, boolean other"))
    assert result.summary.errors == 0
    assert len(result.findings) == count
    assert [diagnostic.code for diagnostic in result.diagnostics] == diagnostics


def test_conditional_budget() -> None:
    result = scan_snippet(snippet("if (flag) {}" * 65, f"{PARAMS}, boolean flag"))
    assert [d.code for d in result.diagnostics] == ["BRANCH_LIMIT"]


@pytest.mark.parametrize(
    ("language_filter", "selected_file"), [("python", "demo.py"), ("typescript", "demo.mts")]
)
def test_mixed_directory_and_explicit_language(
    tmp_path: Path, language_filter: str, selected_file: str
) -> None:
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "dependency.py").write_text("broken(")
    (tmp_path / ".next").mkdir()
    (tmp_path / ".next" / "generated.js").write_text("broken(")
    (tmp_path / "demo.java").write_bytes((ROOT / "fixtures/java/Vulnerable.java").read_bytes())
    (tmp_path / "demo.py").write_bytes((ROOT / "fixtures/python/concatenated.py").read_bytes())
    for language, extension, fixture in [
        ("javascript", ".mjs", "concatenated.js"),
        ("typescript", ".mts", "concatenated.ts"),
    ]:
        code = (ROOT / "fixtures" / language / fixture).read_bytes()
        (tmp_path / f"demo{extension}").write_bytes(code)
    result = scan_path(tmp_path)
    assert (result.summary.files_analyzed, result.summary.findings, result.summary.errors) == (
        4,
        4,
        0,
    )
    assert result.coverage.languages_detected == ["java", "javascript", "python", "typescript"]
    assert result.coverage.supported_checks == ["CWE-89"]
    assert {f.location.path for f in result.findings} == {
        "demo.py",
        "demo.java",
        "demo.mjs",
        "demo.mts",
    }
    assert sum("process.argv" in text for text in result.coverage.limitations) == 1
    assert any("sqlite3" in text for text in result.coverage.limitations)
    assert any("JDBC" in text or "Java" in text for text in result.coverage.limitations)
    cli = subprocess.run(
        ["traceward", "scan", str(tmp_path), "--language", language_filter, "--format", "json"],
        capture_output=True,
        text=True,
    )
    assert cli.returncode == 1
    selected = ScanResult.model_validate_json(cli.stdout)
    assert selected.summary.files_analyzed == selected.summary.files_discovered == 1
    assert selected.coverage.languages_detected == [language_filter]
    assert not any("Java" in note for note in selected.coverage.limitations)
    assert selected.findings == [f for f in result.findings if f.location.path == selected_file]
    mismatch = scan_path(tmp_path / "demo.py", language_filter="java")
    assert mismatch.summary.errors == 1
    assert "LANGUAGE_MISMATCH" in [item.code for item in mismatch.diagnostics]
