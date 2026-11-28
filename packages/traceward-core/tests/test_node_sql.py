from pathlib import Path

import pytest
from traceward import node_sql
from traceward.node_sql import NodeSqlAnalysis
from traceward.registry import NODE_SQL

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"
IMPORT = 'import { DatabaseSync } from "node:sqlite";\n'
SETUP = IMPORT + 'const db = new DatabaseSync(":memory:");\n'
QUERY = '"SELECT name FROM sqlite_schema WHERE name = " + process.argv[2]'


def analyze(code: str, path: str = "snippet.js", language: str = "javascript") -> NodeSqlAnalysis:
    analysis = NodeSqlAnalysis(code.encode(), path, language)
    analysis.analyze()
    return analysis


@pytest.mark.parametrize(("language", "extension"), [("javascript", "js"), ("typescript", "ts")])
def test_fixture_findings_and_bound_parameters(language: str, extension: str) -> None:
    folder = FIXTURES / language
    name = f"concatenated.{extension}"
    example = (folder / name).read_text()
    analysis = analyze(example, name, language)
    assert not analysis.diagnostics
    (finding,) = analysis.findings
    assert finding == analyze(example, name, language).findings[0]
    assert (
        finding.fingerprint
        != analyze(example, f"renamed.{extension}", language).findings[0].fingerprint
    )
    assert finding.rule_id == finding.detectors[0].id == NODE_SQL[language].id
    assert finding.detectors[0].version == NODE_SQL[language].version
    assert finding.cwe == ["CWE-89"] and finding.evidence_level == "heuristic_candidate"
    assert finding.evidence.source.path == finding.location.path == name
    assert finding.evidence.source.start_line == 4
    assert finding.evidence.sink == finding.location
    assert finding.location.start_line == 6
    assert finding.evidence.flow[0].symbol == "process.argv"
    assert finding.evidence.flow[-1].symbol == "node:sqlite.DatabaseSync.prepare"

    name = f"parameterized.{extension}"
    bound = analyze((folder / name).read_text(), name, language)
    assert bound.findings == bound.diagnostics == []


def test_exec_span_utf8_and_value_copy() -> None:
    source = "const café = process.argv[3], name = (café);"
    sink = 'db.exec("SELECT café FROM employees WHERE name = " + name);'
    analysis = analyze(SETUP + source + "\n" + sink)
    assert not analysis.diagnostics
    (finding,) = analysis.findings
    assert [(step.kind, step.symbol) for step in finding.evidence.flow] == [
        ("source", "process.argv"),
        ("assignment", "café"),
        ("assignment", "name"),
        ("concatenation", "+"),
        ("sink", "node:sqlite.DatabaseSync.exec"),
    ]
    span = finding.evidence.source
    assert source.encode()[span.start_column - 1 : span.end_column - 1] == b"process.argv[3]"
    span = finding.location
    assert sink.encode()[span.start_column - 1 : span.end_column - 1] == sink.encode()[:-1]


def test_duplicate_sink_spelling_produces_distinct_identities() -> None:
    code = SETUP + f"db.exec({QUERY});\ndb.exec({QUERY});"
    findings = analyze(code).findings
    assert len(findings) == 2 and findings == analyze(code).findings
    assert findings[0].fingerprint != findings[1].fingerprint


@pytest.mark.parametrize(
    "statement",
    [
        'db.exec("SELECT 1");',
        'db.prepare("SELECT " + "1");',
        "db.exec(`SELECT 1`);",
        'db.exec("SELECT " + process.argv[0]);',
        'db.exec("SELECT " + process.argv[1]);',
        "db.exec(process.argv[2]);",
        'const q = "db.exec(process.argv[2])"; db.exec(q);',
        "// db.exec(" + QUERY + ");",
        f"const q = {QUERY};",
        'const stmt = db.prepare("SELECT ?"); stmt.run("value " + process.argv[2]);',
        'const stmt = db.prepare("SELECT ?"); stmt.all(1); stmt.iterate(true); stmt.get(null);',
    ],
)
def test_only_concatenated_input_reaching_sql_text_counts(statement: str) -> None:
    analysis = analyze(SETUP + statement)
    assert analysis.findings == analysis.diagnostics == []


@pytest.mark.parametrize(
    "statement",
    [
        f"if (false) db.exec({QUERY});",
        f"function savedForLater() {{ db.exec({QUERY}); }}",
        'db.exec("SELECT " + process.argv[1 + 1]);',
        'db.exec("SELECT " + process.argv[0x2]);',
        'db.exec("SELECT " + process?.argv[2]);',
        'db.exec("SELECT " + process.argv?.[2]);',
        'db.exec("SELECT " + process.argv[processIndex]);',
        f'db["exec"]({QUERY});',
        f"db?.exec({QUERY});",
        f"db.exec?.({QUERY});",
        f"let temp = {QUERY}; db.exec(temp);",
        f"const db2 = db; db2.exec({QUERY});",
        f"db.exec = replacement; db.exec({QUERY});",
        f"db = fake; db.exec({QUERY});",
        f"another.prepare({QUERY});",
        f"db.exec({QUERY}, extra);",
        "db.exec(3);",
        "db.exec(sql`SELECT ${process.argv[2]}`);",
        'new DatabaseSync(":memory:", options);',
        "const { name } = unknown;",
    ],
)
def test_unsupported_flow_has_diagnostic_and_does_not_stitch_later_sink(statement: str) -> None:
    analysis = analyze(SETUP + statement + f"\ndb.exec({QUERY});\n")
    assert not analysis.findings
    (warning,) = analysis.diagnostics
    assert warning.level == "warning" and warning.code == "UNSUPPORTED_FLOW"
    assert warning.location is not None and warning.location.start_line == 3


@pytest.mark.parametrize(
    ("suffix", "language"),
    [
        ("const process = other;", "javascript"),
        ("function process() {}", "javascript"),
        ("const { process } = other;", "javascript"),
        (r"function \u0070rocess() {}", "javascript"),
        ("class process {}", "typescript"),
        ("declare const process: Process;", "typescript"),
        ("enum process { Foo }", "typescript"),
        ("const DatabaseSync = other;", "javascript"),
        (IMPORT, "javascript"),
        ("const db = other;", "javascript"),
    ],
)
def test_ambiguous_bindings_even_after_a_candidate(suffix: str, language: str) -> None:
    code = SETUP + f"db.exec({QUERY});\n" + suffix
    analysis = analyze(code, "snippet.js" if language == "javascript" else "snippet.ts", language)
    assert not analysis.findings
    assert [item.code for item in analysis.diagnostics] == ["UNRESOLVED_BINDING"]


@pytest.mark.parametrize(
    ("import_line", "language", "expected"),
    [
        ('import { DatabaseSync } from "sqlite";', "javascript", "UNRESOLVED_BINDING"),
        ('import { DatabaseSync as DB } from "node:sqlite";', "javascript", "UNRESOLVED_BINDING"),
        ('import type { DatabaseSync } from "node:sqlite";', "typescript", "UNRESOLVED_BINDING"),
        ('import { type DatabaseSync } from "node:sqlite";', "typescript", "UNRESOLVED_BINDING"),
        (
            'import { DatabaseSync, StatementSync } from "node:sqlite";',
            "typescript",
            "UNRESOLVED_BINDING",
        ),
        ('import DB from "node:sqlite";', "javascript", "UNSUPPORTED_FLOW"),
        ('import DB, { DatabaseSync } from "node:sqlite";', "javascript", "UNRESOLVED_BINDING"),
        ("", "javascript", "UNSUPPORTED_FLOW"),
    ],
)
def test_constructor_requires_exact_value_import(
    import_line: str, language: str, expected: str
) -> None:
    code = import_line + '\nconst db = new DatabaseSync(":memory:");\n' + f"db.exec({QUERY});"
    analysis = analyze(code, "snippet.js" if language == "javascript" else "snippet.ts", language)
    assert not analysis.findings
    assert [item.code for item in analysis.diagnostics] == [expected]


def test_typescript_constructor_annotation_is_not_a_binding() -> None:
    code = SETUP.replace("const db", "const db: DatabaseSync") + f"db.exec({QUERY});"
    analysis = analyze(code, "snippet.ts", "typescript")
    assert len(analysis.findings) == 1 and not analysis.diagnostics


@pytest.mark.parametrize(
    ("path", "language"), [("source.jsx", "javascript"), ("source.TSX", "typescript")]
)
def test_jsx_grammar_parses_but_analysis_stops_at_jsx(path: str, language: str) -> None:
    code = SETUP + f"db.exec({QUERY});\nconst element = <p>Test</p>;"
    analysis = analyze(code, path, language)
    assert len(analysis.findings) == 1
    assert [item.code for item in analysis.diagnostics] == ["UNSUPPORTED_FLOW"]


def test_invalid_file_reports_parse_error_without_a_finding() -> None:
    analysis = analyze(SETUP + f"db.exec({QUERY});\nconst broken = ;")
    assert not analysis.findings
    (error,) = analysis.diagnostics
    assert error.code == "PARSE_ERROR" and error.level == "error"
    assert error.location is not None and error.location.start_line == 4


def test_ast_and_result_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(node_sql, "MAX_AST_NODES", 100)
    analysis = analyze(SETUP + f"db.exec({QUERY});\n" * 100)
    assert not analysis.findings
    assert [item.code for item in analysis.diagnostics] == ["AST_LIMIT"]
    monkeypatch.setattr(node_sql, "MAX_AST_NODES", 100_000)
    monkeypatch.setattr(node_sql, "MAX_FINDINGS", 2)
    analysis = analyze(SETUP + f"db.exec({QUERY});\n" * 3)
    assert len(analysis.findings) == 2
    assert [item.code for item in analysis.diagnostics] == ["ANALYSIS_LIMIT"]


def test_expression_and_trace_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(node_sql, "MAX_EXPRESSION_DEPTH", 3)
    depth = analyze(SETUP + "db.exec(" + "(" * 5 + QUERY + ")" * 5 + ");")
    assert not depth.findings
    assert [item.code for item in depth.diagnostics] == ["ANALYSIS_LIMIT"]
    monkeypatch.setattr(node_sql, "MAX_TRACE_STEPS", 3)
    trace = analyze(SETUP + "const name = process.argv[2]; db.exec('SELECT ' + name);")
    assert not trace.findings
    assert [item.code for item in trace.diagnostics] == ["ANALYSIS_LIMIT"]
