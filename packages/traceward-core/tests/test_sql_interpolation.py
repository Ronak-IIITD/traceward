"""SQL interpolation follows a witnessed string flow, never arbitrary coercion."""

import json
from pathlib import Path

import pytest
from traceward.scanner import scan_snippet

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/sql-interpolation"
PYTHON_SETUP = 'import sqlite3\ndb = sqlite3.connect(":memory:")\n'
NODE_SETUP = (
    'import { DatabaseSync } from "node:sqlite";\nconst db = new DatabaseSync(":memory:");\n'
)
LANGUAGES = [
    ("python", "py", "f-string"),
    ("javascript", "js", "template literal"),
    ("typescript", "ts", "template literal"),
]


@pytest.mark.parametrize(("language", "extension", "symbol"), LANGUAGES)
def test_interpolation_fixture_evidence_and_binding_hard_negative(
    language: str, extension: str, symbol: str
) -> None:
    code = (FIXTURES / language / f"interpolated.{extension}").read_text()
    result = scan_snippet(code, language=language)
    assert result.summary.errors == 0 and not result.diagnostics
    assert result.coverage.partial
    (finding,) = result.findings
    assert finding.cwe == ["CWE-89"] and finding.evidence_level == "heuristic_candidate"
    assert [(step.kind, step.location.start_line) for step in finding.evidence.flow] == [
        ("source", 4),
        ("assignment", 4),
        ("concatenation", 5),
        ("assignment", 5),
        ("sink", 6),
    ]
    assert finding.evidence.flow[2].symbol == symbol
    assert finding.evidence.source == finding.evidence.flow[0].location
    assert finding.evidence.sink == finding.location
    assert finding == scan_snippet(code, language=language).findings[0]
    # Fingerprints continue to identify the sink when lines move.
    assert (
        finding.fingerprint == scan_snippet("\n" + code, language=language).findings[0].fingerprint
    )
    bound = (FIXTURES / language / f"parameterized.{extension}").read_text()
    safe = scan_snippet(bound, language=language)
    assert safe.findings == safe.diagnostics == []


@pytest.mark.parametrize("prefix", ["f", "F", "fr", "rf", "Fr", "rF"])
def test_python_f_string_prefixes_and_cursor_sink(prefix: str) -> None:
    code = PYTHON_SETUP + f'cur = db.cursor()\ncur.execute({prefix}"SELECT {{input()}}")'
    result = scan_snippet(code, language="python")
    assert not result.diagnostics
    (finding,) = result.findings
    assert [step.symbol for step in finding.evidence.flow] == [
        "input",
        "f-string",
        "sqlite3.Cursor.execute",
    ]


@pytest.mark.parametrize("language", ["python", "javascript", "typescript"])
def test_interpolation_utf8_multiline_span_and_first_witness(language: str) -> None:
    if language == "python":
        template = 'f"""SELECT café\nWHERE name = {input("é")} AND other = {input()}"""'
        code = PYTHON_SETUP + f"db.execute({template})"
        expression = 'input("é")'
    else:
        template = "`SELECT café\nWHERE name = ${process.argv[2]} AND other = ${process.argv[3]}`"
        code = NODE_SETUP + f"db.exec({template});"
        expression = "process.argv[2]"
    result = scan_snippet(code, language=language)
    assert not result.diagnostics
    (finding,) = result.findings
    assert [step.kind for step in finding.evidence.flow] == ["source", "concatenation", "sink"]
    source = finding.evidence.source
    line = code.splitlines()[source.start_line - 1].encode()
    assert line[source.start_column - 1 : source.end_column - 1] == expression.encode()
    assembly = finding.evidence.flow[1].location
    assert assembly.start_line == 3 and assembly.end_line == 4
    assert (
        code.splitlines()[2].encode()[assembly.start_column - 1 :]
        == template.splitlines()[0].encode()
    )
    assert (
        code.splitlines()[3].encode()[: assembly.end_column - 1]
        == template.splitlines()[1].encode()
    )


@pytest.mark.parametrize(
    "statement",
    [
        "db.execute(f\"SELECT {'constant'}\")",
        'db.execute(f"SELECT {{input()}}")',
        'value = input()\nquery = f"SELECT {value}"\ndb.execute("SELECT 1")',
        'value = input()\nvalue = "constant"\ndb.execute(f"SELECT {value}")',
        '# db.execute(f"SELECT {input()}")',
        'db.execute("SELECT {input()}")',
        'db.execute(f"SELECT 1")',
    ],
)
def test_python_interpolation_hard_negatives(statement: str) -> None:
    result = scan_snippet(PYTHON_SETUP + statement, language="python")
    assert result.findings == result.diagnostics == []


@pytest.mark.parametrize("language", ["javascript", "typescript"])
@pytest.mark.parametrize(
    "statement",
    [
        'db.exec(`SELECT ${"constant"}`);',
        r"db.exec(`SELECT \${process.argv[2]}`);",
        'const name = process.argv[2]; const query = `SELECT ${name}`; db.exec("SELECT 1");',
        "db.exec(`SELECT ${process.argv[0]} ${process.argv[1]}`);",
        "// db.exec(`SELECT ${process.argv[2]}`);",
        'db.exec("SELECT ${process.argv[2]}");',
        'const stmt = db.prepare("SELECT ?"); stmt.get(`${process.argv[2]}`);',
    ],
)
def test_node_interpolation_hard_negatives(language: str, statement: str) -> None:
    result = scan_snippet(NODE_SETUP + statement, language=language)
    assert result.findings == result.diagnostics == []


@pytest.mark.parametrize(
    "template",
    [
        'f"SELECT {input()!s}"',
        'f"SELECT {input()!r}"',
        'f"SELECT {input()!a}"',
        'f"SELECT {input()=}"',
        'f"SELECT {input():}"',
        'f"SELECT {input():>10}"',
        'f"SELECT {input():{input()}}"',
        'f"SELECT {input()} {unknown}"',
        'f"SELECT {unknown} {input()}"',
        'f"SELECT {input()} {42}"',
        'f"SELECT {input()} {db}"',
        'f"SELECT {transform(input())}"',
        "f\"SELECT {input()} {(value := 'constant')}\"",
    ],
)
def test_unmodeled_python_fields_stop_the_path(template: str) -> None:
    code = PYTHON_SETUP + f'db.execute({template})\ndb.execute(f"SELECT {{input()}}")'
    result = scan_snippet(code, language="python")
    assert not result.findings and result.summary.errors == 0
    (warning,) = result.diagnostics
    assert warning.code == "UNSUPPORTED_FLOW" and warning.location is not None
    assert warning.location.start_line == 3


@pytest.mark.parametrize("language", ["javascript", "typescript"])
@pytest.mark.parametrize(
    "template",
    [
        "`SELECT ${process.argv[2]} ${unknown}`",
        "`SELECT ${unknown} ${process.argv[2]}`",
        "`SELECT ${process.argv[2]} ${42}`",
        "`SELECT ${process.argv[2]} ${db}`",
        "`SELECT ${transform(process.argv[2])}`",
        '`SELECT ${(process.argv[2], "constant")}`',
        "sql`SELECT ${process.argv[2]}`",
        "String.raw`SELECT ${process.argv[2]}`",
        '`SELECT ${process.argv[2]} ${name = "constant"}`',
    ],
)
def test_unmodeled_node_fields_stop_the_path(language: str, template: str) -> None:
    code = NODE_SETUP + f"db.exec({template});\ndb.exec(`SELECT ${{process.argv[2]}}`);"
    result = scan_snippet(code, language=language)
    assert not result.findings and result.summary.errors == 0
    (warning,) = result.diagnostics
    assert warning.code == "UNSUPPORTED_FLOW" and warning.location is not None
    assert warning.location.start_line == 3


@pytest.mark.parametrize("language", ["python", "javascript", "typescript"])
def test_nested_interpolation_and_concatenation_preserve_order(language: str) -> None:
    if language == "python":
        code = PYTHON_SETUP + 'db.execute("SELECT " + f"{f\'{input()}\'}")'
    else:
        code = NODE_SETUP + 'db.exec("SELECT " + `${`${process.argv[2]}`}`);'
    result = scan_snippet(code, language=language)
    assert not result.diagnostics
    (finding,) = result.findings
    assert [step.kind for step in finding.evidence.flow] == [
        "source",
        "concatenation",
        "concatenation",
        "concatenation",
        "sink",
    ]
    assert finding.evidence.flow[-2].symbol == "+"


@pytest.mark.parametrize("language", ["python", "javascript", "typescript"])
def test_constant_fields_before_the_source_preserve_its_evidence(language: str) -> None:
    if language == "python":
        code = PYTHON_SETUP + "db.execute(f\"{'SELECT '}{input()}\")"
        symbol = "input"
    else:
        code = NODE_SETUP + 'db.exec(`${"SELECT "}${process.argv[2]}`);'
        symbol = "process.argv"
    result = scan_snippet(code, language=language)
    assert not result.diagnostics
    (finding,) = result.findings
    assert finding.evidence.flow[0].symbol == symbol


@pytest.mark.parametrize("language", ["python", "javascript", "typescript"])
def test_interpolation_never_executes_embedded_calls(tmp_path: Path, language: str) -> None:
    marker = tmp_path / "executed"
    path = json.dumps(str(marker))
    if language == "python":
        template = f"f\"{{input()}}{{__import__('pathlib').Path({path}).touch()}}\""
        code = PYTHON_SETUP + f"db.execute({template})"
    else:
        template = (
            f'`${{process.argv[2]}}${{require("node:fs").writeFileSync({path}, "executed")}}`'
        )
        code = NODE_SETUP + f"db.exec({template});"
    result = scan_snippet(code, language=language)
    assert not result.findings and result.summary.errors == 0
    assert result.diagnostics[0].code == "UNSUPPORTED_FLOW"
    assert not marker.exists()


def test_flask_f_string_source_and_dynamic_query_with_bindings() -> None:
    code = (
        "from flask import request\nimport sqlite3\n"
        "def lookup():\n"
        '    db = sqlite3.connect(":memory:")\n'
        '    db.execute(f"SELECT {request.args[\'table\']} WHERE name = ?", ("value",))\n'
    )
    result = scan_snippet(code, language="python")
    assert not result.diagnostics
    (finding,) = result.findings
    assert finding.evidence.flow[0].symbol == "flask.request.args"
    assert finding.evidence.flow[1].symbol == "f-string"
    assert finding.location.start_line == 5


@pytest.mark.parametrize(
    ("language", "code"),
    [
        ("python", PYTHON_SETUP + 'db.execute(f"SELECT {input()")'),
        ("javascript", NODE_SETUP + "db.exec(`SELECT ${process.argv[2]`);"),
        ("typescript", NODE_SETUP + "db.exec(`SELECT ${process.argv[2]`);"),
    ],
)
def test_invalid_interpolation_reports_a_scan_error(language: str, code: str) -> None:
    result = scan_snippet(code, language=language)
    assert not result.findings and result.summary.errors == 1
    assert result.diagnostics[0].code == "PARSE_ERROR"


@pytest.mark.parametrize("language", ["python", "javascript", "typescript"])
def test_interpolation_reuses_expression_and_evidence_budgets(language: str) -> None:
    if language == "python":
        setup, source, declaration, sink = (
            PYTHON_SETUP,
            "value = input()\n",
            'value = f"{value}"\n',
            "db.execute(value)",
        )
        nested = 'f"{' * 52 + "input()" + '}"' * 52
        deep = f"db.execute({nested})"
    else:
        setup = NODE_SETUP
        source = "const value0 = process.argv[2];\n"
        declaration = "".join(f"const value{i + 1} = `${{value{i}}}`;\n" for i in range(35))
        sink = "db.exec(value35);"
        nested = "`${" * 52 + "process.argv[2]" + "}`" * 52
        deep = f"db.exec({nested});"
    long_code = setup + source + (declaration * 35 if language == "python" else declaration) + sink
    for code in (long_code, setup + deep):
        result = scan_snippet(code, language=language)
        assert not result.findings and result.summary.errors == 0
        assert (
            "budget" in result.diagnostics[0].message or "nesting" in result.diagnostics[0].message
        )
