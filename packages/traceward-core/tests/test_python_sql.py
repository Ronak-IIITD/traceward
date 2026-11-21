from pathlib import Path
from textwrap import dedent

import pytest
from traceward.python_sql import PythonAnalysis
from traceward.registry import PYTHON_SQL

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/python"
SETUP = 'import sqlite3\ndb = sqlite3.connect(":memory:")\n'


def analyze(code: str, path: str = "lookup.py") -> PythonAnalysis:
    analysis = PythonAnalysis(code.encode(), path)
    analysis.analyze()
    return analysis


def test_fixture_evidence_and_identity() -> None:
    code = (FIXTURES / "concatenated.py").read_text()
    analysis = analyze(code)
    assert analysis.diagnostics == []
    (finding,) = analysis.findings
    assert finding.rule_id == finding.detectors[0].id == PYTHON_SQL.id
    assert finding.detectors[0].version == PYTHON_SQL.version
    assert finding.cwe == ["CWE-89"] and finding.evidence_level == "heuristic_candidate"
    assert finding.guidance == PYTHON_SQL.guidance
    assert [
        (step.kind, step.symbol, step.location.start_line) for step in finding.evidence.flow
    ] == [
        ("source", "input", 6),
        ("assignment", "value", 6),
        ("concatenation", "+", 7),
        ("assignment", "query", 7),
        ("sink", "sqlite3.Connection.execute", 8),
    ]
    assert finding == analyze(code).findings[0]
    assert finding.fingerprint != analyze(code, "elsewhere.py").findings[0].fingerprint
    repeated = analyze(code + "    db.execute(query)\n").findings
    assert len({item.fingerprint for item in repeated}) == 2


def test_only_concatenated_first_argument_counts() -> None:
    assert analyze((FIXTURES / "parameterized.py").read_text()).findings == []
    assert analyze(SETUP + "db.execute(input())").findings == []
    assert analyze(SETUP + 'db.execute("SELECT " + "1")').findings == []
    assert (
        analyze(SETUP + 'value = input()\nvalue = "1"\ndb.execute("SELECT " + value)').findings
        == []
    )
    assert (
        analyze(SETUP + '# db.execute("SELECT " + input())\n"db.execute(input())"').findings == []
    )


def test_positional_bindings_do_not_hide_a_dynamic_template() -> None:
    code = SETUP + 'db.execute(("SELECT " + input()), (1,))'
    (finding,) = analyze(code).findings
    assert finding.location.start_line == 3
    assert finding.evidence.flow[1].kind == "concatenation"


def test_utf8_byte_offsets_match_submitted_source() -> None:
    line = 'nomé = "SELECT " + input("é")'
    code = SETUP + line + "\ndb.execute(nomé)"
    source = analyze(code).findings[0].evidence.source
    assert source.start_line == source.end_line == 3
    assert line.encode()[source.start_column - 1 : source.end_column - 1].decode() == 'input("é")'


@pytest.mark.parametrize(
    "code",
    [
        'import sqlite3 as sqlite3_alt\ndb = sqlite3_alt.connect(":memory:")',
        SETUP + "db = other",
        SETUP + 'db = sqlite3.connect(":memory:", factory=other)',
        'db = sqlite3.connect(":memory:")',
        SETUP + "if allowed:\n    pass",
        SETUP + 'value = f"SELECT {input()}"',
        SETUP + "cursor = db.cursor(factory=other)",
        SETUP + "value = transform(input())",
        SETUP + "value = input(42)",
        SETUP + "value = 1 + input()",
        SETUP + 'db.execute("SELECT 1", params)',
        SETUP + "db.execute()",
        SETUP + "db, other = pair",
        SETUP + "a, b",
        SETUP + 'value = b"bytes"',
        SETUP + 'value = obj.execute("SELECT " + input())',
        SETUP + 'value = "λ" * 3',
        SETUP + 'value = input()\nquery = "SELECT " + value\nreturn',
    ],
)
def test_unsupported_paths_never_stitch_evidence(code: str) -> None:
    analysis = analyze(code + '\ndb.execute("SELECT " + input())')
    assert analysis.findings == []
    assert analysis.diagnostics


@pytest.mark.parametrize(
    "code",
    [
        SETUP + 'ｄｂ = fake\ndb.execute("SELECT " + input())',
        SETUP + 'input = trusted\ndb.execute("SELECT " + input())',
        SETUP + 'sqlite3.connect = alternate\ndb.execute("SELECT " + input())',
        "from helpers import *\n" + SETUP + 'db.execute("SELECT " + input())',
        (FIXTURES / "concatenated.py").read_text().replace("lookup()", "lookup(input)"),
        (FIXTURES / "concatenated.py").read_text().replace("lookup()", "lookup(sqlite3)"),
        (FIXTURES / "concatenated.py").read_text() + "    input = lambda: '1'\n",
        (FIXTURES / "concatenated.py").read_text() + "def input(): return '1'\n",
    ],
)
def test_shadowed_or_ambiguous_names_skip_scope(code: str) -> None:
    analysis = analyze(code)
    assert analysis.findings == []
    assert [item.code for item in analysis.diagnostics] == ["UNRESOLVED_BINDING"]


def test_scope_and_return_boundaries() -> None:
    code = dedent("""\
        import sqlite3

        def first():
            db = sqlite3.connect(":memory:")
            return
            db.execute("SELECT " + input())

        def second():
            db.execute("SELECT " + input())

        def third():
            db = sqlite3.connect(":memory:")
            return db.execute("SELECT " + input())
        """)
    analysis = analyze(code)
    assert {item.location.start_line for item in analysis.findings} == {13}
    assert len(analysis.diagnostics) == 1


def test_invalid_source_has_error_and_no_findings() -> None:
    code = (FIXTURES / "concatenated.py").read_text() + "\ndef broken(:"
    analysis = analyze(code)
    assert not analysis.findings
    (error,) = analysis.diagnostics
    assert error.code == "PARSE_ERROR" and error.level == "error" and error.location is not None


def test_path_and_output_budgets() -> None:
    long_path = SETUP + "value = input()\n" + 'value = "x" + value\n' * 34 + "db.execute(value)"
    analysis = analyze(long_path)
    assert not analysis.findings and "64-step" in analysis.diagnostics[0].message
    nested = SETUP + 'db.execute("SELECT " + ' + "(" * 52 + "input()" + ")" * 52 + ")"
    assert "nesting" in analyze(nested).diagnostics[0].message
    noisy = SETUP + 'db.execute("SELECT " + input())\n' * 160
    analysis = analyze(noisy)
    assert len(analysis.findings) == 128 and analysis.diagnostics[-1].code == "ANALYSIS_LIMIT"
    very_large = "value = 1\n" * 22_000
    assert analyze(very_large).diagnostics[0].code == "AST_LIMIT"


def test_cursor_fixture_reports_the_cursor_sink() -> None:
    code = (FIXTURES / "cursor_concatenated.py").read_text()
    analysis = analyze(code)
    assert analysis.diagnostics == []
    (finding,) = analysis.findings
    assert finding.rule_id == PYTHON_SQL.id
    assert finding.evidence.source.start_line == 7
    assert finding.evidence.flow[-1].symbol == "sqlite3.Cursor.execute"
    assert finding.evidence.sink == finding.location
    assert finding.location.start_line == 8


def test_cursor_bound_query_and_literal_statements_continue() -> None:
    # Same API shapes as the CPython sqlite3 execute_1 documentation example.
    code = SETUP + dedent("""\
        cur = db.cursor()
        cur.execute("CREATE TABLE items (name, count)")
        cur.execute("INSERT INTO items VALUES (?, ?)", ("sample", 2))
        value = input()
        cur.execute("SELECT count FROM items WHERE name = ?", (value,))
        """)
    analysis = analyze(code)
    assert analysis.findings == analysis.diagnostics == []
    assert len(analyze(code + 'cur.execute("SELECT " + value)').findings) == 1


@pytest.mark.parametrize(
    "invalid_receiver",
    [
        "cur = db.cursor()\ncur = unknown",
        "cur = other.cursor()",
        "cur = db.cursor(factory=custom)",
        "copy = db\ncur = copy.cursor()",
        "original = db.cursor()\ncur = original",
        "cur = db.cursor()\nimport cur",
        "cur = db.cursor()\ndef cur(): pass",
    ],
)
def test_cursor_origin_and_rebinding(invalid_receiver: str) -> None:
    analysis = analyze(SETUP + invalid_receiver + '\ncur.execute("SELECT " + input())')
    assert not analysis.findings
    assert analysis.diagnostics[-1].code == "UNSUPPORTED_FLOW"


def test_ordinary_imports_and_cursor_rebinding_to_connection() -> None:
    code = (
        "import sys\n"
        + SETUP
        + dedent("""\
        client = db.cursor()
        client.execute("SELECT " + input())
        client = sqlite3.connect(":memory:")
        client.execute("SELECT " + input())
        """)
    )
    analysis = analyze(code)
    assert analysis.diagnostics == []
    assert [f.evidence.flow[-1].symbol for f in analysis.findings] == [
        "sqlite3.Cursor.execute",
        "sqlite3.Connection.execute",
    ]
