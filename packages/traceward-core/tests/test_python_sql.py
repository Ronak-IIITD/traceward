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
        SETUP + 'value = f"SELECT {input()!r}"',
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


FLASK_FIXTURES = FIXTURES.with_name("flask-sqlite")


def test_flask_route_fixture_evidence_and_parameterized_query() -> None:
    code = (FLASK_FIXTURES / "concatenated.py").read_text()
    analysis = analyze(code)
    assert analysis.diagnostics == []
    (finding,) = analysis.findings
    assert finding == analyze(code).findings[0]
    assert finding.detectors[0].version == PYTHON_SQL.version
    assert [
        (step.kind, step.symbol, step.location.start_line) for step in finding.evidence.flow
    ] == [
        ("source", "flask.request.args.get", 10),
        ("assignment", "name", 10),
        ("concatenation", "+", 12),
        ("concatenation", "+", 12),
        ("assignment", "query", 12),
        ("sink", "sqlite3.Connection.execute", 13),
    ]
    assert finding.evidence.source.start_column == 12
    assert finding.evidence.source.end_column == 40
    assert finding.evidence.sink.start_column == 5
    assert any("Flask request context" in note for note in finding.evidence.uncertainties)
    bound = analyze((FLASK_FIXTURES / "parameterized.py").read_text())
    assert bound.findings == bound.diagnostics == []


def test_flask_subscription_uses_exact_utf8_byte_span_with_separate_imports() -> None:
    code = (FLASK_FIXTURES / "concatenated.py").read_text()
    code = (
        code.replace(
            "from flask import Flask, request", "from flask import Flask\nfrom flask import request"
        )
        .replace("Flask(__name__)", 'Flask("example")')
        .replace("@app.get", "@app.route")
        .replace('name = request.args.get("name", "")', 'café = request.args["é"]')
        .replace("+ name +", "+ café +")
    )
    (finding,) = analyze(code).findings
    source = finding.evidence.flow[0]
    assert source.symbol == "flask.request.args"
    where = source.location
    line = code.splitlines()[where.start_line - 1].encode()
    assert line[where.start_column - 1 : where.end_column - 1].decode() == 'request.args["é"]'


def test_exact_request_import_with_one_get_argument_in_undecorated_function() -> None:
    analysis = analyze(
        dedent("""\
        from flask import request
        import sqlite3

        def lookup():
            db = sqlite3.connect(":memory:")
            value = request.args.get("table")
            db.execute("SELECT " + value)
        """)
    )
    assert not analysis.diagnostics
    assert len(analysis.findings) == 1


@pytest.mark.parametrize("lookup", ['request.args.get("table")', 'request.args["table"]'])
def test_direct_module_lookup_has_no_modeled_flask_request_context(lookup: str) -> None:
    code = "from flask import request\n" + SETUP + f'db.execute("SELECT " + {lookup})'
    analysis = analyze(code)
    assert analysis.findings == []
    assert [item.code for item in analysis.diagnostics] == ["UNSUPPORTED_FLOW"]


@pytest.mark.parametrize(
    "modify",
    [
        'request.args.get("name", type=int)',
        'request.args.get("name", 42)',
        'request.args.get("name", default="")',
        "request.args.get(key)",
        'request.args.get("name", "", "")',
        "request.args.get()",
        'request.args["name",]',
        'request.args["name", "other"]',
        "request.args[key]",
        'request.form.get("name", "")',
        'other.request.args.get("name", "")',
        'flask.request.args.get("name", "")',
    ],
)
def test_unmodeled_request_lookups_do_not_create_evidence(modify: str) -> None:
    code = (FLASK_FIXTURES / "concatenated.py").read_text()
    code = code.replace('request.args.get("name", "")', modify)
    analysis = analyze(code)
    assert analysis.findings == []
    assert [item.code for item in analysis.diagnostics] == ["UNSUPPORTED_FLOW"]


@pytest.mark.parametrize(
    ("old", "replacement"),
    [
        ("def lookup():", "def lookup(request):"),
        ("def lookup():", "def lookup(*, request):"),
        ('    return "done"', '    request = "replacement"'),
        ('    return "done"', '    ｒｅｑｕｅｓｔ = "replacement"'),
        ('    return "done"', "    from example import request"),
        ("app = Flask(__name__)", 'request = "replacement"\napp = Flask(__name__)'),
        ("app = Flask(__name__)", "Flask = custom\napp = Flask(__name__)"),
        ("app = Flask(__name__)", "def Flask(): pass\napp = Flask(__name__)"),
        ("def lookup():", "def request():"),
    ],
)
def test_flask_import_bindings_cannot_be_shadowed(old: str, replacement: str) -> None:
    code = (FLASK_FIXTURES / "concatenated.py").read_text()
    analysis = analyze(code.replace(old, replacement))
    assert analysis.findings == []
    assert [item.code for item in analysis.diagnostics] == ["UNRESOLVED_BINDING"]


@pytest.mark.parametrize(
    ("old", "replacement"),
    [
        ("from flask import Flask, request", "from helper import Flask, request"),
        ("from flask import Flask, request", "from .flask import Flask, request"),
        ("from flask import Flask, request", "from flask import Flask, request as req"),
        ("from flask import Flask, request", "from flask import Flask, request, session"),
        ("from flask import Flask, request", "from flask import Flask, Flask, request"),
        ("app = Flask(__name__)", "app = Flask()"),
        ("app = Flask(__name__)", "app = Flask(__name__, option=True)"),
        ("app = Flask(__name__)", 'app = Flask(__name__)\napp = "replacement"'),
        ("app = Flask(__name__)", "app = Flask(__name__)\nother = app"),
        ('@app.get("/tables")', '@app.post("/tables")'),
        ('@app.get("/tables")', "@app.route(variable)"),
        ('@app.get("/tables")', '@app.route("/tables", methods=["GET"])'),
        ('@app.get("/tables")', '@app.get("/tables")\n@other'),
        ('@app.get("/tables")', "@app"),
        ('@app.get("/tables")', '@"literal"'),
        ('@app.get("/tables")', '@other("/tables")'),
        ('@app.get("/tables")', '@app.get("/tables")\ndef unrelated(): pass\n@app.get()'),
    ],
)
def test_only_direct_flask_initialization_and_routes_are_analyzed(
    old: str, replacement: str
) -> None:
    code = (FLASK_FIXTURES / "concatenated.py").read_text()
    code = code.replace(old, replacement)
    if "other = app" in code:
        code = code.replace("@app.get", "@other.get")
    analysis = analyze(code)
    assert analysis.findings == []
    assert [item.code for item in analysis.diagnostics] == ["UNSUPPORTED_FLOW"]


def test_assignment_to_request_args_stops_analysis() -> None:
    code = (FLASK_FIXTURES / "concatenated.py").read_text()
    code = code.replace("def lookup():", 'def lookup():\n    request.args = "replacement"')
    analysis = analyze(code)
    assert analysis.findings == []
    assert [item.code for item in analysis.diagnostics] == ["UNSUPPORTED_FLOW"]


def test_request_name_is_not_reserved_without_flask_import() -> None:
    code = (FIXTURES / "concatenated.py").read_text()
    analysis = analyze(code.replace("lookup()", "lookup(request, Flask)"))
    assert len(analysis.findings) == 1
    assert not analysis.diagnostics
