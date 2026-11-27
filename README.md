# TraceWard

**Trace the risk. Secure the code.**

TraceWard scans Java, Python, JavaScript and TypeScript locally for selected SQL
injection paths (CWE-89). Each finding links input, query construction and a database call to
locations in the source. The CLI and snippet API share a versioned JSON contract.
Scans run offline and submitted code is never executed.

## Open the dashboard

From the repository root, run:

```sh
./start.sh
```

Open <http://127.0.0.1:3000>, choose a language, and select **Try the vulnerable
example**. Select a finding or trace step to highlight its source in the editor.
Open **Suggested fix** for a copyable parameterized query. Use **Ctrl+Enter**
(**Cmd+Enter** on macOS) to scan your own code. Load **Parameterized** to see the
clean result for the selected rule. The dashboard includes diagnostics, coverage
details, and JSON copy and export. Stop both local servers with Ctrl+C.
The launch script installs the locked API and web dependencies as needed.
It requires uv, Node.js 22 or later, and [Bun](https://bun.com/) 1.4.4 or later.
The dashboard toolchain is verified on Linux x64.

### Local pre-push checks

Enable this repository's hooks once per clone with `git config --local core.hooksPath .githooks`.
The pre-push hook checks the revisions being pushed. It checks formatting and lint
on changed source files, then checks types across the affected Python or web project.
The hook uses locked dependencies and tsrs for web types. GitHub still runs the full suite.

## Run locally

Install [uv](https://docs.astral.sh/uv/), then from this directory:

```sh
uv sync --locked --python 3.12
uv run traceward --version
uv run traceward doctor
uv run traceward scan fixtures/javascript/concatenated.js
# Expected exit 1: a candidate at the SQLite prepare call.
uv run traceward scan fixtures/typescript/parameterized.ts
# Expected exit 0: the prepared statement binds the argument separately.
uv run traceward rules list --language python
uv run traceward scan fixtures/python/concatenated.py
# Expected exit 1: one candidate at the SQLite execute call on line 8.
uv run traceward scan fixtures/python/parameterized.py
# Expected exit 0: the constant query binds the value separately.
uv run traceward rules list --language java
uv run traceward scan fixtures/java/Vulnerable.java
# Expected exit 1: one experimental CWE-89 candidate at line 8.
uv run traceward scan fixtures/java/Safe.java
# Expected exit 0: no supported findings; coverage remains partial.
uv run traceward scan fixtures/java --format json --output traceward-results.json
```

The initial supported OS is Linux. Python 3.11–3.14 is supported by the package;
the test suite runs on all four versions in CI.
The Java source need not compile or have
dependencies installed, but must be syntactically valid Java (wrap a bare snippet
in a class and method). No Java runtime is required.

```python
from pathlib import Path
from traceward.scanner import scan_path, scan_snippet

result = scan_path(Path("fixtures/java"))
print(result.model_dump_json(indent=2))
```

`scan_snippet(source, language="typescript")` analyzes source in memory. The
default language is Java. Directory scans identify language by extension.
Use `--language java`, `python`, `javascript` or `typescript` to narrow the scan.
JavaScript extensions are `.js`, `.jsx` and `.mjs`. TypeScript extensions are
`.ts`, `.tsx` and `.mts`. Production ML inference is disabled. Repository
download remains on the roadmap.

## Local snippet API

Start the optional FastAPI service on Linux, then open its interactive documentation
at <http://127.0.0.1:8000/docs>.

```sh
uv run --locked --extra api uvicorn traceward_api.app:app --host 127.0.0.1 --port 8000 --no-access-log
```

In another terminal, send the same fixture through the API.

```sh
uv run python -c 'import json, pathlib; print(json.dumps({"language":"java","code":pathlib.Path("fixtures/java/Vulnerable.java").read_text()}))' |
  curl --fail-with-body -sS -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8000/api/v1/scans/snippet
```

The response includes one finding at line 8 of `snippet.java`. Syntax errors appear
in the scan's diagnostics with HTTP 200. Invalid submissions receive a structured
HTTP error with a request ID. The service accepts 64 KiB of UTF-8 source and up to
256 KiB of JSON per request, with two simultaneous submissions per server process.
Each scan runs in a disposable subprocess with CPU, memory and wall-time limits.
The API accepts at most 2 MiB of worker output. When its HTTP client
disconnects, it stops and reaps the worker before releasing the scan slot.
Scan responses include
`Cache-Control: no-store`, and the service keeps source and results in memory for
the request. Health, version, capabilities and model status are available under
`/api/v1/`.

## Detection and limits

The experimental **Java** rule recognizes `HttpServletRequest` / `ServletRequest`
`getParameter` and `getHeader` sources, local declarations, assignments, `+`, `+=`,
parentheses, and aliases of **values** inside a method. Sinks are
explicitly typed `Statement.executeQuery/executeUpdate/execute/addBatch` and
`Connection.prepareStatement/prepareCall`. A tainted concatenated query at a
recognized sink raises a high-severity, medium-confidence `heuristic_candidate`.
Each finding includes source, assignments, concatenation, and sink locations.
Constant templates with `PreparedStatement` bindings do not trigger this rule;
concatenating untrusted input before `prepareStatement` can still trigger it.

Java types are syntactic hints: imports, inheritance, dispatch, aliases of API
receivers, fields, framework wrappers, string builders, sanitizers and calls across
methods are unresolved. The rule follows nested blocks and the normal path through try-with-resources
initializers and bodies. It recognizes explicitly declared JDBC resources and
previously declared resource variables. To try both JDBC cases locally, run
`.venv/bin/traceward scan fixtures/jdbc-resources`. The query in `ResourceQuery.java`
produces one candidate at line 10. The bound parameter example produces zero.

Simple `if` conditions support boolean literals, explicitly typed boolean local variables
and parameters, and parentheses around them. The scanner visits only the reachable arm for a
known condition and analyzes unknown conditions with separate local values in each arm.
When both arms continue, differing tainted values are dropped with a
`BRANCH_VALUE_DIVERGENCE` diagnostic. If one arm returns or throws, the continuing arm's
values carry forward. Try `.venv/bin/traceward scan fixtures/java-conditionals` to compare
a finding inside a branch with an example whose input and JDBC call are in opposite branches.

Complex conditions, loops, plain `try` statements, and exception handlers stop analysis
on the affected path with a diagnostic. Resource closure and exceptional paths are outside
the model. Unknown expression
and call propagation is reported where tainted arguments are observed. No complete
control-flow or symbol graph is claimed. Dead comments and unused strings are not
SQL evidence. Methods are analyzed regardless of whole-program reachability.

The experimental **Python** rule follows built-in `input()` and selected Flask
query parameters through local assignments and string `+` into `execute()`
on a local SQLite connection or cursor. The adapter models an unaliased
`import sqlite3` and a connection created with `sqlite3.connect("literal database name")`
in the same straight-line scope as the sink. Cursors created with `db.cursor()`
in that scope also work.

For Flask, the scanner resolves a module-level `from flask import request` and
tracks `request.args["key"]` and `request.args.get("key")` inside a top-level
function, including a positional string default. It recognizes a single `@app.get("/path")` or
`@app.route("/path")` on a function when the module constructs that app with
`Flask(__name__)` or a literal string. Other request attributes, typed conversion,
f-strings, branches and cross-function flow remain outside the rule. Consult the
diagnostics when an unsupported statement ends the modeled path. Flask itself
is unnecessary for scanning. [Flask request data](https://flask.palletsprojects.com/en/stable/quickstart/#accessing-request-data)

Scan `fixtures/flask-sqlite` for a comparison between a concatenated query
and a constant query that binds the same value separately.
[SQLite parameter binding guide](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).

The experimental **JavaScript and TypeScript** rules share a Node.js SQLite
model. They follow `process.argv[2]` and later literal indexes through top-level
`const` bindings and string `+` into `prepare()` or `exec()` on a directly
constructed `DatabaseSync` from a named `node:sqlite` import. Constant prepared
queries can bind positional values separately. Check the diagnostics when an
unsupported statement ends the modeled path. Coverage is limited to straight-line
module code, with web request sources, CommonJS, receiver aliases, functions, and
template interpolation outside this slice. [Node.js SQLite reference](https://nodejs.org/download/release/v24.11.1/docs/api/sqlite.html)

All results declare **partial coverage**. No supported findings does not certify
security. Coverage outside the documented CWE-89 cases remains on the roadmap.
No rule is externally validated or ready for production assurance.

Discovery skips `.git`, `.next`, `.venv`, `venv`, `__pycache__`, `node_modules`, `vendor`, `dist`, `build`, and
`target`; `--exclude 'relative/glob/*'` adds repeatable root-relative exclusions.
Symlinks are skipped. Inputs are bounded to 2 MiB per file, 20 MiB total, 2,000
source files, 20,000 discovered entries, a 120-second scan budget, a 500 ms native
parse budget per file and 100,000 AST nodes. The Java adapter also caps analysis at
32 nested scope levels, 64 visited conditionals per method and 128 expression levels. Skips and limits produce diagnostics. These are initial engineering caps, not benchmarked
service guarantees. Discovery is designed for local trees, not hostile concurrently
mutating filesystems. ZIP uploads and public hosting are not implemented.

## CLI policy and result contract

Exit codes: `0` no policy-violating findings, `1` findings meet policy, `2` invalid
input or analysis error, `3` partial scan with `--fail-on-partial`. Errors take
precedence over strict partial coverage, then findings. Default policy is
`--fail-on high --min-confidence medium`. `--fail-on none` disables finding-based
failure. Confidence controls exit policy, not report visibility. `--min-confidence
high` does not fail on the current medium-confidence candidates. YAML configuration
is not loaded yet; supported options are listed by `traceward scan --help`.

[JSON Schema](schemas/scan-result.schema.json) is generated from Pydantic models.
Paths are relative to the scanned directory (a file scan uses its basename).
Lines and columns are one-based; columns count **UTF-8 bytes** and end positions
are exclusive, matching Tree-sitter. Consumers must convert byte columns for
UTF-16 editors. Java fingerprints hash rule, relative path, method signature, sink text
and duplicate occurrence; identical inputs under different roots produce the
same findings. Scan IDs and timings are intentionally volatile. Editing sink or
method text can change fingerprints; no semantic baseline matching is promised.
Evidence stores locations and symbol names, not copied SQL or request values.

## SARIF export

```sh
uv run --locked traceward scan fixtures/java --format sarif --output traceward.sarif
```

SARIF 2.1.0 includes rule metadata, stable TraceWard fingerprints, the source-to-sink
trace, scan diagnostics and coverage. Findings appear as SARIF warnings, with TraceWard
severity, confidence and evidence level recorded separately. Locations use whole lines.
JSON retains the exact UTF-8 byte columns. The CLI applies the same exit codes in all
formats. Use `--fail-on none` for an informational check that still fails on scan errors.

Paths are relative to the scan root. For GitHub code scanning, run from the checkout
and scan `.` so paths match the repository. The package CI job publishes a sample
SARIF artifact after validation against the checksum-pinned OASIS schema. Uploading
alerts requires GitHub code scanning access for the target repository.
See [GitHub's SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## CI and release delivery

GitHub Actions runs on pull requests, pushes, manual dispatches and a weekly schedule.
Every supported Linux Python version (3.11 through 3.14) runs the core and API tests.
Each version must reach 90% combined line and branch coverage, including subprocesses.
JUnit and coverage XML reports are available as workflow artifacts for 14 days.
Separate jobs validate the workflow, check formatting and types, audit locked dependencies,
and install the wheel and source archive in fresh environments for CLI and HTTP smoke tests.
Those installs must agree on findings, coverage, and parse diagnostics. The HTTP checks
also verify that malformed and oversized submissions return structured errors without
echoing submitted code and that scan responses prohibit caching.

A pushed tag matching the package version, such as `v0.1.0`, stages a **draft GitHub
Release** after all jobs pass. The draft contains the tested wheel, source archive,
and SHA-256 checksums. A maintainer reviews the draft and the project's distribution
permissions before publication. Re-running a tag workflow can refresh a draft's assets.
The release job rejects changes to an already published release.

## Verify

```sh
uv run --locked --extra api coverage erase
uv run --locked --extra api coverage run -m pytest -q
uv run --locked --extra api coverage report
uv audit --locked
uv run ruff check .
uv run ruff format --check .
uv run --extra api mypy packages/traceward-core/src services/api/traceward_api
uv build
```

Tests check vulnerable/safe fixtures, parser and Unicode byte spans, scope
isolation, branch limitations, reproducibility, committed schema consistency,
discovery, symlink/FIFO handling, size limits and installed CLI behavior. These
fixtures are regression tests, not independent accuracy measurements.

See [implementation status](docs/status.md), [coverage](docs/coverage.md),
[security policy](SECURITY.md), and [contribution notes](CONTRIBUTING.md).

## Offline ML research

The [Juliet Java CWE-89 workflow](docs/evaluation/juliet-java-cwe89.md) verifies
the official NIST archive, prepares a family-disjoint method corpus and trains
four offline baselines with reproducible JSON artifacts.

## Ownership and distribution

TraceWard is an independent solo-developed project. The earlier benchmark
description is unverified historical reference material. The implementation and
experiments here use their own versioned source and recorded corpus provenance.
External data attribution and upstream license information are recorded in
docs/evaluation/data-sources.md. A distribution license for TraceWard remains an
owner decision before publication.
