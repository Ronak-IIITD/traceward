# TraceWard

**Trace the risk. Secure the code.**

An experimental, local-first Java source scanner. This repository implements the
first scanner milestone (M1A) from [the PRD](TraceWard_PRD_v1.0.md), with a narrow
method-local CWE-89 rule, actual source-to-sink evidence, an installable Python CLI,
and a versioned JSON contract. It never executes scanned code or installs project
dependencies. Scans need no network connection.

## Open the dashboard

From the repository root, run:

```sh
./start.sh
```

Open <http://127.0.0.1:3000>. Load the vulnerable example, select **Scan Java**, then
select the sink in the evidence trace to highlight its source span. The parameterized
example demonstrates a result with no supported findings. The dashboard includes
parse diagnostics, current limitations, and JSON export. Stop both local servers
with Ctrl+C. The launch script installs the locked API and web dependencies as needed.
It requires uv and Node.js 22 or later with npm.

## Run locally

Install [uv](https://docs.astral.sh/uv/), then from this directory:

```sh
uv sync --locked --python 3.12
uv run traceward --version
uv run traceward doctor
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

`scan_snippet(java_source)` analyzes a UTF-8 string in memory with the same contract.
Only Java is enabled. No model is loaded and no metric is inferred from the source
research. The browser dashboard and offline research training harness are available. Repository download and SARIF remain on the roadmap.

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
The service keeps source and results in memory for the request. Health, version,
capabilities and model status are available under `/api/v1/`.

## Detection and limits

The experimental rule recognizes `HttpServletRequest` / `ServletRequest`
`getParameter` and `getHeader` sources, local declarations, assignments, `+`, `+=`,
parentheses, and aliases of **values** inside a straight-line method. Sinks are
explicitly typed `Statement.executeQuery/executeUpdate/execute/addBatch` and
`Connection.prepareStatement/prepareCall`. A tainted concatenated query at a
recognized sink raises a high-severity, medium-confidence `heuristic_candidate`.
Each finding includes source, assignments, concatenation, and sink locations.
Constant templates with `PreparedStatement` bindings do not trigger this rule;
concatenating untrusted input before `prepareStatement` can still trigger it.

Java types are syntactic hints: imports, inheritance, dispatch, aliases of API
receivers, fields, framework wrappers, string builders, sanitizers and calls across
methods are unresolved. Control flow (including `try`, loops and nested scopes)
causes the rest of that method to be skipped with a diagnostic. Unknown expression
and call propagation is reported where tainted arguments are observed. No complete
control-flow or symbol graph is claimed. Dead comments and unused strings are not
SQL evidence. Methods are analyzed regardless of whole-program reachability.

All results declare **partial coverage**. No supported findings does not certify
security. Other languages and the other 11 planned CWEs have no detectors.
No rule is externally validated or ready for production assurance.

Discovery skips `.git`, `.venv`, `node_modules`, `vendor`, `dist`, `build`, and
`target`; `--exclude 'relative/glob/*'` adds repeatable root-relative exclusions.
Symlinks are skipped. Inputs are bounded to 2 MiB per file, 20 MiB total, 2,000
source files, 20,000 discovered entries, a 120-second scan budget, a 500 ms native
parse budget per file, 100,000 AST nodes and 128 expression levels. Skips and
limits produce diagnostics. These are initial engineering caps, not benchmarked
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
UTF-16 editors. Fingerprints hash rule, relative path, method signature, sink text
and duplicate occurrence; identical inputs under different roots produce the
same findings. Scan IDs and timings are intentionally volatile. Editing sink or
method text can change fingerprints; no semantic baseline matching is promised.
Evidence stores locations and symbol names, not copied SQL or request values.

## CI and release delivery

GitHub Actions runs on pull requests, pushes, manual dispatches and a weekly schedule.
Every supported Linux Python version (3.11 through 3.14) runs the core and API tests.
Each version must reach 90% combined line and branch coverage, including subprocesses.
JUnit and coverage XML reports are available as workflow artifacts for 14 days.
Separate jobs validate the workflow, check formatting and types, audit locked dependencies,
and install the wheel and source archive in fresh environments for CLI and HTTP smoke tests.

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
