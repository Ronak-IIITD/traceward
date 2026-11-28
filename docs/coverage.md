# Capability registry, scanner 0.1.0

| Language | Parse support | CWE-89 detection | Other planned CWEs | Maturity |
|---|---|---|---|---|
| Java | Tree-sitter Java 0.23.5 | Method-local servlet input to JDBC concatenation, including simple conditionals and try-with-resources | Unsupported | Experimental |
| Python | Tree-sitter Python 0.25.0 | Built-in input and Flask query parameters through string concatenation or supported f-strings to a SQLite connection or cursor execute call | Unsupported | Experimental |
| JavaScript | Tree-sitter JavaScript 0.25.0 | Node.js command-line input through string concatenation or supported untagged templates to `node:sqlite` `DatabaseSync.prepare` or `exec` | Unsupported | Experimental |
| TypeScript | Tree-sitter TypeScript/TSX 0.23.2 | Same Node.js SQLite model with simple typed bindings | Unsupported | Experimental |
| Go, C, C++ | Not implemented | Unsupported | Unsupported | Planned |

Rules `java.sql.concatenated-untrusted-input` (0.3.0),
`python.sqlite.concatenated-input` (0.3.0),
`javascript.sqlite.concatenated-argv` (0.2.0) and
`typescript.sqlite.concatenated-argv` (0.2.0) report
`heuristic_candidate`, high severity, medium confidence. All scans are partial.
Production promotion requires independent real-world evaluation. See README
for the modeled methods and unsupported semantics. Live scans use static rules.

Interpolation requires known string expressions. Python conversions, format
specifications and debug fields, tagged templates, and non-string or unresolved
substitutions produce diagnostics. Nested interpolation shares the existing
expression-depth and evidence budgets. Evidence follows one witnessed input
through string assembly; it does not combine independent source paths. These
extensions remain experimental pending independent evaluation of interpolation
cases, including parameter binding and framework-specific template tags.

The mixed-project regression suite runs on every PR. It exercises the installed
CLI against one synthetic checkout with paired Java, Python, Flask, JavaScript,
and TypeScript cases. It checks binding and comment hard negatives, excluded
paths, malformed inputs, and reproducible JSON/SARIF finding identity and evidence.
Run it with `uv run --locked --extra api pytest packages/traceward-core/tests/test_project_scan.py`.

For a repo-level review, scan a local checkout you are authorized to inspect.
Pick a reviewed parameterized query and a known finding within the documented
rule scope. Compare the reported source, sink, and line numbers with the checked-out revision.

Fixture results must not be described as real-world precision or recall. The
research paper's synthetic macro-F1 is not a scanner performance measurement.

Three pinned CPython documentation examples parsed successfully. Each reached an
unsupported statement or binding. The [Python SQLite compatibility check](evaluation/python-sqlite.md)
records the source hashes, diagnostics and a plan for evaluating accuracy.

Two pinned Node.js examples exercised the JavaScript grammar. The scanner
followed positional bindings in the basic example and reported unsupported calls
in both examples. The [Node.js SQLite compatibility check](evaluation/node-sqlite.md)
records the source hashes, diagnostics and the evaluation plan for both languages.

The Flask quickstart query expression parsed in a minimal route. The tutorial
blueprint stopped at an unsupported import. The [Flask SQLite compatibility check](evaluation/flask-sqlite.md)
records both outcomes, their source hashes and the evaluation plan.

The [OWASP BenchmarkPython baseline](evaluation/owasp-python-cwe89.md) measured
0/5 recall on synthetic CWE-89 cases. All 16 files reported an unsupported
statement before analysis reached their SQL paths.
