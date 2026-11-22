# Capability registry, scanner 0.1.0

| Language | Parse support | CWE-89 detection | Other planned CWEs | Maturity |
|---|---|---|---|---|
| Java | Tree-sitter Java 0.23.5 | Method-local servlet input to JDBC concatenation, including simple conditionals and try-with-resources | Unsupported | Experimental |
| Python | Tree-sitter Python 0.25.0 | Built-in input and Flask query parameters through string concatenation to a SQLite connection or cursor execute call | Unsupported | Experimental |
| JavaScript | Tree-sitter JavaScript 0.25.0 | Node.js command-line input through string concatenation to `node:sqlite` `DatabaseSync.prepare` or `exec` | Unsupported | Experimental |
| TypeScript | Tree-sitter TypeScript/TSX 0.23.2 | Same Node.js SQLite model with simple typed bindings | Unsupported | Experimental |
| Go, C, C++ | Not implemented | Unsupported | Unsupported | Planned |

Rules `java.sql.concatenated-untrusted-input` (0.3.0),
`python.sqlite.concatenated-input` (0.2.0),
`javascript.sqlite.concatenated-argv` (0.1.0) and
`typescript.sqlite.concatenated-argv` (0.1.0) report
`heuristic_candidate`, high severity, medium confidence. There is no independent
external evaluation or production promotion. All scans are partial. See README
for exact modeled methods and unsupported semantics. No ML models are enabled.

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
