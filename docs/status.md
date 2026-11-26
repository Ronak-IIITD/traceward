# Implementation status

## Verified capabilities

Progress is tracked through working features and release gates. The previous
60% number counted initial issues equally and did not measure product completion.

- Java, Python, JavaScript and TypeScript CLI scans with JSON and SARIF 2.1.0 reports.
- Bounded FastAPI snippet endpoint and CLI/API parity. Disconnected clients
  release scan slots after worker cleanup, and scan responses prohibit caching.
- Next.js scan workspace with evidence selection, diagnostics and JSON export.
- Offline SVM, Random Forest and XGBoost research harness, safe JSON SVM inference,
  provenance checks, train-only TF-IDF and repository-family split validation.
- CVE-linked MegaVul acquisition pipeline and exploratory measured baseline.
- Python matrix, audit, package, ML and browser checks in CI.

## Remaining release gates

- Independent manual review of corpus labels, hard negatives and an untouched
  holdout for detector/model promotion. Current ML recall is insufficient.
- Production model inference and hybrid prioritization.
- Public deployment isolation and abuse controls, distribution-license decision
  and release acceptance review.
- Roadmap work includes additional languages, expanded CWE coverage,
  bounded repository fetching and interprocedural analysis.

## Delivered scanner

- Installable `traceward-core`, pinned uv environment, CLI and typed result model.
- Tree-sitter Java, Python, JavaScript and TypeScript parsers with UTF-8 byte spans.
- Experimental CWE-89 rules for Java servlet/JDBC, Python console and Flask/SQLite, and Node.js command-line SQLite flows.
- Bounded file discovery, JSON/text reports, deterministic finding fingerprints.
- Regression suite, lint, strict type check, schema and CI workflow.

## Initial architecture decisions

- Python 3.11–3.14, uv packaging at repository root, incremental package layout.
- Tree-sitter and grammar packages pinned independently in `uv.lock`.
- Pydantic result contract; core imports no web framework.
- Models run through the offline research CLI; production promotion is pending evaluation.
- Always partial; syntactic API matching yields heuristic candidates, not
  validated `static_supported` findings.
- Keep the pinned parser's native timeout despite its deprecated API; a future
  service must additionally use isolated processes and OS resource limits.
- No database, persistence, outbound model requests, build execution or telemetry.
