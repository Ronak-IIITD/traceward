# Implementation status

## Initial backlog checkpoint

**12 of the 20 implementation issues in PRD section 26 are complete (60%).**
Each issue counts once. This measures the initial backlog. Effort estimates and
production readiness are tracked separately.

| Completed issue | Verified behavior |
|---|---|
| 1 · Tooling | Locked install, lint, type checks, tests and CI configuration |
| 3 · Java parser | Syntax diagnostics and UTF-8 byte spans |
| 4 · Fixtures | Vulnerable sink at line 8 and parameterized safe control |
| 5 · Discovery | Relative exclusions, traversal limits and symlink handling |
| 6 · Analysis records | Method, call site, flow node and validated source-to-sink trace |
| 7 · Extraction | Method and invocation collection with source locations |
| 8 · Rule registry | Packaged versioned manifest with unique IDs and field validation |
| 9 · SQL detection | Concatenated servlet input reported at supported JDBC sinks |
| 10 · Local flow | Straight-line assignments and diagnostics for unsupported flow |
| 11 · Reports | Versioned schema and reproducible finding fingerprints |
| 12 · CLI | Installed scan, rules and doctor commands, text/JSON and policy exits |
| 17 · Snippet API | Strict request validation, byte limits, worker isolation and CLI parity |

Eight issues remain open. Issue 2 awaits distribution and reporting decisions.
Issues 13–16 cover corpus reproduction, training, artifacts and optional inference.
Issues 18–20 cover the dashboard, full browser/API/CLI acceptance suite, benchmark
methodology and release checklist. Partial work on these issues earns no credit.

## Delivered scanner

- Installable `traceward-core`, pinned uv environment, CLI and typed result model.
- Tree-sitter Java parser, byte spans, method and call extraction.
- One experimental CWE-89 rule with limited local propagation and safe controls.
- Bounded file discovery, JSON/text reports, deterministic finding fingerprints.
- Regression suite, lint, strict type check, schema and CI workflow.

## Remaining release work

1. M0: acquire and verify rights to the original corpus; build audited split
   manifests and independently reproduce RF, SVM and XGBoost experiments. No data
   or artifacts were supplied, so nothing has been trained or measured.
2. M1A: broaden Java semantic models only with fixtures; implement a trusted,
   versioned optional classifier adapter after artifact/feature contracts exist.
3. Evaluate on independent repositories, publish precision/recall and false
   positives, and review evidence before promoting any rule.
4. M1B: Next.js workspace, browser verification, deployment controls and local Docker deployment.
5. Review licensing/ownership, distribution permissions and full P0 acceptance.

The complete M1 definition of done has **not** been met. Do not claim seven-language
support, ML inference, independent accuracy, web UI parity or deployed-demo safety.

## Initial architecture decisions

- Python 3.11–3.14, uv packaging at repository root, incremental package layout.
- Tree-sitter and Java grammar pinned independently in `uv.lock`.
- Pydantic result contract; core imports no web framework.
- No model loaded: original research material is absent and validation pending.
- Always partial; syntactic API matching yields heuristic candidates, not
  validated `static_supported` findings.
- Keep the pinned parser's native timeout despite its deprecated API; a future
  service must additionally use isolated processes and OS resource limits.
- No database, persistence, outbound model requests, build execution or telemetry.
