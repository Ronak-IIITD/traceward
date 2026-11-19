# Implementation status

## Delivered: initial M1A scanner

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
4. M1B: FastAPI, bounded isolated snippet workers, API abuse protection, Next.js
   workspace, browser verification and local Docker deployment.
5. Review licensing/ownership, distribution permissions and full P0 acceptance.

The complete M1 definition of done has **not** been met. Do not claim seven-language
support, ML inference, independent accuracy, API/UI parity or deployed-demo safety.

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
