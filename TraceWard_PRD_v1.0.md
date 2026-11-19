# TraceWard — Product Requirements Document (PRD)

> **Trace the risk. Secure the code.**

| Field | Value |
|---|---|
| Product | TraceWard |
| Version | 1.0 — proposed specification |
| Document date | 19 November 2026 |
| Product category | Developer-first, hybrid static analysis and ML-assisted application security testing (SAST) |
| Delivery channels | Python CLI, web dashboard, REST API, GitHub Actions / SARIF, future VS Code extension |
| Implementation approach | Python-first modular monolith; TypeScript/Next.js UI; no Rust dependency |
| Target languages | Java, Python, JavaScript, TypeScript, Go, C, C++ |
| Planned vulnerability taxonomy | 12 CWE categories; capabilities differ by language and release |
| Model research track | 8 candidate ML model families; only independently validated models are enabled for production findings |
| Status | Design proposal; not a description of implemented features |

**Attribution and baseline:** TraceWard is a proposed independent product inspired by the Group 38 TCOM research project *Efficient Machine Learning Models for Automated Source Code Vulnerability Classification*. The research assessed Java SQL-injection detection with Random Forest, Linear SVM, and XGBoost. Retain attribution and verify team ownership and dataset/model reuse rights before publishing shared work. The paper's reported 1.000 macro-F1 on 64 synthetic test examples is **not** a real-world detection guarantee.

---

## 1. Executive summary

TraceWard is a developer-focused source-code security analysis platform combining **language-aware parsing**, **deterministic vulnerability rules**, **source-to-sink data-flow analysis**, and **machine-learning classifiers**. It helps developers identify *potential* weaknesses, see the supporting evidence, and prioritize code review. A single scanner engine powers the CLI, API, dashboard, and CI workflows. The platform will support seven languages over phased releases; the initial minimum viable product (MVP) supports Java and a small, well-evaluated set of CWE patterns.

The differentiator is not the number of models. It is a **transparent hybrid detection process**: deterministic evidence when possible, ML signals to prioritize or discover candidates, and explicit reporting of where analysis is incomplete. A finding may be *confirmed by supported static evidence*, *ML-suspected*, or *needs manual review*; none is a proof that a complete application is exploitable. Never imply that a clean scan certifies safety.

### Product north star

> A developer can point TraceWard at a project and quickly learn *what may be vulnerable, where the risky flow occurs, why the analyzer raised the finding, how to investigate or remediate it, and what coverage limitations remain*.

### Scope distinction

- **Product vision:** seven languages, twelve CWE categories, model research lab, repository scans, PR checks, dashboard, and optional IDE support.
- **MVP promise:** Java scanning with a reproducible analysis pipeline and evidence-backed findings, CLI, JSON output, FastAPI, basic dashboard, transparent benchmark reporting.
- **Explicitly not promised:** exploit proof, full interprocedural soundness, reliable detection of every weakness in every language, autonomous code patches, or guaranteed vulnerability absence.

## 2. Problem statement

Developers struggle to identify vulnerabilities early, especially when tainted data crosses several statements or functions. Traditional static rules can be precise for known idioms but miss unfamiliar patterns, whereas ML classifiers can flag suspicious code without proving exploitability and can generalize poorly to unseen repositories. Enterprise analysis tools may have steep setup or complex reporting flows. TraceWard addresses the gap for smaller projects and research teams with a **reproducible, explainable, locally runnable scanner**.

### User pain points

1. A developer needs security feedback before merging a change.
2. Findings without exact source locations, evidence, or remediation guidance are hard to act upon.
3. ML benchmark scores often fail to represent real-repository performance or false-positive burden.
4. A research scanner is difficult to use outside a notebook.
5. Multi-language repositories require consistent result formats without erasing language-specific semantics.

### Opportunity

Bring a compiler-inspired analysis pipeline and a rigorously evaluated ML research layer into one coherent developer tool, prioritizing **trustworthy evidence and workflow integration** over broad, unsupported marketing claims.

## 3. Users and jobs to be done

| Persona | Primary job | Main outcome |
|---|---|---|
| Solo Java developer | Scan a file or project | Explainable findings and a suggested review path |
| Full-stack developer | Scan mixed-language code | Unified dashboard with language-specific coverage |
| Open-source maintainer | Check pull requests | Stable, actionable annotations; avoid regressions |
| AppSec reviewer | Triage probable weaknesses | Evidence, severity, fingerprints, false-positive control |
| ML researcher/student | Reproduce and compare models | Held-out metrics, splits, latency, artifact provenance |

**Primary persona for MVP:** solo developer running TraceWard locally. This avoids premature SaaS complexity and reduces source-code privacy risks.

## 4. Goals, success metrics, and non-goals

### Product goals

G1. Provide deterministic, reproducible scans via `traceward scan <path>`.

G2. Produce useful code locations, classifications, and concise evidence for supported vulnerability patterns.

G3. Maintain a clear capability matrix by **language × CWE × detection technique × maturity**.

G4. Validate detection against external repositories and curated safe controls before claiming production readiness.

G5. Offer identical core findings through CLI, API, web, and SARIF.

G6. Preserve user source-code privacy and safely handle untrusted uploads/repositories.

### Proposed success measures (targets, not existing results)

| Metric | Initial target | Measurement |
|---|---|---|
| Basic CLI usable | 100% of smoke-test scenarios pass | Versioned test suite |
| Supported fixture correctness | ≥ 95% pass on maintained unit fixtures | Per-rule test suite |
| External validation precision | Aim ≥ 0.85 for release-gated, high-confidence finding classes | Separate reviewed repositories; per CWE/language |
| False-positive burden | Publish findings per 1,000 LOC and false-positive rate; improve each release | Independently reviewed holdout |
| Reproducibility | Identical inputs + tool/model versions give same findings | Golden-file CI |
| Security | Zero known critical issues in upload/archive and scan isolation tests | Adversarial test plan |
| End-to-end use | A contributor can clone, install, scan samples, and view a report from the README | Fresh-environment test |

**Metric caution:** Accuracy targets are not allowed to mask poor recall. Report precision, recall, F1, PR-AUC (where suitable), false positives per KLOC, category-specific performance, and coverage separately. Performance budgets must be measured on explicitly stated hardware and repository sizes.

### Non-goals for v1

- Dynamic application exploitation, penetration testing, malware detection, or executing uploaded code.
- Replacing human security review, Semgrep, CodeQL, dependency scanners, or compiler diagnostics.
- Building a complete compiler for all seven languages.
- Guaranteeing all 12 CWE categories for every supported language.
- Training a proprietary foundation model from scratch.
- Automatically committing AI-generated security fixes without review.
- Running untrusted build scripts, dependency installation, test suites, package lifecycle hooks, or repository-defined workflows during analysis.

## 5. Brand, positioning, and product principles

**Name:** TraceWard  
**Tagline:** *Trace the risk. Secure the code.*  
**Positioning:** ML-assisted, evidence-first source-code security analysis built for developers and researchers.

**Principles:** evidence before labels; reproducibility before leaderboard scores; local-first privacy; honest coverage; controlled resource usage; interoperable outputs; modular language adapters; measured performance; accessible developer UX.

The name is proposed. Trademark, repository slug, and domain availability must be checked before any commercial launch.

## 6. Release boundaries and priorities

| Release | Languages | Detection | Interfaces | Maturity |
|---|---|---|---|---|
| **M0 — research reproduction** | Java | CWE-89 binary method classifier and rule baseline | Notebook + evaluation scripts | Research |
| **M1 — scanner MVP** | Java | CWE-89; selected command/path rules as experimental if tested | Python CLI + JSON + API + minimal web | First shipped release |
| **M2 — web-stack expansion** | Python, JS, TS + Java | Scoped injection / XSS / path / SSRF rules, per-language coverage | Dashboard + GitHub public-repo scanning + SARIF | Beta |
| **M3 — advanced analysis** | Prior four + Go | Interprocedural taint on chosen frameworks; calibrated ML evaluation | PR integration + Model Lab | Beta/validated subsets |
| **M4 — native-code research** | C, C++ + prior five | Memory-safety candidates with clear static-analysis limitations | Expanded CI + detailed reporting | Experimental until reviewed |
| **M5 — platform maturation** | Seven targets | Broader CWE coverage, stronger real-world evaluations | IDE extension, team features optional | Planned |

**Exit criteria before expanding:** evidence-backed results in the current release, stable schema, regression fixtures, privacy/security validation, and published false-positive analysis.

## 7. Language support and adapter specification

### Seven target languages

| Language | File types | Initial code contexts | Typical framework/API targets | Notes |
|---|---|---|---|---|
| Java | `.java` | methods, classes, calls | JDBC, servlets, Spring | First validated language |
| Python | `.py` | functions, calls, imports | Django, Flask, FastAPI, DB-API, subprocess | Distinguish escaped SQL parameters from string-building |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | functions, modules, promises | Express, DOM, Node.js | Server/client contexts differ |
| TypeScript | `.ts`, `.tsx` | functions, modules, typed call sites | Next.js, NestJS, Node | Type information may need a compiler service later |
| Go | `.go` | functions, packages, call sites | `database/sql`, `os/exec`, HTTP clients | Import and call resolution matter |
| C | `.c`, `.h` | functions, macros, pointer operations | libc, POSIX | Macro expansion and aliasing constrain precision |
| C++ | `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hxx` | functions, methods, templates | STL, native APIs | Templates, overloads and compile flags complicate full analysis |

**Architecture rule:** a Tree-sitter grammar establishes *parse support*, not *security detection support*. Detection status is recorded per combination. The platform may parse a language while declaring some CWE detectors unsupported.

### Language adapter interface

Each adapter implements `detect_files()`, `parse()`, `discover_units()`, `normalize_symbols()`, `extract_calls()`, `extract_sources()`, `extract_sinks()`, `extract_sanitizers()`, `build_local_flow()`, and `capabilities()` where applicable. Unsupported features return explicit diagnostics rather than empty successful results.

Each adapter carries a semantic version, grammar version, test fixtures, and supported rules list. Shared code may normalize syntax, but language-specific adapters control semantics, scope, escape handling, call resolution, and framework idioms.

## 8. Vulnerability taxonomy and evidence levels

### Twelve target CWE categories

| CWE | Weakness | Primary detection direction | Initial applicability |
|---|---|---|---|
| CWE-89 | SQL injection | Untrusted input → SQL query assembly → query execution, mitigations | Java first, then Python/JS/TS/Go |
| CWE-79 | Cross-site scripting | Untrusted input → browser HTML/DOM sink without context-safe handling | JS/TS, server-rendered code |
| CWE-78 | OS command injection | Input → shell command construction/execution | Java/Python/JS/TS/Go |
| CWE-22 | Path traversal | Input → filesystem path → file read/write | Java/Python/JS/TS/Go |
| CWE-918 | SSRF | Input-controlled URL/host → server-side HTTP request | Python/Java/JS/TS/Go |
| CWE-787 | Out-of-bounds write | Array/pointer writes with insufficient bounds evidence | C/C++; specialized research |
| CWE-416 | Use-after-free | Path-sensitive allocation/free/use patterns | C/C++; specialized research |
| CWE-798 | Hard-coded credentials | Credential assignment or literals in code contexts | All where patterns are meaningful; avoid retaining secrets |
| CWE-502 | Deserialization of untrusted data | Untrusted bytes → unsafe deserializer or class loader | Java/Python/JS/TS as supported |
| CWE-863 | Incorrect authorization | Sensitive operation lacking required authorization under known framework semantics | Experimental, app-wide context |
| CWE-190 | Integer overflow/wraparound | Arithmetic under bounded numeric semantics | Primarily C/C++/Go/Java cases |
| CWE-295 | Improper certificate validation | TLS verification disabled or bypassed | Java/Python/JS/TS/Go |

**CWE categories are not equivalent difficulty.** A fixed API call can support a high-confidence misconfiguration rule; use-after-free can require path-, alias-, and lifetime-sensitive analysis; missing authorization can depend on application policy unknown to the tool. These features cannot share a single evidence standard.

### Finding evidence levels

- `static_supported`: documented source-to-sink path or rule evidence meets a validated detector's criteria.
- `heuristic_candidate`: suspicious known code idiom; insufficient proof of reaching a dangerous sink.
- `ml_suspected`: classifier recommends review without a verified flow.
- `incomplete_analysis`: ambiguity, parse failure, unresolved call, unsupported framework, or resource limit prevents a sound conclusion.

**Severity** (impact if exploitable) and **confidence** (strength of evidence) are distinct. ML outputs must not be labelled exploit probabilities unless calibrated and validated. Findings can carry multiple CWE mappings only with justified evidence.

## 9. End-user workflows

### Workflow A — local CLI scan (M1)

1. Developer installs `traceward` in an isolated Python environment.
2. Runs `traceward scan ./src --format text` or JSON/SARIF if enabled.
3. Scanner discovers supported files; excludes configured directories, generated/binary files, and oversized inputs.
4. It parses, builds normalized analysis units, invokes eligible deterministic rules, optionally calls a versioned classifier, deduplicates, and aggregates findings.
5. Developer receives summary, exact file/line spans, evidence, limitations, and remediation links.
6. CI can fail on findings meeting a configured severity and confidence threshold, but **analysis errors have a separate exit code**.

### Workflow B — paste/upload a snippet (M1)

1. User pastes Java code into editor or uploads a supported file.
2. Browser sends code to HTTPS backend on deliberate user action; editor never uploads silently.
3. Server validates size, content and language; runs isolated static analysis without execution.
4. Dashboard shows findings, code highlighting, and a coverage warning.
5. By default input and scan results are transient; no code persistence.

### Workflow C — repository scan (M2)

1. User submits a public GitHub repository URL; only approved public hosts and capped repository sizes accepted.
2. Backend retrieves a pinned commit / archive into a sandboxed temporary workspace.
3. Worker rejects symlink escape, traversal and excessive download/unpack size.
4. Scanner processes allowlisted file types and returns asynchronous job status.
5. User opens scan summary and navigates file-scoped findings.

### Workflow D — GitHub Actions (M2/M3)

1. Maintainer adds a version-pinned TraceWard action or invokes CLI in workflow.
2. Scanner analyzes checked-out code without executing the repository.
3. It produces SARIF 2.1.0 and stable finding fingerprints.
4. Upload to GitHub code scanning is conditional on repository entitlements and permissions; local artifact export works regardless.
5. Workflow can use a defined baseline to distinguish introduced findings from existing findings.

### Workflow E — ML experiment (M3)

1. Researcher registers immutable dataset manifest and split strategy.
2. Trains model candidates using only training data for vocabulary, normalization, feature selection, and fit.
3. Selects hyperparameters on validation data; test data remains untouched until final measurement.
4. Compares methods by CWE, language, dataset source, compute budget and false positives.
5. Exports reproducible benchmark report and optionally publishes a compatible model.

## 10. Functional requirements and priority

Requirements use `P0` (launch blocker), `P1` (next release), `P2` (later). Each requirement should be linked to tests.

| ID | Priority | Requirement | Acceptance criterion |
|---|---|---|---|
| FR-001 | P0 | Installable Python CLI | `traceward --version`, `scan`, `rules`, `doctor` work on supported OS |
| FR-002 | P0 | Parse and traverse Java | Method spans, calls, byte offsets and errors match fixtures |
| FR-003 | P0 | Analyze CWE-89 | Safe parameterization and vulnerable concatenation fixtures distinguished in validated subset |
| FR-004 | P0 | Hybrid detector result | Deterministic and ML evidence identified separately; no fabricated data flow |
| FR-005 | P0 | Stable result schema | JSON Schema validated; tests cover serialization/fingerprinting |
| FR-006 | P0 | Structured CLI output | Human text and JSON output, explicit error codes and summary |
| FR-007 | P0 | Reproducible ML experiment | Dataset hashes/splits/seeds/artifacts and report reproducible |
| FR-008 | P0 | FastAPI entry point | Health, model information, scan, error responses documented by OpenAPI |
| FR-009 | P0 | Minimal web scan | Paste, scan, finding list and details, privacy notice |
| FR-010 | P0 | Security boundaries | Upload/path/archive abuse tests and no-code-execution guarantee pass |
| FR-011 | P0 | Coverage transparency | Unsupported CWE/language combos and partial analysis visible |
| FR-012 | P1 | File/ZIP multi-file scan | Valid files scanned; malicious archive rejected |
| FR-013 | P1 | Four-language support | Java/Python/JS/TS adapters with versioned fixture coverage |
| FR-014 | P1 | Public repo import | Safe retrieval, caps, status, deterministic commit reference |
| FR-015 | P1 | SARIF export | SARIF schema and GitHub support validation pass |
| FR-016 | P1 | Async scan jobs | Status, cancellation, timeout and recovery behavior tested |
| FR-017 | P1 | Static taint propagation | Local flow traced with source/sink/sanitizer evidence on chosen languages |
| FR-018 | P1 | Suppression/baseline | Inline or config suppression with justification and auditing |
| FR-019 | P2 | Interprocedural analysis | Bounded call graph and context-sensitive cases supported, failures flagged |
| FR-020 | P2 | Deep model lab | CodeBERT/GraphCodeBERT training and comparative reports |
| FR-021 | P2 | Seven-language coverage | Go/C/C++ parsing + assessed detector subsets |
| FR-022 | P2 | VS Code extension | Uses local CLI or opt-in API; links to exact file spans |
| FR-023 | P2 | Team accounts | Auth, projects, isolated workspaces, role permissions and retention controls |
| FR-024 | P2 | Fix assistant | Reviewable suggestions only; automatic changes opt-in and tests required |

## 11. Detailed analysis pipeline

```text
CLI / Web / API / GitHub Action
          │
          ▼
Input validation + bounded file discovery
          │
          ▼
Language detection + Tree-sitter parse
          │
          ▼
Language adapter ──► analysis units + source locations
          │
          ▼
Shared IR: symbols, calls, data-flow edges, source spans
          │
          ├────────► deterministic rules / API patterns
          ├────────► intra-procedural taint flow
          ├────────► ML feature extraction + inference
          └────────► partial/unsupported diagnostics
          │
          ▼
Finding aggregator + dedup + confidence/priority policies
          │
          ▼
Versioned JSON schema ─► CLI / API / dashboard / SARIF
```

### Parser/IR decisions

- Read source as bytes; preserve line/column and byte offsets, and define conversions to UTF-16 columns only when needed for IDE interoperability.
- Preserve parse errors and error-node boundaries; do not silently produce a clean scan on malformed source.
- `AnalysisUnit`: repository-relative path, language, scope (function/method/file), AST type, syntax-tree location, normalized token stream and features.
- `SymbolRef`: lexical identity, declaration span, scope, type information if available, unresolved marker.
- `CallSite`: callee text, resolved target if known, argument expressions, span, framework mapping.
- `FlowNode`: source, assignment, transformation, sanitizer, branch, call, sink and return categories.
- `FlowEdge`: direct assignment, argument pass, return transfer, conditional edge or conservative unknown edge.
- `FlowTrace`: ordered source-to-sink path with provenance and explicit uncertainties.
- `RuleExecution`: rule/version, language, success or incomplete diagnostic, elapsed time, evidence spans.

**Scope restraint:** M1 IR is lexical/AST-based with local def-use relations. M2 adds a conservative CFG and limited local taint. M3 can expand selected interprocedural cases. Full C++ semantics are out of scope for early versions; adapter should accurately declare limitations.

### Rules, sanitizer modeling, and taint policies

A rule declares language, CWE, version, source patterns, sink patterns, sanitizers or safe API semantics, scope, minimum evidence, remediation references and tests. Taint is context-specific: SQL parameter binding is not equivalent to HTML escaping, URL allowlisting, or shell argument handling. A sanitizer applicable to one sink must not be globally trusted for all contexts.

For each candidate: locate untrusted source → track transformations/assignments → locate sink → check relevant safety constraints → emit path evidence if possible. If resolution fails, emit a weaker candidate or an analysis limitation, never an invented complete trace.

### Finding deduplication

Findings are grouped by normalized path, rule/CWE, sink span and trace identity. The fingerprint is stable across scan runs when line numbers shift, to the extent practicable; use normalized neighboring syntax rather than raw line numbers alone. Each finding includes all contributing engines without duplicating user-visible alerts.

## 12. Machine-learning subsystem and Model Lab

### Eight candidate families

| Candidate | Input form | Role in experiments | Deployment posture |
|---|---|---|---|
| Logistic Regression | Sparse TF-IDF | Interpretable linear baseline; probability calibration study | Lightweight candidate |
| Multinomial Naive Bayes | Nonnegative token counts / TF-IDF | Very fast lexical baseline | Lightweight research baseline |
| Random Forest | Sparse/dense engineered code features | Nonlinear ensemble benchmark | Only if value demonstrated |
| Linear SVM | Sparse TF-IDF | Baseline from TCOM study; fast decision score | Preferred initial classification baseline |
| XGBoost | Engineered feature matrix | Boosted-tree benchmark | Only if validated against SVM |
| LightGBM | Engineered feature matrix | Alternate boosting benchmark | Research/optional |
| CodeBERT | Tokenized code | Contextual encoder, task-specific fine-tuning | Later optional inference model |
| GraphCodeBERT | Tokenized code + model-specific data-flow representation | Structural model experiment | Later research model; not a drop-in taint engine |

**Decision rule:** eight candidates are an **experiment plan**, not eight mandatory production inference steps. The production scanner runs only models that add measurable lift for a defined CWE/language cohort at an acceptable latency and false-positive cost. Avoid model stacking that inflates false alarms without independent benefit.

### Reproduction of the project baseline

The source TCOM presentation reported:

- NIST SARD Juliet Java 1.3, CWE-89 focus.
- 240 candidate vulnerable/safe pairs, 48 duplicate pairs removed → 192 pairs / 384 methods.
- 12 input-source families: 8 train, 2 validation, 2 test.
- Tree-sitter token/syntax normalization, training-only TF-IDF fitting, 534 features.
- Random Forest: 50 trees, depth 4; Linear SVM: `C=0.1`; XGBoost: 50 rounds, depth 2.
- All models: **macro-F1 = 1.000** on **64 held-out synthetic methods**.
- Reported median end-to-end latency: RF 6.09 ms, SVM 2.81 ms, XGBoost 3.22 ms; SVM serialized model 4.7 KiB, memory roughly 179–182 MiB on the reported test environment.

These numbers are **historical research observations only**. Confirm original scripts, preprocessing, dependencies, hardware, evaluation mode, and data rights before reproducing. A shortcut rule based on `setString` classified 56/64 in the reported test, underscoring the need to detect benchmark-specific lexical shortcuts. Do not extrapolate to other languages, weaknesses, or repositories.

### Data management and provenance

Every corpus has a machine-readable manifest with `dataset_id`, source URL, acquisition date, upstream license, schema version, license restrictions, repository IDs, commit hashes, language, CWE, ground-truth provenance, label confidence, group identity, duplicate cluster, and content hashes. Avoid uploading dataset copies containing proprietary or secret-bearing source. Document redistribution rules.

Sources to investigate:

- **NIST SARD/Juliet:** controlled synthetic positive and negative examples. Useful for known data-/control-flow patterns, not a complete model of production code.
- **OWASP Benchmark:** known-answer Java and Python application security test suites; use independent scoring conventions.
- **CVEfixes:** vulnerability-linked open-source change history; verify that changed code actually corresponds to the reported CWE, and that changed lines are not casually labelled as fully vulnerable or safe.
- **Verified repository-level examples:** select distinct projects and commits and manually review positive/negative cases with file and sink context.
- **Curated adversarial negatives:** safe API usage, encoded-but-not-sanitized variants, same token vocabulary with different flow, dead branches, unresolved calls, and misleading function names.

### Train/validation/test strategy

1. Lock a repository-disjoint holdout set before training or tuning; group forks, vendored code and near-duplicates.
2. When relevant, hold out later commits or time periods to check temporal drift.
3. Keep transformations learned from data (TF-IDF vocabulary, scalers, feature selection, calibrators) fitted only on training/validation folds as appropriate; never fit to test.
4. Report metrics by language, CWE, repository, synthetic vs real source, and confidence tier.
5. Publish confidence intervals or bootstrap intervals for sample sizes where appropriate; document prevalence.
6. Reserve a **final untouched test set**; repeated model shopping against that set invalidates the reported comparison.
7. Maintain a separate **challenge set** (hard negatives and edge cases) without leaking it into model selection.
8. Report per-class confusion matrices and errors from safe code incorrectly flagged.

### Evaluation metrics

**Classification:** per-CWE precision, recall, F1; macro/micro-F1 where appropriate; PR-AUC for variable threshold; confusion matrix; calibration error and reliability plots for probability outputs. Include top-k triage utility when model is used for ranking rather than direct detection.

**Security scanner:** true-positive rate, false-positive rate, findings per KLOC, issue-level recall for curated known vulnerabilities, evidence-path correctness, location accuracy, unsupported-analysis percentage, and human review burden.

**Operational:** end-to-end files/s and LOC/s, per-file p50/p95 wall time, per-rule cost, model memory, serialized size, worker peak RSS, startup time, and cache hit rates. Separate preprocessing latency from pure inference latency.

**Comparison baselines:** regex/token heuristic, deterministic rule engine, standalone SVM, tree ensembles, fine-tuned code models, hybrid pipeline; evaluate another established static scanner on compatible CWE/language subsets without implying identical detection semantics.

### Model lifecycle and artifacts

A model registry entry must include `model_id`, version, training code git SHA, dependency lock digest, dataset manifest hash, feature contract hash, split IDs, metrics per supported cell, threshold and calibration version, inference runtime and size. Model loading validates compatibility; mismatched feature schemas cause a visible error, never a silent fallback to wrong predictions. Use `safetensors` or other safer documented serialization where feasible; treat Python pickle/joblib artifacts as trusted-code-only inputs and never deserialize user uploads.

**M1 serving:** frozen TF-IDF + Linear SVM artifact; versioned feature extraction identical to training. Score is an *uncalibrated decision value* unless a separate calibration stage is validated. Emit model suspicion as separate evidence; a low score does not certify safety.

**Transformer serving:** offline or opt-in workers, explicit model size and inference budget; GPU acceleration optional. No need to load transformers for baseline CLI scans.

## 13. Priority and risk scoring

Every finding has:

- **CWE and rule ID:** objective category and triggering detector.
- **Severity:** `critical | high | medium | low | informational | unknown`, based on a documented policy and available context, not simply a model's confidence score.
- **Confidence:** `high | medium | low` and evidence tier; independent of severity.
- **Review status:** `new | acknowledged | false_positive | accepted_risk | resolved` (persistent statuses when history enabled).
- **Analysis completeness:** `complete_for_rule | partial | unsupported | error` with reasons.

Priority sorting defaults to strong static evidence and high severity before ML-only suggestions. Do not issue a `critical` grade solely because a classifier score is high. Unknown trust boundaries, unresolved dispatch, or missing build context must lower confidence.

## 14. Unified JSON result contract

### Common envelope

```json
{
  "schema_version": "1.0.0",
  "scan_id": "scan_example_001",
  "source": {"kind": "directory", "revision": null},
  "scanner": {"name": "TraceWard", "version": "0.1.0"},
  "coverage": {
    "languages_detected": ["java"],
    "supported_checks": ["CWE-89"],
    "unsupported_checks": [],
    "partial": false
  },
  "summary": {
    "files_discovered": 2,
    "files_analyzed": 2,
    "findings": 1,
    "errors": 0
  },
  "findings": [
    {
      "id": "tw_58f6f9",
      "fingerprint": "sha256:illustrative-stable-fingerprint",
      "rule_id": "java.sql.concatenated-untrusted-input",
      "cwe": ["CWE-89"],
      "title": "Potential SQL injection via query concatenation",
      "severity": "high",
      "confidence": "high",
      "evidence_level": "static_supported",
      "location": {
        "path": "src/UserRepository.java",
        "start_line": 28,
        "start_column": 11,
        "end_line": 28,
        "end_column": 39
      },
      "evidence": {
        "source": "request.getParameter(...) at line 22",
        "sink": "Statement.executeQuery(...) at line 28",
        "flow": ["line 22", "line 25", "line 28"],
        "uncertainties": []
      },
      "detectors": [{"type": "taint_rule", "id": "java.sql.concatenated-untrusted-input", "version": "1.0.0"}],
      "guidance": "Use parameterized queries and bind untrusted values.",
      "references": ["https://cwe.mitre.org/data/definitions/89.html"]
    }
  ],
  "diagnostics": [],
  "duration_ms": 187
}
```

**The JSON above is a sample contract only, not a real scan.** Source/sink traces must be constructed by actual analysis and not filled from templates. Column conventions and path normalization will be specified in the JSON Schema and tested across UTF-8/UTF-16 boundaries.

### API error contract

Return `error.code`, `error.message`, `error.request_id`, and optional validation details. Error codes include `INVALID_INPUT`, `UNSUPPORTED_LANGUAGE`, `INPUT_TOO_LARGE`, `ARCHIVE_UNSAFE`, `REPOSITORY_NOT_ALLOWED`, `SCAN_TIMEOUT`, `MODEL_INCOMPATIBLE`, `RATE_LIMITED`, and `INTERNAL_ERROR`. Error messages never reveal internal filesystem paths, credentials, raw secrets, or full source snippets.

## 15. Public API and CLI requirements

### REST API (M1 + future)

| Method | Endpoint | Release | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | M1 | Liveness/readiness (separate detailed readiness internally) |
| `GET` | `/api/v1/version` | M1 | Scanner/schema versions and build info |
| `GET` | `/api/v1/capabilities` | M1 | Language × CWE × detector version/maturity |
| `GET` | `/api/v1/models` | M1 | Supported model metadata, non-sensitive benchmark caveats |
| `POST` | `/api/v1/scans/snippet` | M1 | Synchronous bounded snippet scan |
| `POST` | `/api/v1/scans/upload` | M2 | Safe bounded file/ZIP scan; async if substantial |
| `POST` | `/api/v1/scans/repository` | M2 | Public GitHub repo URL at pinned commit; asynchronous |
| `GET` | `/api/v1/scans/{scan_id}` | M2 | Status and compact summary (authorized access only) |
| `GET` | `/api/v1/scans/{scan_id}/findings` | M2 | Cursor-paginated filtered findings |
| `GET` | `/api/v1/scans/{scan_id}/reports/{format}` | M2 | JSON or SARIF export, access controlled |
| `DELETE` | `/api/v1/scans/{scan_id}` | M2 | Cancel scan and/or delete retained data per policy |

API requests include explicit language for snippets and optional `rulesets`, `min_confidence`, and scan mode (`fast` vs `deep`) only where supported. Unsupported combinations must return an informative response, never silently run nonexistent detectors.

### CLI usage

```bash
traceward --version
traceward doctor
traceward rules list --language java
traceward scan ./src --language java --format text
traceward scan . --format json --output traceward-results.json
traceward scan . --format sarif --output traceward.sarif  # M2+
traceward scan . --fail-on high --min-confidence high
traceward benchmark --config configs/benchmarks/java_sql.yaml
```

Proposed exit codes: `0` = scan successfully completed without policy-violating findings; `1` = scan completed and policy-violating findings present; `2` = invalid input / fatal scan error; `3` = partial scan disallowed by configured strict mode. Text summary must always indicate partial coverage; `0` is not equivalent to “software is secure.”

### Configuration file

```yaml
# traceward.yaml — illustrative, validated against a published schema
schema_version: 1
scan:
  include: ["src/**"]
  exclude: ["**/vendor/**", "**/node_modules/**", "**/dist/**"]
  max_file_mb: 2
  max_files: 2000
  timeout_seconds: 120
  fail_on: high
  fail_on_partial: false
engines:
  static_rules: true
  ml: true
  experimental_rules: false
privacy:
  persist_source: false
  external_model_requests: false
```

Values above are preliminary defaults; final sizes and limits must be measured and justified before production deployment.

## 16. Frontend / UX PRD

**Design direction:** mature developer tool, dark-first but accessible in light mode; strong typography, clean monospaced code, functional color semantics (red severe, amber caution, neutral info), minimal decorative effects. Avoid promising a finding on the basis of a colored warning icon alone.

### M1 screens

1. **Landing/demo:** tagline, product explanation, supported coverage table, try-an-example CTA, exact privacy disclaimer.
2. **Scan workspace:** Monaco editor, language picker restricted to enabled adapters, paste/clear, demo examples, scan button, size meter, processing states.
3. **Results explorer:** summary, findings by severity/CWE, file/method list, “no supported findings” vs “not analyzed” distinction, warnings on partial analysis.
4. **Finding detail:** exact code span, rule, CWE, source-to-sink evidence when available, reasons, confidence, limitations, and secure coding references.
5. **Model & methodology page:** dataset provenance, reproducibility, research vs external-validation labels, confusion matrices and timing methodology.

### M2/M3 screens

6. **Repository overview:** pinned repo revision, file/language coverage, scan status, trend charts (only with stored history).
7. **PR comparison:** new/resolved/unchanged findings using stable fingerprints.
8. **Model Lab:** experiment selector, dataset metadata, model metrics, confidence intervals, size, CPU/GPU usage and runtime.
9. **Settings:** exclusions, enabled rulesets, privacy controls, false-positive suppressions, scan budget.

### UX acceptance rules

- Every status is exposed as text, not color alone.
- Scanner results include a clear coverage banner if rules are unsupported, timed out, or skipped.
- Link to highlighted source line; accessible keyboard navigation and screen-reader labels.
- No claims of “100% secure” or “all vulnerabilities fixed.”
- Do not label uncalibrated ML scores as probability percentages.
- No background upload or telemetry of source code without explicit consent.
- Copy/export finding and remediation reference easily; never insert an unsafe auto-fix without review.

## 17. Storage, entities and data retention

### M1: no persistent server database needed

Operate locally/in memory, store model assets in package-managed or downloaded trusted directories, and optionally export scan JSON. A local SQLite database for opt-in scan history is permissible but not required. A stateless demo minimizes hosting and privacy requirements.

### M2+: PostgreSQL domain entities

| Entity | Key fields | Purpose |
|---|---|---|
| `User` | ID, auth provider ID, created_at | Accounts (only after introducing auth) |
| `Workspace` | ID, owner_id, name, retention_policy | Isolation boundary |
| `Repository` | ID, workspace_id, provider, canonical URL, default_ref | Repository metadata |
| `ScanJob` | ID, repository_id/null, source_revision, status, timestamps, coverage summary, expires_at | Async lifecycle |
| `Finding` | ID, scan_id, fingerprint, rule_id, CWE, location, severity, confidence, evidence JSON | Findings |
| `RuleVersion` | ID, semver, language, CWE, maturity | Capability registry |
| `ModelVersion` | ID, artifact digest, feature contract, benchmark reference, state | Audit model use |
| `Suppression` | fingerprint/rule/path scope, reason, owner, expiry | Auditable triage |
| `AuditEvent` | actor, action, entity, timestamp, metadata | Security-sensitive activity |

### Storage rules

- Do **not** persist raw uploaded source by default; transient job workspaces are deleted on success/failure/cancellation.
- If history is enabled, persist minimal excerpts/evidence references, not full project files; source retention separately opt-in with visible expiration.
- Encrypt transport and appropriate at-rest storage; secrets stored in external secret manager/environment, not database columns in plaintext.
- Use row-level authorization checks in service code; optional DB row-level security is defense in depth.
- Logs exclude code, tokens, environment values and credentials; include request ID, timings and aggregate status only.
- Make scan results and audit data deletable by authenticated owners; apply configurable retention and scheduled cleanup.

## 18. Infrastructure, performance and deployment

### Architecture choice: modular monolith first

- **Python package:** `traceward-core` contains parsers, IR, rule runtime, taint, findings, model adapter; no FastAPI imports.
- **Python FastAPI app:** request validation, auth/rate limiting, scan orchestration, API serialization.
- **Next.js/TypeScript app:** viewer and developer workflows.
- **Optional worker:** heavy scans behind a queue in M2; can initially reuse the same Python package.
- **PostgreSQL + Redis:** introduced when jobs, persistence and concurrency require them, not prerequisites for the first CLI release.

### Run modes

1. **Local CLI:** no backend, no network, no tokens. Most reproducible default.
2. **Local Docker Compose:** API + web (and later DB/worker) for demos.
3. **Hosted demo:** small resource-capped public instance; stateless input, abuse protection, no private repository access initially.
4. **CI:** pinned scanner image/version and committed output artifact; use GitHub SARIF when permitted.

### Performance budgeting

Split modes:

- `fast`: language detection, AST/rule evaluation, selected small classical ML artifacts.
- `deep`: expensive flow analysis and, if specifically enabled, transformer inference; may require asynchronous jobs.

Benchmark with fixed hardware, file count, LOC and framework coverage. Initial planning objective: `fast` scans of small Java demo projects should feel interactive; production p95 performance limits will be set after a measured baseline rather than guessed from the 2.81 ms method-level research measurement. Enforce timeout, max files, max AST nodes, max graph edges and memory constraints. Avoid repeatedly loading ML models per file. Cache per-content digest and analyzer version, with correct invalidation.

### Observability

Metrics: jobs started/completed/failed, latency p50/p95, files scanned, parse-error rate, partial-analysis rate, detector hits, queue latency, worker RSS, model-load time, rate-limit hits. Use OpenTelemetry-compatible structure where practical; source content is never a metric label or tracing span. Log audit events for access and configuration changes without secrets.

## 19. Threat model and security controls

TraceWard analyzes adversarial inputs and must be designed as a hardened service even when only reading source.

| Threat | Attack surface | Required mitigation |
|---|---|---|
| Archive traversal | Uploaded ZIP entries | Reject absolute paths, `..`, symlinks, device files; extract to controlled sandbox |
| ZIP bomb / resource exhaustion | Archives and huge files | Caps on compressed/uncompressed size, expansion ratio, file count, total bytes, nested archives, time, AST depth |
| SSRF | Git repo URL or future webhook | Restrict to approved HTTPS hosts, validate redirects and resolved IPs, block private/link-local/metadata addresses, outbound firewall |
| Repo credential leak | Git URL/logging | Public repos initially; no credentials in URLs/logs; ephemeral scoped tokens only if private repos added |
| Code execution | Build files, scripts, parsers, model artifacts | Never run source/build scripts; hardened non-root container; strict package/model allowlist; no pickle uploads |
| Parser crashes | Malformed source | Pin and patch grammars, fuzz tests, timeouts, worker isolation |
| Tenant data leak | Stored findings/history | Workspaces, per-request access authorization, deletion/retention policy |
| Stored XSS | Source displayed in web UI | Escape code and messages; strict content security policy; avoid unsafe HTML rendering |
| Prompt injection | Future LLM explanations | Treat repository text as untrusted data, no tool/credential access, constrained output and review |
| Secret disclosure | Code snippets and telemetry | Never persist source by default, redact detected secrets in logs/UI where appropriate |
| Supply-chain compromise | Dependencies/actions/models | Pin versions/digests, lockfiles, SBOM/dependency checks, trusted artifact provenance |
| Denial of service | Public API | Rate limits, request quotas, bounded queue, cancellation, fair scheduling |

**Absolute MVP security requirement:** uploading a project or running TraceWard against a repo never causes that project’s code to execute. Launching `npm install`, Maven, `setup.py`, Make, or any test/build tool against untrusted scans is prohibited unless a future isolated execution mode receives a separate threat model.

### Privacy/security defaults

Public hosted demo accepts only intentionally submitted snippets or public repositories. No auto-indexing users' GitHub accounts. No remote LLM calls by default. Scans are temporary and automatically cleaned. User-consented telemetry contains aggregate performance only. Public repo URLs are validated; unknown hosts are not silently fetched.

## 20. GitHub and CI integration

### SARIF requirements

Use the GitHub-supported subset of SARIF 2.1.0. Provide `runs.tool.driver`, stable rule descriptors, result message, physical location, severity level mapped appropriately, result fingerprints, and category/analysis identity. Validate output with schema checks and an actual representative GitHub Actions integration test.

GitHub code scanning availability depends on repository visibility, ownership, plan and enabled Code Security features. The CLI's SARIF artifact remains useful independently of GitHub ingestion. Do not claim code-scanning alerts will appear on every private repo.

### PR workflow policy

- Pin scanner release and workflow actions.
- Scan the checked-out PR revision in least-privileged CI.
- Generate SARIF, optionally upload using permitted workflow permissions.
- Use a baseline on the merge base or previous approved revision to separate introduced from existing findings.
- Fail CI only for explicitly configured validated confidence/severity rules; experimental ML suggestions are informational by default.
- If scan ends partial or errors, show the separate status rather than a false green security result.
- Protect against untrusted PR workflow code executing with repository write tokens; document safe GitHub Actions permissions.

## 21. Test strategy and evaluation gates

### Testing pyramid

| Level | What to test | Gate |
|---|---|---|
| Unit | AST visitors, normalization, rule patterns, file paths, encoding | Every PR |
| Golden fixtures | Vulnerable + safe paired examples, expected evidence lines, no spurious finding | Every PR |
| Schema/contract | JSON/SARIF outputs and Pydantic/API compatibility | Every PR |
| Integration | CLI → engine → result; API → engine; UI → API smoke tests | Every PR / release |
| Differential | Compare expected behavior on tested cases with selected established tools | Scheduled/release |
| Property/fuzz | Malformed Java/C++, random tokens, archives, encodings | Scheduled/release |
| Security | Traversal, ZIP bombs, SSRF, XSS, rate limits, auth checks | Release blocker |
| Model reproducibility | Locked splits/seeds, train-only preprocessing, feature compatibility | New model release |
| External holdout | Project-disjoint, human-reviewed real-world examples | Supported detector promotion |
| Performance | Time/memory on fixed machines + fixed repositories | Release/regression |

### Required hard-negative cases

- SQL keywords in comments or string literals without execution.
- Safe parameter binding with misleading method names.
- Stored procedures with dynamic SQL concatenation.
- Sanitizer applied for the wrong output context.
- User input transformed by intermediate helper functions.
- Source and sink in different scopes (declared analysis limit in M1).
- Trusted constants concatenated to a query without attacker control.
- SQL query with unsafe identifier selection (binding values alone does not sanitize identifiers).
- C/C++ macros and template paths that parser-only analyses cannot resolve.
- Network calls with known-safe fixed destinations vs untrusted dynamic hosts.
- Branches that make flow infeasible; record limitations if path sensitivity absent.

### Detector promotion policy

`experimental` → `beta` → `validated` requires: documented threat model and intended scope; safe/vulnerable fixtures; code review; independent external dataset; acceptable precision/recall and evidence correctness; false-positive review; repeatable benchmark; known unsupported cases. High-confidence status is earned per detector/language combination, never globally inherited from the platform.

## 22. Complete project/repository layout

```text
traceward/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── pyproject.toml                   # Python workspace / uv or equivalent
├── uv.lock                          # exact toolchain lock (if uv selected)
├── traceward.yaml                   # example configuration
├── apps/
│   └── web/                         # Next.js + TypeScript + Monaco
│       ├── app/
│       ├── components/
│       ├── lib/
│       └── tests/
├── services/
│   ├── api/                         # FastAPI + Pydantic
│   │   ├── traceward_api/
│   │   └── tests/
│   └── worker/                      # asynchronous scans, M2+
├── packages/
│   ├── traceward-core/              # Pure Python library
│   │   ├── src/traceward/
│   │   │   ├── cli/
│   │   │   ├── config/
│   │   │   ├── discovery/
│   │   │   ├── parsers/
│   │   │   ├── languages/
│   │   │   │   ├── java/
│   │   │   │   ├── python/
│   │   │   │   ├── javascript/
│   │   │   │   ├── typescript/
│   │   │   │   ├── go/
│   │   │   │   ├── c/
│   │   │   │   └── cpp/
│   │   │   ├── ir/
│   │   │   ├── cfg/
│   │   │   ├── taint/
│   │   │   ├── detectors/
│   │   │   ├── rulepacks/
│   │   │   ├── ml_inference/
│   │   │   ├── findings/
│   │   │   ├── reporters/             # text/json/sarif
│   │   │   └── security/
│   │   └── tests/
│   └── traceward-ml/                # Offline ML experiments, Python
│       ├── src/traceward_ml/
│       │   ├── datasets/
│       │   ├── features/
│       │   ├── classical/
│       │   ├── transformers/
│       │   ├── evaluation/
│       │   ├── calibration/
│       │   └── registry/
│       └── tests/
├── models/                           # manifests only; large artifacts external
├── rules/                            # versioned rules with metadata/tests
├── configs/
│   └── benchmarks/
├── fixtures/
│   ├── java/
│   ├── python/
│   ├── javascript/
│   ├── typescript/
│   ├── go/
│   ├── c/
│   └── cpp/
├── benchmarks/                       # locked manifests; no private data
├── schemas/                          # JSON Schema + SARIF mapping
├── docs/
│   ├── architecture/
│   ├── adr/                          # architecture decision records
│   ├── api/
│   ├── threat-model/
│   ├── coverage/
│   ├── evaluation/
│   └── prd/
├── scripts/
├── docker/
├── .github/
│   └── workflows/
└── tests/e2e/
```

The structure anticipates future features but should be created **incrementally**; avoid dozens of empty folders in the initial commit. First deliver `traceward-core`, Java fixtures, one detector, CLI and tests.

## 23. Milestones, engineering tasks, and dependencies

### M0 — reproduce and establish trustworthy baseline

**Deliverables:** dataset manifest, preprocessing scripts, deterministic train/validation/test split, three original classifiers, evaluation table, model artifact, limitations memo.  
**Tasks:** verify original data rights and dedup logic; implement normalized feature extractor; fit vectorizer on training only; test 64 held-out methods; repeat baseline under declared hardware and log observed differences.  
**Exit:** reproducible benchmark in a fresh Python environment, all metrics labelled synthetic, no unexplained data leakage.

### M1A — scanner core + Java CWE-89

**Deliverables:** installable CLI, Java parser, method extractor, scan result schema, deterministic SQL pattern rules, model adapter, JSON report.  
**Tasks:** fixtures, AST and span conversion, URI/path normalization, rule registry, source/sink mapping, safe API checks, limited local flow, fingerprinting, error handling.  
**Exit:** golden vulnerable/safe cases pass; `traceward scan fixtures/java/` works locally; partial analysis is visible.

### M1B — API + web demo

**Deliverables:** FastAPI endpoints, bounded snippet scan, Next.js scan page, findings page, method/model documentation, Docker deployment.  
**Tasks:** Pydantic schemas, HTTP error contract, no-persistence guarantees, syntax highlighting, privacy notice, request size/rate limits, end-to-end browser tests.  
**Exit:** a visitor can submit Java code and inspect evidence, and the same scan produces equivalent CLI/API findings.

### M2A — multi-language and expanded CWE

**Deliverables:** Python/JS/TS adapters, initial injection/XSS/path/SSRF patterns, coverage registry, external fixture evaluation.  
**Tasks:** language-specific source/sink/sanitizer lists, common IR extension, dedicated test suites, release gates.  
**Exit:** each advertised language/CWE pair has passing fixtures and documented capability; unsupported combinations explicitly identified.

### M2B — repositories + SARIF

**Deliverables:** bounded public repository fetcher, async queue, GitHub Actions example, SARIF export and validation.  
**Tasks:** SSRF prevention, archive isolation, commit pinning, fingerprinting, baseline policy, job cleanup, permission/entitlement documentation.  
**Exit:** successful public repo demo and a public GitHub Actions demo that renders or exports findings reproducibly.

### M3 — model lab and better data-flow

**Deliverables:** eight-model benchmark harness, independent real-world comparison, selected transformer experiments, local taint v2 + selected interprocedural analysis.  
**Tasks:** reproducible dataset/label manifests, calibration, class imbalance and uncertain labels, model registry, review-based promotion.  
**Exit:** benchmark cards, model selection rationale, measured real-world performance; expensive model off by default if no clear benefit.

### M4 — Go and native languages

**Deliverables:** Go, C and C++ parsers/adapters, new frameworks and targeted integer/memory-safety research detectors.  
**Tasks:** C/C++ grammar/compile-context limitations, flow graph experiments, safe/unsafe fixtures, external evaluation against native static analysis references.  
**Exit:** accurate capability matrix, separately reviewed experimental findings; no broad C/C++ safety claims without adequate evidence.

### M5 — developer experience

**Deliverables:** editor integration, trend view, scan history, suppression lifecycle, optional team workspaces and secure fix review.  
**Exit:** authenticated access controls and retention policies pass security review before any private code is persisted.

### Dependency order

Parser/span correctness → common result schema → deterministic rule baseline → local data flow → classifier adapter → CLI → API → web → repo scanning → SARIF/CI → multi-language expansion → richer model lab → native-code research. Several research tasks can run in parallel, but the integration path is sequenced deliberately.

### Scope control

For a solo project, ship M1 before chasing all seven languages. An initial shareable demo with Java CWE-89 detection, credible false-positive tests, CLI, API and dashboard is more valuable than a broad menu with unimplemented detectors.

## 24. Acceptance tests and definition of done

### M1 minimum acceptance scenarios

- **AT-01:** Java snippet with `Statement.executeQuery` and request-controlled concatenation yields an evidence-based potential CWE-89 finding when recognized flow is present.
- **AT-02:** Corresponding `PreparedStatement`/parameter-binding fixture is not flagged by the same unsafe-concatenation rule.
- **AT-03:** SQL-looking comments and dead strings do not trigger a high-confidence SQL injection report.
- **AT-04:** Unsupported language or unknown CWE is described accurately; tool does not present a clean bill of health.
- **AT-05:** A parsing error is reported with location/diagnostic; no blank-success response.
- **AT-06:** Repeating same scan on same content/scanner/model versions yields same findings and fingerprints.
- **AT-07:** CLI exit-code policy is documented and separately distinguishes findings from analysis errors.
- **AT-08:** API error handling rejects oversized input and does not leak source in server logs.
- **AT-09:** Web highlights finding spans and displays source/sink evidence only when actually computed.
- **AT-10:** CLI/API JSON contracts conform to the same versioned schema.
- **AT-11:** Research results page labels synthetic vs independently validated metrics.
- **AT-12:** No uploaded user code is executed or persisted by default.
- **AT-13:** README includes fresh-clone setup, reproduction instructions, example scan and limitations.
- **AT-14:** Software licenses, model artifacts and external datasets are audited for appropriate distribution.

**Definition of Done (M1):** all P0 requirements and the above tests pass; documented local installation succeeds on a supported environment; maintainers can run the benchmark with known corpus references; a deployed demo supports safe bounded submissions; a real-world external-evaluation section exists even if findings remain experimental. Coverage is transparent, not inflated.

### Definition of Done (full vision)

- Seven parsers operate with maintained tests and explicit support status.
- Each of twelve target CWE categories has at least one validated, documented language-specific detector **or is prominently identified as experimental/unimplemented**; the full 7×12 grid is not assumed.
- At least one external repository-disjoint evaluation exists for each production-promoted detector.
- All eight model families are supported as experiments when their dependencies/data permits; production inference uses measured winners only.
- Public-repo scan, JSON/SARIF, GitHub Actions, web and CLI workflows are demonstrated.
- Privacy, threat-model and resource-limit tests pass; unsupported findings and partial scans are explicit.

## 25. Risks, mitigations, and open decisions

| Risk | Impact | Mitigation |
|---|---|---|
| Scope explosion (7 languages × 12 CWEs) | Never completing a working tool | Milestone gates, per-cell maturity, M1-first delivery |
| Label noise in CVE-linked data | Misleading model scores | Human-reviewed positive and negative controls; provenance and uncertainty |
| Synthetic benchmark shortcut learning | Poor real-world generalization | External project-disjoint test, hard negatives, shortcuts audit |
| ML false positives | Developer distrust | Separate ML suggestions, thresholding, calibration, evidence-based promotions |
| C/C++ semantic limitations | Incorrect memory findings | Keep experimental, constrain semantics, compare with appropriate native analyzers |
| Parser version drift | Incorrect source spans | Grammar pinning, regression fixtures, lockfiles |
| Cloud cost / GPU constraints | High inference expense | Classical model defaults; transformers opt-in/offline |
| Malicious uploaded code/archive | Service compromise | Never execute, isolate parser workers, quotas, strict input handling |
| Third-party tool naming/licensing | Publication or legal issues | License scan, attribution, brand verification |
| GitHub policy/entitlement variation | SARIF alerts unavailable | Always provide SARIF artifact and note account requirements |
| “AI-generated fix” error | Introduces new weaknesses | No automatic patch application; review, rerun tests and scanner |

**Open decisions for implementation ADRs:** exact Python minimum and parser package versions; packaging (`uv` or Poetry); baseline dataset distribution permissions; how aggressive M1 taint precision should be; public demo upload caps; whether model artifacts are embedded or downloaded from trusted releases; auth provider once accounts exist; source retention opt-in semantics; and the chosen detector benchmark gate thresholds after initial independent evaluation.

## 26. Initial developer backlog — first 20 executable issues

1. Initialize Python monorepo/tooling, lint, type-check, pytest and CI.
2. Publish contribution, licensing, security reporting and data-handling policies.
3. Add Java grammar and a parser wrapper with deterministic span conversion.
4. Create Java positive/negative CWE-89 fixtures with expected locations.
5. Implement file discovery and ignore/exclude rules.
6. Define Pydantic/dataclass IR for `AnalysisUnit`, `CallSite`, `FlowNode` and `FlowTrace`.
7. Implement Java method extraction and call-site collection.
8. Implement versioned rule registry and rule manifest validation.
9. Implement minimal Java SQL concatenation detection with known-safe parameter binding.
10. Implement conservative local source/sink propagation and incomplete-analysis diagnostics.
11. Implement canonical result model, fingerprints and JSON Schema.
12. Implement CLI `scan`, `rules list`, `doctor`, `--format text/json`, exit codes.
13. Reproduce TCOM dataset preparation and split manifest with auditable provenance.
14. Train RF, Linear SVM and XGBoost and compare to rule baseline; write caveats.
15. Save compatible TF-IDF + SVM artifacts with hashes and metadata.
16. Add optional classifier adapter; keep signals separate from deterministic findings.
17. Implement FastAPI snippet endpoint and strict Pydantic input limits.
18. Implement Next.js editor, scan button, results list and finding detail.
19. Add end-to-end browser/API/CLI tests and security abuse tests.
20. Create a clean README demo, benchmark methodology and release checklist.

**Suggested first commit:** `feat(scanner): add Java parser, source spans, and CWE-89 test fixtures` — not an empty 7-language directory tree.

## 27. Public demo and resume showcase

### Demo flow (3–5 minutes)

1. Open terminal and run one vulnerable Java fixture.
2. Show a code-located CWE-89 finding with real source/sink trace.
3. Switch to a safe parameterized version; rerun and show why the rule no longer triggers.
4. Open the web dashboard; paste same code and compare normalized findings.
5. Show false-positive cases, partial-analysis warning, rule metadata and limitations.
6. Show external evaluation against held-out projects—precision, recall and false-positive count, not only synthetic F1.
7. If ready, open a GitHub PR with SARIF annotations or downloadable SARIF artifact.

### Example resume bullet (do not use until built and measured)

> Built **TraceWard**, a Python-first multi-language source-code security scanner combining Tree-sitter parsing, explainable taint analysis, and ML-based vulnerability triage; integrated a FastAPI/Next.js dashboard, CLI and SARIF CI reporting, and evaluated findings on independently held-out repositories with documented false-positive analysis.

Replace generic promises with **actual measured** supported languages, CWE coverage, GitHub workflow usage, latency, precision/recall and test counts when available.

## 28. References and source provenance

### Primary research supplied by project team

- *Efficient Machine Learning Models for Automated Source Code Vulnerability Classification*, Group 38 TCOM presentation/script (supplied in project conversation). Research results in §12 are based on the script and require independent reproduction before claiming achievement in TraceWard.

### Standards, methodology and implementation references

1. MITRE — **CWE Top 25 (2025)**: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
2. MITRE — **CWE-89 SQL Injection**: https://cwe.mitre.org/data/definitions/89.html
3. OWASP — **SQL Injection Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
4. OWASP — **Benchmark Project**: https://owasp.org/projects/benchmark
5. NIST — **Software Assurance Reference Dataset**: https://samate.nist.gov/SARD
6. Tree-sitter — **Introduction and Python bindings**: https://tree-sitter.github.io/tree-sitter/ and https://tree-sitter.github.io/py-tree-sitter/
7. GitHub — **SARIF support for code scanning**: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
8. GitHub — **Uploading SARIF files**: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file
9. Microsoft Research — **CodeBERT**: https://www.microsoft.com/en-us/research/publication/codebert-a-pre-trained-model-for-programming-and-natural-languages/
10. GraphCodeBERT paper: https://arxiv.org/abs/2009.08366
11. CVEfixes project: https://github.com/secureIT-project/CVEfixes

---

## 29. One-page implementation decisions

| Question | Decision |
|---|---|
| Is the scanner implemented in seven languages? | **No.** The scanner is Python; it *analyzes* seven target languages using adapters. |
| Should we learn Rust first? | **No.** Python-first; optional native optimization only when measured bottlenecks demand it. |
| Which model runs first? | Linear SVM/TF-IDF as optional baseline; deterministic rules and evidence remain first-class. |
| Do we run eight models on every scan? | **No.** Eight research candidates; promote selected model only with real-world evidence. |
| Can any model certify safe code? | **No.** Clean scans state supported coverage and limitations. |
| Do all 12 CWEs work on all 7 languages? | **No.** Detection support is declared and validated per language/CWE cell. |
| Is ML enough for injection detection? | **No.** Pair with contextual static rules and source-to-sink analysis. |
| Is a database needed at launch? | **No.** Introduce Postgres for account-based history and team functionality later. |
| Is public GitHub scanning in M1? | **No.** M2 after safe snippet/file scanning and security controls. |
| Can uploaded code be executed for analysis? | **No.** Strict static-only execution boundary. |
| What is the first production-ready milestone? | Java CWE-89 CLI + tests + JSON + limited API/dashboard and honest evaluation. |
| What is the main success condition? | Developers receive actionable, reproducible, correctly scoped security-review findings. |

**Final product statement:** TraceWard is a research-informed, Python-first, developer-grade SAST platform built around explainable, multi-language vulnerability analysis—not around claiming perfect AI accuracy. Ship one trustworthy capability, measure it, then expand.
