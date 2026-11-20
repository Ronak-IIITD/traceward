# Capability registry, scanner 0.1.0

| Language | Parse support | CWE-89 detection | Other planned CWEs | Maturity |
|---|---|---|---|---|
| Java | Tree-sitter Java 0.23.5 | Straight-line servlet input to JDBC concatenation, including try-with-resources | Unsupported | Experimental |
| Python, JS, TS, Go, C, C++ | Not implemented | Unsupported | Unsupported | Planned |

Rule `java.sql.concatenated-untrusted-input` version `0.2.0` reports
`heuristic_candidate`, high severity, medium confidence. There is no independent
external evaluation or production promotion. All scans are partial. See README
for exact modeled methods and unsupported semantics. No ML models are enabled.

Fixture results must not be described as real-world precision or recall. The
research paper's synthetic macro-F1 is not a scanner performance measurement.
