# OWASP BenchmarkPython CWE-89 baseline

This is a case-level evaluation of TraceWard's experimental Python SQLite rule
against the 16 CWE-89 labels in OWASP BenchmarkPython 0.1. The benchmark is
synthetic and independent of the TraceWard fixtures. This run measures how much
of that suite the scanner reaches. A project-disjoint Flask holdout is still
needed for real-world accuracy. [OWASP Benchmark project](https://owasp.org/projects/benchmark?tab=python-test-cases)

The run used detector `python.sqlite.concatenated-input` v0.2.0 from TraceWard
`7bdb5ff8e3e8e17721626509150fe10e302e1662`, with Tree-sitter 0.25.2 and the
Python grammar 0.25.0. The archive is pinned to OWASP revision
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. The scoring script verifies the
archive SHA-256 before opening it, reads only the expected-results table and
its CWE-89 case files, and analyzes source text without extracting or running
the benchmark application. Benchmark code remains in the separately downloaded
GPL-3.0 archive. [Pinned expected results](https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/expectedresults-0.1.csv) · [Upstream license](https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/LICENSE)

## Measured result

| OWASP label | Cases | Reported | No report | With diagnostics |
| --- | ---: | ---: | ---: | ---: |
| Positive | 5 | 0 | 5 | 5 |
| Negative | 11 | 0 | 11 | 11 |

All 16 returned a scan result with `UNSUPPORTED_FLOW` at a top-level
`from ... import ...` statement. There were zero scan errors. The scanner
stopped before it reached the SQL paths. End-to-end recall is 0/5 and
precision is undefined because the rule emitted zero findings. The observed
false-positive rate is 0/11, with all 11 negative files containing an
unsupported-flow warning. There is no diagnostic-free subset to score.

The evaluator counts a case once if it reports any finding from the Python
SQLite rule. Scans that return findings before a warning still count as
reported. Parser or scan failures are excluded from the scored denominator,
reported by label, and cause exit status 2. A warning alone keeps the case in
the score. Reported rates use the scored denominators and encode an undefined
ratio as JSON `null`.

## Reproduce

From the repository root, download the pinned archive into the ignored local
data directory and run the evaluator.

```sh
mkdir -p data/owasp
curl --proto '=https' --fail --silent --show-error --max-time 30 --max-filesize 10485760 \
  https://codeload.github.com/OWASP-Benchmark/BenchmarkPython/zip/f1291485808b66e20ddb6b01b10dc71b3df8c8ba \
  -o data/owasp/benchmark-python.zip
uv run --locked --inexact python -m scripts.datasets.benchmark_owasp_python \
  --archive data/owasp/benchmark-python.zip
```
