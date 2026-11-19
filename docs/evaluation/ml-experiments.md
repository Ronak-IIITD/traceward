# Offline Java CWE-89 experiments

See [Juliet Java 1.3 CWE-89](juliet-java-cwe89.md) for the NIST ingestion workflow.

The research harness trains fixed lexical baselines on a provenance-checked JSONL
corpus. It supports Logistic Regression, Linear SVM (`C=0.1`), Random Forest (50 trees, depth 4), and
XGBoost (50 estimators, depth 2). TF-IDF learns its vocabulary and IDF from the
training partition. These settings provide repeatable comparisons. A successful
run produces measured results for its declared corpus and feature extractor.

This harness uses a documented lexical feature contract. Experiment reports
identify their actual data and label provenance. Model promotion requires
additional evidence review.

## Install and run

From the repository root, install the optional dependencies, then point the
training command at the corpus manifest and records prepared for the experiment.
The output directory must be new so earlier results remain immutable.

```sh
uv sync --locked --extra ml
uv run --extra ml traceward-ml train \
  --manifest data/research/megavul-java-cwe89/manifest.json \
  --dataset data/research/megavul-java-cwe89/records.jsonl \
  --output models/local/java-cwe89-run-001 \
  --models svm rf xgboost \
  --seed 38 --code-revision "$(git rev-parse HEAD)" --lock uv.lock
```

The command validates hashes, labels and split isolation before training. It fits
the declared training examples and records metrics for training, validation and
test. Models use fixed hyperparameters. This command performs no tuning or model
promotion. Treat repeated test-set comparisons as exploratory after the first
measurement, and reserve another untouched holdout before production selection.

## Corpus contract

The manifest identifies schema version `1.0.0`, dataset ID, source HTTPS URL,
upstream revision, acquisition date, license, attribution, label provenance,
`corpus_kind` (`synthetic` or `real_world`), `language: java`,
`cwe: CWE-89`, the SHA-256 of the exact JSONL bytes, and record count.
Each line is a record with these fields.

| Field | Meaning |
|---|---|
| `id` | Unique example identifier |
| `code` | Java method or source text, at most 64 KiB of UTF-8 |
| `label` | Integer 0 for safe control or 1 for vulnerable label |
| `split` | Explicit `train`, `validation`, or `test` |
| `group_id` | Related examples that must share a split |
| `repository_id` | Upstream repository identity |
| `content_sha256` | SHA-256 of the code's exact UTF-8 bytes |

The loader rejects duplicate IDs, exact or whitespace-equivalent code, content
hash mismatches, groups shared between splits, and real-world repositories shared
between splits. All three splits must contain examples, and training must contain
both labels. It accepts at most 50,000 records and 50 MiB of JSONL. Fork clustering,
identifier-renamed near-duplicate detection and manual correctness review remain
responsibilities of corpus preparation. An upstream vulnerability/fix label still
requires scrutiny. A post-fix example can contain unrelated weaknesses.

## Results and artifacts

`report.json` records corpus provenance, content hash, split IDs, seed,
training revision, source-code digest, lockfile digest, installed dependency
versions, platform, model settings, fit time, vocabulary size, classification
metrics and latency. Metrics include per-class precision/recall/F1, macro-F1,
average precision, confusion counts and false-positive rate. Per-example p50 and
p95 latency include TF-IDF transformation and model prediction on up to 100 test
examples. They describe that machine and sample. They exclude parser and worker
startup time.

The scoped rule baseline wraps methods in a Java class when needed and treats
candidate presence as its positive classification. The report includes analysis
errors and partial-coverage counts. The rule sees a narrower source/sink subset
than the labels' complete application context. Review these limits alongside its
metrics.

A successful SVM run exports `svm.json` with the vocabulary, IDF vector,
coefficients and intercept. The report records its byte size and SHA-256.
Peak process RSS is recorded in KiB on Linux and is cumulative for that process. RF and
XGBoost are evaluated in memory. Their trained state is not exported by this
harness. No pickle deserialization is used. A failed run leaves a `FAILED`
marker and removes its incomplete results.

## Research inference

Take the expected SHA-256 from a trusted experiment report and score one Java
file explicitly.

```sh
uv run --extra ml traceward-ml predict \
  --model models/local/java-cwe89-run-001/svm.json \
  --sha256 <expected-hash-from-report> fixtures/java/Vulnerable.java
```

The loader verifies the exact file hash, feature contract, feature dimensions,
finite numeric weights and class ordering before computing a linear score. A
positive prediction produces `ml_suspected` with an uncalibrated SVM decision
value. A negative prediction produces `no_ml_signal`. These are offline
research outputs with no invented source-to-sink trace. The normal scanner keeps
its validated serving-model gate separate from this explicit research command.

The small synthetic corpus generated inside unit tests verifies pipeline
mechanics and split isolation. Its scores have no real-world accuracy meaning.
