# Juliet Java 1.3 CWE-89

TraceWard's offline pipeline builds a method corpus from [NIST SARD suite 111](https://samate.nist.gov/SARD/test-suites/111).
The source lock records the official archive URL, license statements, size and
published SHA-256. NIST describes the test suite as public domain in the US and
applies CC0 1.0 to foreign rights it may claim. The downloader verifies the
published digest and licensing statements before accepting a cached or fresh
archive. Bundled executable and third-party dependencies are outside the
extraction allowlist. Java is read as source and never executed.

## Reproduce

Run from the repository root. Preparation and training each take a new output
directory so earlier runs stay available.

```sh
uv run --locked --extra ml traceward-ml fetch-juliet \
  --output data/research/juliet-java-1.3
uv run --locked --extra ml traceward-ml prepare-juliet \
  --archive data/research/juliet-java-1.3/juliet-java-1.3.zip \
  --output data/research/juliet-prepared-v1 --seed 38
uv run --locked --extra ml traceward-ml train \
  --manifest data/research/juliet-prepared-v1/manifest.json \
  --dataset data/research/juliet-prepared-v1/records.jsonl \
  --output models/local/juliet-java-cwe89-v1 \
  --code-revision "$(git rev-parse HEAD)" --lock uv.lock --seed 38
```

The importer verifies the ZIP before extracting Java CWE-89 source and selected
documentation into a temporary directory. It rejects unsafe paths, archive
collisions, special files, excessive expansion and oversized archives.

Juliet's bundled XML contains an unmatched closing tag outside CWE-89. For the
known manifest digest only, the importer parses each intact CWE-89 file element
as XML and checks that every such file entry was accounted for. It neither
rewrites flaw lines nor uses this fallback for unknown malformed manifests.
The raw method bytes and provenance are retained locally. Tree-sitter associates
the generated class and method with the upstream filename, source family,
CWE and flaw lines. Positive examples require a flaw line inside `bad`.
Safe examples require a documented `goodB2G` or `goodG2B` name and no flaw line
inside the method. Both classes require a local sink. Dispatchers, helper-only
methods and inconclusive cases receive skip diagnostics. Confidence describes
agreement with synthetic testcase intent.

Training first removes comments and method modifiers, masks declaration names
and renames local variables using the Java syntax tree. The normalization
preserves API names, operators, and literals. Identical normalized methods and
near duplicates are clustered globally. Near duplicates use a 95% Jaccard
threshold on sets of five-token shingles. Conflicting-label clusters are dropped,
and each remaining cluster retains a deterministic representative. A local audit
records the provenance of every cluster member and the representative. Families
are then assigned to three disjoint partitions using seed 38. The preparation
manifest records family membership, counts, provenance and content hashes.

The four fixed baselines fit their own TF-IDF on training examples. Reports
record per-split precision, recall, macro-F1, confusion matrices and false
positive rates. The output contains fitted TF-IDF and classifier parameters in
four local JSON artifacts. The experiment confirms that all four reloaded
artifacts agree with the fitted predictions. Use the digest from a trusted
report when loading an artifact. Dataset source and artifact weights stay local.

The evaluation is synthetic and method scoped. Benchmark template conventions
remain a possible source of shortcuts even after normalization and duplicate
removal. Results are research measurements and leave the production scanner's
model serving disabled.

## Measured run

The pinned archive yielded 4,800 candidate methods. Preparation retained 2,403
methods across 12 input-source families.

| Partition | Families | Safe | Vulnerable |
| --- | ---: | ---: | ---: |
| Train | 8 | 1,009 | 532 |
| Validation | 2 | 306 | 168 |
| Test | 2 | 247 | 141 |

| Model | Test macro-F1 | Vulnerable precision | Vulnerable recall | False positive rate |
| --- | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.5851 | 0.9394 | 0.2199 | 0.0081 |
| Linear SVM | 0.5479 | 0.9600 | 0.1702 | 0.0040 |
| Random Forest | 0.9944 | 0.9860 | 1.0000 | 0.0081 |
| XGBoost | 1.0000 | 1.0000 | 1.0000 | 0.0000 |

The [aggregate report](juliet-java-cwe89-report.json) includes confusion
matrices, preprocessing and source digests, and model artifact hashes. An
earlier engineering run used different normalization, so this comparison is
exploratory. The high tree-model scores apply to these generated methods only.
Model promotion still requires an untouched, independently reviewed real-world
evaluation.
