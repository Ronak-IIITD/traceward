# Java CWE-89 baseline measurements

These measurements come from the locally acquired MegaVul Java CWE-89 research
corpus described in the acquisition documentation. The dataset contains 921
functions from 20 upstream repositories and 19 repository-family groups. Labels
come from upstream automated CVE/fix mining and require independent review.
The exact corpus hash and split counts are in the machine-readable report.

| Partition | Negative label | Positive label | Total |
|---|---:|---:|---:|
| Training | 217 | 41 | 258 |
| Validation | 475 | 5 | 480 |
| Test | 151 | 32 | 183 |

Related xm-online repositories share one group. Each repository and family occurs
in a single partition. Exact and whitespace-equivalent duplicates were removed
before the manifest was frozen. Identifier-renamed near duplicates can remain.
Class imbalance and the small number of held-out projects limit generalization.

## Measured test results

All model settings and the SVM threshold were fixed before these measurements.

| Classifier | True positives | False positives | False negatives | Positive precision | Positive recall | Macro-F1 |
|---|---:|---:|---:|---:|---:|---:|
| Linear SVM | 0 | 0 | 32 | 0.0000 | 0.0000 | 0.4521 |
| Random Forest | 0 | 0 | 32 | 0.0000 | 0.0000 | 0.4521 |
| XGBoost | 2 | 1 | 30 | 0.6667 | 0.0625 | 0.5103 |
| Scoped Java rule baseline | 0 | 0 | 32 | 0.0000 | 0.0000 | 0.4521 |

The rule baseline completed all 183 test method scans without parse errors and
reported partial coverage on every scan. Its recognized servlet-to-JDBC flow did
not match any positive in this held-out method cohort. Whole-application context
and other input sources are absent from that rule's modeled scope.

SVM and RF missed every test positive. XGBoost detected two of 32. These results
keep model serving disabled in the normal scanner. The explicit offline research
prediction command remains available for investigating scores and errors.

The experiment is exploratory. An earlier repository-only partition was measured
before related repositories were grouped together. Fixed baselines were then
rerun with family isolation, followed by metadata-only instrumentation reruns.
Features, hyperparameters and decision thresholds were unchanged. A future model
selection exercise needs another untouched test set.

The training run used an uncommitted working tree based on the recorded Git
revision. The report identifies the exact training source files and lockfile by
SHA-256 so the base revision cannot be mistaken for the complete training code.
Hardware, dependency versions, fit time, vocabulary size, per-split confusion
matrices and measured per-example latency are recorded in
[the aggregate JSON report](megavul-java-cwe89-report.json). Corpus source and SVM
weights remain in ignored local directories. The SVM JSON artifact's hash and size
appear in the report for reproducible offline research use.
