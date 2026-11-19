# Real-world Java SQL-injection research corpus

TraceWard acquired a local research subset of **MegaVul**, a published CVE-linked
function dataset by Ni et al. (MSR 2024). Acquisition uses the Java-only public
mirror at Hugging Face. Dataset labels are inherited from automated vulnerability
fix mining. Each record is associated with a real project, a CVE and a Git commit.
The labels have not received independent line-by-line security review. Three
positive functions were spot-checked against original project source at the fix
commit and its parent. PostgreSQL JDBC (CVE-2022-31197), Spring Data JPA
(CVE-2016-6652) and Apache SkyWalking (CVE-2020-13921) each contain the dataset
function in the parent source and change that function in the linked fix. These
checks verify a small sample of source provenance.

## Reproduce acquisition

From the repository root, with uv and network access available,

```sh
uv run --no-project --with pyarrow==26.0.1 python scripts/datasets/acquire_megavul.py
```

The command writes local files under `data/research/megavul-java-cwe89/`.
It downloads three pinned Parquet files totalling 16,329,003 bytes, verifies each
SHA-256 digest and applies a 20 MiB download limit per file. It never executes the
acquired code. Local output contains `records.jsonl`, `manifest.json`,
`provenance.jsonl` and `summary.json`, plus cached source files.

The mirror revision is `38ccb0e531503c682b7e0eab7e8e73897e3ce899`. Exact source
file digests, known project aliases, license snapshot and verified full fix-commit
and parent hashes are recorded in `scripts/datasets/megavul-java-sources.json` and
the acquisition script. All 33 distinct fix commits were resolved through GitHub's
API during acquisition. Source identity resolution and licenses were checked on
19 November 2026.

## Acquired subset

The reproducible output contains **921 Java functions from 20 projects linked to
28 CVEs**, including 78 upstream-labeled vulnerable functions and 843 upstream-labeled
non-vulnerable functions. Projects include PostgreSQL JDBC, Apache SkyWalking,
Spring Data JPA, OpenRefine, DHIS2 and JeecgBoot.

| Split | Non-vulnerable label | Vulnerable label | Total |
|---|---:|---:|---:|
| Training | 217 | 41 | 258 |
| Validation | 475 | 5 | 480 |
| Test | 151 | 32 | 183 |

The dataset SHA-256 is
`b989109ab78727a82f1996658d285bbfee213b4ffa53df32889fd53fe572e7e9`.
It covers 19 repository-family groups. The two related `xm-online` projects share
a group and split. All other groups use canonical repository identity. A fixed
hash order assigns groups to 60% training, 20% validation and 20% test by group
count. Group sizes differ, which produces the class imbalance shown above.
Splits are fixed before fitting and are never adjusted to improve reported scores.

Acquisition excludes test-file paths and test annotations, unresolved project
identities/licenses, oversized functions, exact or whitespace-equivalent duplicate
functions and conflicting duplicate labels. Exclusions from 1,897 CWE-89 candidate
rows were 735 unresolved license/identity rows, 217 test-code rows, six conflicting
label rows and 18 further duplicate rows. This does not detect every renamed clone,
fork or semantically equivalent function.

## Provenance and label limitations

MegaVul's positive labels identify functions changed in CVE-linked security fixes.
A changed function can include ancillary changes. Its negative labels identify
functions the mining pipeline did not label vulnerable. A negative label does not
certify safety. A model trained on these records learns from noisy function-level
labels and an imbalanced cohort.

The mirror includes generated instruction and explanation text. Acquisition uses
only the function source, binary upstream label and vulnerability provenance. It
discards that generated prose. Vulnerability evidence in scanner findings still
comes from the deterministic scanner.

The training harness measured an initial candidate corpus before a related-project
grouping correction. Any final result on this corpus is an **exploratory held-out
study**, because a previous variant's test results were already observed. Fixed
model settings may be compared, with that exposure disclosed. A future independent
final evaluation needs a newly locked corpus and human-reviewed labels.

## Reuse and distribution

MegaVul's upstream repository declares GPL-3.0. The Java mirror's dataset card has
no explicit license field. Original functions also retain their source-project
licenses, including Apache-2.0, MIT, BSD and GPL. Repository-level SPDX license
detection at acquisition does not establish the historical license of every file.
Sources with ambiguous or absent license detection were excluded.

Acquired source and trained artifacts stay in ignored local research directories.
This repository tracks the downloader and provenance metadata. Review dataset,
source-file and derivative-artifact obligations before redistributing the corpus
or model weights. Reproducible local experiments are available now.

## Sources

- [MegaVul upstream and license](https://github.com/Icyrockton/MegaVul/tree/2b34eb3685b2a215d44c08d34fe9cec0f49eada3)
- [MegaVul field specification](https://github.com/Icyrockton/MegaVul/blob/2b34eb3685b2a215d44c08d34fe9cec0f49eada3/SPECIFICATION.md)
- [Pinned Java mirror](https://huggingface.co/datasets/athrv/megavul-vulnerability-detection-java/tree/38ccb0e531503c682b7e0eab7e8e73897e3ce899)
- [Example PostgreSQL JDBC fix for CVE-2022-31197](https://github.com/pgjdbc/pgjdbc/commit/739e599d52ad80f8dcd6efedc6157859b1a9d637)
