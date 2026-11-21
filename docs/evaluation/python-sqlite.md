# Python SQLite compatibility check

TraceWard scanned three complete source files from CPython v3.10.0 for the experimental rule `python.sqlite.concatenated-input` v0.1.0. These are the upstream documentation examples for placeholders, connection shortcuts and transactions. The checked revision is `b494f5935c92951e75597bfe1c8b1f3112fec270`. CPython documents its example code under the PSF and Zero-Clause BSD licenses. [Upstream examples](https://github.com/python/cpython/tree/b494f5935c92951e75597bfe1c8b1f3112fec270/Doc/includes/sqlite3) · [Upstream license](https://github.com/python/cpython/blob/b494f5935c92951e75597bfe1c8b1f3112fec270/Doc/license.rst#L74-L80)

Each file parsed with zero findings and zero errors. All three produced a partial-analysis warning.

| File | First reported limitation | Line |
| --- | --- | --- |
| `execute_1.py` | `UNSUPPORTED_FLOW` at a list of rows | 11 |
| `shortcut_methods.py` | `UNSUPPORTED_FLOW` at a list of rows | 3 |
| `ctx_manager.py` | `UNRESOLVED_BINDING` at the SQLite exception type | 15 |

In `execute_1.py`, the scanner followed cursor creation on line 4 and reached the parameterized insert on line 8 without a finding. The warning on line 11 marks the end of the supported path in that file. None of the three examples contains the modeled interactive input flow. Precision, recall and false-positive rate require an independently labeled corpus.

## Reproduce

Run the following from this checkout on Linux. It downloads each file to a temporary directory, verifies its SHA-256, and submits the original bytes to the CLI for static analysis.

```sh
(
  set -eu
  uv sync --locked --inexact
  tmp=$(mktemp -d)
  trap 'rm -r "$tmp"' EXIT
  upstream=https://raw.githubusercontent.com/python/cpython/b494f5935c92951e75597bfe1c8b1f3112fec270/Doc/includes/sqlite3
  while read -r digest file; do
    curl --fail --silent --show-error "$upstream/$file" -o "$tmp/$file"
    printf '%s  %s\n' "$digest" "$tmp/$file" | sha256sum --check
    uv run --no-sync traceward scan "$tmp/$file" --format json
  done <<'FILES'
3a4f401871000174f0960cff4c025f0efaf97934da1b65d205ce3008122b9fb5 execute_1.py
7b4c8d538341d0d3d8cbe10e1ddeae1e54934b2022ec648443447b467ab098ae shortcut_methods.py
52478a41521671e68721a3ae4cca7c8f03e94a2060275e00f2f6b4bc57ef6587 ctx_manager.py
FILES
)
```

## External evaluation before promotion

Freeze the rule revision before selecting a project-disjoint holdout of Python SQLite applications. Record each revision, path, license and source hash. Have reviewers label paths against the documented source, construction and sink criteria without seeing scanner output. Include parameterized queries and ambiguous receivers. Record disagreements and out-of-scope paths separately, match by source and sink location, then report counts for true positives, misses, false alarms and skipped paths. Publish metrics only when the corresponding denominators are available.
