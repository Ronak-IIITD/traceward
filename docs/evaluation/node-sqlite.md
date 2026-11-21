# Node.js SQLite compatibility check

This check uses two JavaScript examples published in the Node.js v24.11.1 SQLite documentation. Both use an in-memory database with constant values. The first shows conventional prepared statements and the second shows SQL tag-store bindings. Node.js contributors hold the copyright, and the procedure below fetches both examples from the pinned revision. [Pinned example source](https://github.com/nodejs/node/blob/18aefb2d2b36938316d27b5cb53089e97632f0c3/doc/api/sqlite.md) · [Node.js license](https://github.com/nodejs/node/blob/18aefb2d2b36938316d27b5cb53089e97632f0c3/LICENSE)

Both examples parsed with zero findings and zero errors. Each reported one `UNSUPPORTED_FLOW` warning.

| Example | Result | First skipped expression |
| --- | --- | --- |
| `basic-usage.mjs` | Reached the constant multiline SQL, prepared statements, and parameter bindings. | Line 19, `console.log(query.all())` |
| `sql-tag-store.mjs` | Reached the database construction. | Line 4, `db.createTagStore()` |

These examples measure parser and rule compatibility on two published JavaScript snippets. Neither uses command-line input. Independent detection accuracy remains unmeasured.

## Reproduce

Run from the repository root. This downloads the pinned Markdown file, verifies its SHA-256, extracts the exact source lines from the two code blocks, verifies both excerpts, and scans them as source text.

```sh
(
  set -eu
  uv sync --locked --inexact
  tmp=$(mktemp -d)
  trap 'rm -r "$tmp"' EXIT
  revision=18aefb2d2b36938316d27b5cb53089e97632f0c3
  curl --proto '=https' --fail --silent --show-error --max-time 30 \
    "https://raw.githubusercontent.com/nodejs/node/$revision/doc/api/sqlite.md" \
    -o "$tmp/sqlite.md"
  printf '%s  %s\n' aff3956460a6b628debed4248e45535aca1d0f8d4b6031a504a7f6f773805a5d "$tmp/sqlite.md" \
    | sha256sum --check --strict
  sed -n '30,49p' "$tmp/sqlite.md" > "$tmp/basic-usage.mjs"
  sed -n '450,473p' "$tmp/sqlite.md" > "$tmp/sql-tag-store.mjs"
  while read -r digest file; do
    printf '%s  %s\n' "$digest" "$tmp/$file" | sha256sum --check --strict
    uv run --no-sync traceward scan "$tmp/$file" --format json
  done <<'FILES'
2cbb2c47060e004a9244b9073bc8d2ad8fc585f70a844b93b8b7d1748f9dabc7 basic-usage.mjs
753446fbbe215a5a77f97a2999f89ca6f625dbbfcb8b7c9e0ac5fa8dc1980e11 sql-tag-store.mjs
FILES
)
```

## External evaluation before promotion

Freeze rule and grammar versions, then select a project-disjoint holdout of JavaScript and TypeScript SQLite applications. Record source revisions, hashes, and licenses. Label command-line input boundaries, dynamic SQL, constant prepared statements, unrelated receivers, and unsupported paths independently of scanner output. Match findings by source and sink locations and report false alarms, misses, and skipped cases separately. Publish metrics with the reviewed labels and denominators.
