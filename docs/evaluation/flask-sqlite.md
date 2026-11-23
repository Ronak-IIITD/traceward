# Flask request and SQLite compatibility check

The check uses two examples from Flask 3.1.2. The quickstart supplies a query-parameter expression, which this procedure places in a minimal Flask route with a constant response. The tutorial supplies a complete blueprint that binds form data to constant SQLite statements. The procedure downloads both upstream files at the pinned revision and scans them as source text. [Quickstart source](https://github.com/pallets/flask/blob/2c1b30d0503cfb064f1cb252e6614a06915a362a/docs/quickstart.rst#L539-L546) · [Tutorial blueprint](https://github.com/pallets/flask/blob/2c1b30d0503cfb064f1cb252e6614a06915a362a/examples/tutorial/flaskr/blog.py) · [Pallets BSD-3-Clause license](https://github.com/pallets/flask/blob/2c1b30d0503cfb064f1cb252e6614a06915a362a/LICENSE.txt)

| Input | Findings | Errors | Diagnostics |
| --- | ---: | ---: | --- |
| Wrapped quickstart query expression | 0 | 0 | None |
| Unmodified tutorial blueprint | 0 | 0 | `UNSUPPORTED_FLOW` at the Blueprint import on line 1 |

The quickstart scan completed through the constant return. The blueprint scan stopped before the database code. Both examples exercise parser and rule compatibility under partial coverage. Real-world precision and recall remain unmeasured.

## Reproduce

From the repository root, download the pinned files, verify their SHA-256 digests, and assemble the quickstart snippet. TraceWard analyzes the snippets without importing Flask or running a web app.

```sh
(
  set -eu
  uv sync --locked --inexact
  work=$(mktemp -d)
  trap 'rm -r "$work"' EXIT
  revision=2c1b30d0503cfb064f1cb252e6614a06915a362a
  base="https://raw.githubusercontent.com/pallets/flask/$revision"
  curl --proto '=https' --fail --silent --show-error --max-time 30 \
    "$base/docs/quickstart.rst" -o "$work/quickstart.rst"
  curl --proto '=https' --fail --silent --show-error --max-time 30 \
    "$base/examples/tutorial/flaskr/blog.py" -o "$work/blog.py"
  (
    cd "$work"
    sha256sum --check --strict <<'FILES'
7edf2b08a926b08149ba13d9d8124431244568b9de06791aeefff44d39491071  quickstart.rst
c49c5f6e3db32d74bfac13633fd328ec904cb7159d76ca78f6956432076c1fd7  blog.py
FILES
  )
  {
    printf '%s\n' 'from flask import Flask, request' '' 'app = Flask(__name__)' ''
    printf '%s\n' '@app.get("/search")' 'def search():'
    sed -n '543p' "$work/quickstart.rst"
    printf '%s\n' '    return "Request received"'
  } > "$work/quickstart-query.py"
  printf '%s  %s\n' 6056a9b9d5301a76480faf34183c02c9d30a450387f0b6a20b88b2a4d3377742 \
    "$work/quickstart-query.py" | sha256sum --check --strict
  uv run --no-sync traceward scan "$work/quickstart-query.py" --format json
  uv run --no-sync traceward scan "$work/blog.py" --format json
)
```

## External evaluation before promotion

Freeze the detector and grammar revisions. Label independent Flask projects with request arguments, string-built and parameterized queries, and unrelated objects named `request`. Preserve routes that need unsupported features as a separate coverage slice. Match findings to labeled source and sink spans, then report reviewed denominators for precision, recall, and skipped paths.

The [OWASP BenchmarkPython baseline](owasp-python-cwe89.md) tracks gaps on a
separate synthetic suite. The Flask holdout above remains the real-world
evaluation gate.
