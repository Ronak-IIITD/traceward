"""Single-use Linux worker. Only the submitted source travels on stdin."""

import resource
import sys

from traceward_api.limits import MAX_RESULT, MAX_SOURCE


def main() -> int:
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (2, 3))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    from traceward.scanner import scan_snippet

    source = sys.stdin.buffer.read(MAX_SOURCE + 1)
    if len(source) > MAX_SOURCE:
        return 1
    result = scan_snippet(source.decode("utf-8"), language=sys.argv[1]).model_dump_json().encode()
    if len(result) > MAX_RESULT:
        return 1
    sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
