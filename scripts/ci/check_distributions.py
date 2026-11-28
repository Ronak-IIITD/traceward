"""Exercise each built distribution in a fresh environment outside the checkout."""

import argparse
import json
import socket
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


def check_rejected_input(endpoint: str) -> None:
    marker = "traceward-release-submission"
    oversized = json.dumps(
        {"language": "python", "code": "é" * (32 * 1024) + marker}, ensure_ascii=False
    ).encode()
    malformed = f'{{"language":"python","code":"{marker}'.encode()
    for body, status, code in [
        (oversized, 413, "INPUT_TOO_LARGE"),
        (malformed, 422, "INVALID_INPUT"),
    ]:
        request = Request(endpoint, body, {"Content-Type": "application/json"})
        try:
            response = urlopen(request, timeout=10)
        except HTTPError as error:
            response = error
        with response:
            assert response.status == status, (code, response.status)
            assert response.headers["Cache-Control"] == "no-store", code
            payload = response.read()
        assert marker.encode() not in payload, code
        detail = json.loads(payload)["error"]
        assert detail["code"] == code and detail["request_id"], code


def check_http(bin_dir: Path, work: Path, cases: list[tuple[str, str, dict[str, object]]]) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        base = f"http://127.0.0.1:{listener.getsockname()[1]}/api/v1"
        server = subprocess.Popen(
            [
                bin_dir / "uvicorn",
                "traceward_api.app:app",
                "--fd",
                str(listener.fileno()),
                "--no-access-log",
            ],
            cwd=work,
            pass_fds=(listener.fileno(),),
        )
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("Installed API failed to start")
                try:
                    with urlopen(base + "/health", timeout=1) as response:
                        assert json.load(response)["status"] == "ok"
                    break
                except URLError:
                    time.sleep(0.1)
            else:
                raise TimeoutError("Installed API did not become ready")
            endpoint = base + "/scans/snippet"
            check_rejected_input(endpoint)
            for language, code, cli_report in cases:
                request = Request(
                    endpoint,
                    json.dumps({"language": language, "code": code}).encode(),
                    {"Content-Type": "application/json"},
                )
                with urlopen(request, timeout=10) as response:
                    assert response.status == 200, language
                    assert response.headers["Cache-Control"] == "no-store", language
                    report = json.load(response)
                for field in (
                    "schema_version",
                    "scanner",
                    "coverage",
                    "summary",
                    "diagnostics",
                    "findings",
                ):
                    assert report[field] == cli_report[field], (language, field)
        finally:
            server.terminate()
            server.wait(timeout=10)


def check(package: Path, version: str) -> None:
    with TemporaryDirectory() as directory:
        work = Path(directory)
        bin_dir = work / "env/bin"
        subprocess.run(["uv", "venv", "--python", sys.executable, work / "env"], check=True)
        install = ["uv", "pip", "install", "--python", str(bin_dir / "python")]
        subprocess.run([*install, str(package)], cwd=work, check=True)
        assert (
            subprocess.check_output(
                [bin_dir / "traceward", "--version"], cwd=work, text=True
            ).strip()
            == f"TraceWard {version}"
        )
        fixtures = [
            ("java", "java/Safe.java", 0),
            ("java", "java/Vulnerable.java", 1),
            ("python", "python/parameterized.py", 0),
            ("python", "python/concatenated.py", 1),
            ("python", "flask-sqlite/parameterized.py", 0),
            ("python", "flask-sqlite/concatenated.py", 1),
            ("javascript", "javascript/parameterized.js", 0),
            ("javascript", "javascript/concatenated.js", 1),
            ("typescript", "typescript/parameterized.ts", 0),
            ("typescript", "typescript/concatenated.ts", 1),
            ("python", "sql-interpolation/python/parameterized.py", 0),
            ("python", "sql-interpolation/python/interpolated.py", 1),
            ("javascript", "sql-interpolation/javascript/parameterized.js", 0),
            ("javascript", "sql-interpolation/javascript/interpolated.js", 1),
            ("typescript", "sql-interpolation/typescript/parameterized.ts", 0),
            ("typescript", "sql-interpolation/typescript/interpolated.ts", 1),
        ]
        cases = [
            (language, Path(path).suffix, (ROOT / "fixtures" / path).read_text("utf-8"), expected)
            for language, path, expected in fixtures
        ]
        cases.append(("python", ".py", "def broken(:\n", 2))
        api_cases = []
        for language, suffix, code, expected in cases:
            source = work / f"snippet{suffix}"
            source.write_text(code, encoding="utf-8")
            cli = subprocess.run(
                [bin_dir / "traceward", "scan", source.name, "--format", "json"],
                cwd=work,
                capture_output=True,
            )
            assert cli.returncode == expected, cli.stderr
            report = json.loads(cli.stdout)
            assert report["coverage"]["partial"] is True
            if expected == 2:
                assert report["summary"]["files_analyzed"] == 0
                assert report["summary"]["errors"] and report["findings"] == []
                diagnostic = report["diagnostics"][0]
                assert diagnostic["code"] == "PARSE_ERROR" and diagnostic["location"]
            else:
                assert report["summary"]["files_analyzed"] == 1
                assert report["summary"]["errors"] == 0 and not report["diagnostics"]
                assert len(report["findings"]) == expected
            api_cases.append((language, code, report))
        subprocess.run(
            [*install, f"traceward-core[api] @ {package.as_uri()}"], cwd=work, check=True
        )
        check_http(bin_dir, work, api_cases)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--tag", help="Require the release tag to match the package version")
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    if args.tag is not None and args.tag != f"v{version}":
        parser.error(f"Expected release tag v{version}")
    for suffix in (".whl", ".tar.gz"):
        (artifact,) = args.directory.resolve().glob(f"*{suffix}")
        check(artifact, version)
