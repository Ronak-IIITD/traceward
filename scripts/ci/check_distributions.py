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
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


def check_http(bin_dir: Path, work: Path, language: str, code: str, findings: list[dict]) -> None:
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
            request = Request(
                base + "/scans/snippet",
                json.dumps({"language": language, "code": code}).encode(),
                {"Content-Type": "application/json"},
            )
            with urlopen(request, timeout=10) as response:
                report = json.load(response)
            assert report["summary"]["errors"] == 0 and report["findings"] == findings
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
        api_cases = []
        for language, name, expected in [
            ("java", "Safe.java", 0),
            ("java", "Vulnerable.java", 1),
            ("python", "parameterized.py", 0),
            ("python", "concatenated.py", 1),
        ]:
            fixture = ROOT / "fixtures" / language / name
            code = fixture.read_text(encoding="utf-8")
            source = work / f"snippet{fixture.suffix}"
            source.write_text(code, encoding="utf-8")
            cli = subprocess.run(
                [bin_dir / "traceward", "scan", source.name, "--format", "json"],
                cwd=work,
                capture_output=True,
            )
            assert cli.returncode == expected, cli.stderr
            result = json.loads(cli.stdout)
            findings = result["findings"]
            assert len(findings) == expected and result["summary"]["errors"] == 0
            if findings:
                api_cases.append((language, code, findings))
        subprocess.run(
            [*install, f"traceward-core[api] @ {package.as_uri()}"], cwd=work, check=True
        )
        for language, code, findings in api_cases:
            check_http(bin_dir, work, language, code, findings)


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
