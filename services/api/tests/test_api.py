import asyncio
import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from traceward.models import ScanResult
from traceward_api.app import MAX_BODY, MAX_SOURCE, app

client = TestClient(app)
ENDPOINT = "/api/v1/scans/snippet"
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


@pytest.mark.parametrize(
    ("name", "count"),
    [
        ("java/Safe.java", 0),
        ("java/Vulnerable.java", 1),
        ("jdbc-resources/ResourceQuery.java", 1),
        ("jdbc-resources/BoundResourceQuery.java", 0),
        ("java-conditionals/ConditionalQuery.java", 1),
        ("java-conditionals/SeparateBranches.java", 0),
        ("python/concatenated.py", 1),
        ("python/cursor_concatenated.py", 1),
        ("python/parameterized.py", 0),
        ("flask-sqlite/concatenated.py", 1),
        ("flask-sqlite/parameterized.py", 0),
        ("javascript/concatenated.js", 1),
        ("javascript/parameterized.js", 0),
        ("typescript/concatenated.ts", 1),
        ("typescript/parameterized.ts", 0),
    ],
)
def test_cli_and_api_agree(tmp_path: Path, name: str, count: int) -> None:
    source = FIXTURES / name
    code = source.read_text()
    language = {
        ".java": "java",
        ".js": "javascript",
        ".py": "python",
        ".ts": "typescript",
    }[source.suffix]
    path = tmp_path / f"snippet{source.suffix}"
    path.write_text(code)
    cli = subprocess.run(["traceward", "scan", str(path), "--format", "json"], capture_output=True)
    assert cli.returncode == count
    response = client.post(ENDPOINT, json={"language": language, "code": code})
    assert response.status_code == 200
    result = ScanResult.model_validate(response.json())
    assert result.summary.findings == count
    cli_result = ScanResult.model_validate_json(cli.stdout)
    assert result.findings == cli_result.findings
    assert result.coverage == cli_result.coverage
    assert result.diagnostics == cli_result.diagnostics
    assert result.summary == cli_result.summary
    assert result.summary.files_analyzed == 1 and result.summary.errors == 0
    if source.parent.name == "flask-sqlite":
        assert not result.diagnostics


@pytest.mark.parametrize(
    ("language", "code"),
    [
        ("java", "class A { int a }"),
        ("javascript", "const value ="),
        ("python", "def broken(:\n"),
        ("typescript", "const value: string ="),
    ],
)
def test_parse_failure_with_location(language: str, code: str) -> None:
    response = client.post(ENDPOINT, json={"language": language, "code": code})
    assert response.status_code == 200
    result = response.json()
    assert result["summary"]["errors"] and result["diagnostics"][0]["location"]
    assert result["summary"]["files_analyzed"] == 0
    assert result["findings"] == []


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_source_is_analyzed_without_running_it(tmp_path: Path, language: str) -> None:
    marker = tmp_path / "executed"
    if language == "python":
        code = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    else:
        code = (
            'import { writeFileSync } from "node:fs";\n'
            f'writeFileSync({json.dumps(str(marker))}, "");\n'
        )
    response = client.post(ENDPOINT, json={"language": language, "code": code})
    assert response.status_code == 200
    result = ScanResult.model_validate(response.json())
    assert result.summary.files_analyzed == 1
    assert result.coverage.languages_detected == [language]
    assert not marker.exists()


@pytest.mark.parametrize(
    ("data", "status", "error"),
    [
        ({"language": "java", "code": "🍵" * (MAX_SOURCE // 4 + 1)}, 413, "INPUT_TOO_LARGE"),
        ({"language": "python", "code": "🍵" * (MAX_SOURCE // 4 + 1)}, 413, "INPUT_TOO_LARGE"),
        ({"language": "go", "code": "private"}, 422, "UNSUPPORTED_LANGUAGE"),
        ({"language": "java", "code": "private", "filename": "x"}, 422, "INVALID_INPUT"),
        ({"language": "java", "code": 42}, 422, "INVALID_INPUT"),
        ({"language": "java", "code": "   "}, 422, "INVALID_INPUT"),
        ({"language": "java", "code": "private\0"}, 422, "INVALID_INPUT"),
    ],
)
def test_validation_errors(data: dict, status: int, error: str) -> None:
    response = client.post(ENDPOINT, json=data)
    assert response.status_code == status
    detail = response.json()["error"]
    assert detail["code"] == error and detail["request_id"]
    assert "private" not in response.text


def test_body_limit_and_media_type() -> None:
    headers = {"content-type": "application/json"}
    body = iter([b" " * MAX_BODY, b" "])
    assert client.post(ENDPOINT, headers=headers, content=body).status_code == 413
    assert client.post(ENDPOINT, content="private").status_code == 415
    assert client.post(ENDPOINT, headers=headers, content="invalid").status_code == 422


def test_capacity_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("traceward_api.app.slots", asyncio.Semaphore(0))
    response = client.post(ENDPOINT, json={"language": "java", "code": "class X{}"})
    assert response.status_code == 429


def test_documented_routes_and_capabilities() -> None:
    assert client.get("/api/v1/health").json()["status"] == "ok"
    assert client.get("/api/v1/version").json()["schema_version"] == "1.0.0"
    assert client.get("/api/v1/models").json()["models"] == []
    rules = client.get("/api/v1/capabilities").json()["rules"]
    languages = ["java", "javascript", "python", "typescript"]
    assert {rule["language"] for rule in rules} == set(languages)
    for rule in rules:
        cli = subprocess.check_output(
            ["traceward", "rules", "list", "--language", rule["language"]]
        )
        assert rule == json.loads(cli)
    spec = client.get("/openapi.json").json()["paths"][ENDPOINT]["post"]
    schema = spec["requestBody"]["content"]["application/json"]["schema"]
    assert schema["properties"]["language"]["enum"] == languages
    assert "413" in spec["responses"]


def test_failed_worker_returns_transient_error_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unavailable(*args, **kwargs):
        raise OSError("private path")

    payload = {"language": "java", "code": "class A {}"}
    with monkeypatch.context() as patch:
        patch.setattr(asyncio, "create_subprocess_exec", unavailable)
        response = client.post(ENDPOINT, json=payload)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SCAN_FAILED"
    assert "private path" not in response.text
    assert client.post(ENDPOINT, json=payload).status_code == 200
