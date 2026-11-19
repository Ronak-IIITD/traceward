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
FIXTURES = Path(__file__).resolve().parents[3] / "fixtures/java"


@pytest.mark.parametrize(("name", "count"), [("Safe", 0), ("Vulnerable", 1)])
def test_cli_and_api_agree(tmp_path: Path, name: str, count: int) -> None:
    code = (FIXTURES / f"{name}.java").read_text()
    path = tmp_path / "snippet.java"
    path.write_text(code)
    cli = subprocess.run(["traceward", "scan", str(path), "--format", "json"], capture_output=True)
    assert cli.returncode == count
    response = client.post(ENDPOINT, json={"language": "java", "code": code})
    assert response.status_code == 200
    result = ScanResult.model_validate(response.json())
    assert result.summary.findings == count
    assert result.findings == ScanResult.model_validate_json(cli.stdout).findings


def test_parse_failure_with_location() -> None:
    response = client.post(ENDPOINT, json={"language": "java", "code": "class A { int a }"})
    assert response.status_code == 200
    result = response.json()
    assert result["summary"]["errors"] and result["diagnostics"][0]["location"]


@pytest.mark.parametrize(
    ("data", "status", "error"),
    [
        ({"language": "java", "code": "🍵" * (MAX_SOURCE // 4 + 1)}, 413, "INPUT_TOO_LARGE"),
        ({"language": "python", "code": "private"}, 422, "UNSUPPORTED_LANGUAGE"),
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
    rule = client.get("/api/v1/capabilities").json()["rules"][0]
    assert rule == json.loads(subprocess.check_output(["traceward", "rules", "list"]))
    spec = client.get("/openapi.json").json()["paths"][ENDPOINT]["post"]
    assert "requestBody" in spec and "413" in spec["responses"]


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
