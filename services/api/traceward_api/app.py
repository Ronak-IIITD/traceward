"""Local, stateless HTTP interface to the snippet scanner."""

import asyncio
import sys
from typing import Annotated, Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from traceward import __version__
from traceward.models import ScanResult
from traceward.registry import RULES, SUPPORTED_LANGUAGES

MAX_BODY = 256 * 1024
MAX_SOURCE = 64 * 1024
app = FastAPI(title="TraceWard", version=__version__)
slots = asyncio.Semaphore(2)


class Snippet(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    language: str = Field(json_schema_extra={"enum": [*sorted(SUPPORTED_LANGUAGES)]})
    code: Annotated[str, Field(min_length=1)]


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


def reject(status: int, code: str, message: str) -> JSONResponse:
    detail = ErrorDetail(code=code, message=message, request_id=uuid4().hex)
    return JSONResponse(ErrorResponse(error=detail).model_dump(), status_code=status)


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/version")
def version() -> dict[str, str]:
    return {"scanner_version": __version__, "schema_version": "1.0.0"}


@app.get("/api/v1/capabilities")
def capabilities() -> dict[str, Any]:
    return {"rules": [rule.model_dump() for rule in RULES.values()], "max_source_bytes": MAX_SOURCE}


@app.get("/api/v1/models")
def models() -> dict[str, Any]:
    return {"models": [], "status": "No validated model installed", "inference_enabled": False}


async def run_worker(source: bytes, language: str) -> ScanResult | JSONResponse:
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-m",
        "traceward_api.worker",
        language,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        async with asyncio.timeout(5):
            output, _ = await process.communicate(source)
        if process.returncode != 0:
            return reject(503, "SCAN_FAILED", "The worker could not complete this scan.")
        return ScanResult.model_validate_json(output)
    except TimeoutError:
        return reject(504, "SCAN_TIMEOUT", "The scan exceeded the time limit.")
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


@app.post(
    "/api/v1/scans/snippet",
    response_model=ScanResult,
    responses={
        status: {"model": ErrorResponse} for status in (400, 408, 413, 415, 422, 429, 503, 504)
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": Snippet.model_json_schema()}},
        }
    },
)
async def scan(request: Request) -> ScanResult | JSONResponse:
    if (
        request.headers.get("content-type", "").partition(";")[0].strip().lower()
        != "application/json"
    ):
        return reject(415, "INVALID_INPUT", "Use application/json.")
    if slots.locked():
        return reject(429, "RATE_LIMITED", "Both scan slots are busy. Try again shortly.")
    async with slots:
        body = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > MAX_BODY:
                        return reject(413, "INPUT_TOO_LARGE", "Request exceeds 256 KiB.")
                    body.extend(chunk)
            payload = Snippet.model_validate_json(body)
            source = payload.code.encode("utf-8")
        except (ValidationError, UnicodeError):
            return reject(
                422, "INVALID_INPUT", "Supply a language and a nonempty UTF-8 code string."
            )
        except TimeoutError:
            return reject(408, "INVALID_INPUT", "Request body timed out.")
        if payload.language not in SUPPORTED_LANGUAGES:
            supported = ", ".join(sorted(SUPPORTED_LANGUAGES))
            return reject(422, "UNSUPPORTED_LANGUAGE", f"Supported languages are {supported}.")
        if len(source) > MAX_SOURCE:
            return reject(413, "INPUT_TOO_LARGE", "Source exceeds 64 KiB.")
        if not source.strip() or b"\0" in source:
            return reject(422, "INVALID_INPUT", "Expected nonempty source text without NUL bytes.")
        try:
            return await run_worker(source, payload.language)
        except (OSError, ValidationError):
            return reject(503, "SCAN_FAILED", "The scanner is temporarily unavailable.")
