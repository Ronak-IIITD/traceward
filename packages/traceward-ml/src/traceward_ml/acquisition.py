"""Pinned first-party Juliet acquisition with bounded, transactional ZIP extraction."""

import hashlib
import html
import json
import os
import re
import shutil
import stat
import tempfile
import time
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import ZipFile, ZipInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_ENTRIES = 60_000
MAX_TOTAL_BYTES = 400 * 1024 * 1024
MAX_MEMBER_BYTES = 10 * 1024 * 1024
MAX_SELECTED_BYTES = 100 * 1024 * 1024
MAX_RATIO = 200
TIMEOUT_SECONDS = 180


def validate_official_url(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname != "samate.nist.gov"
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or not parts.path.startswith("/SARD/")
    ):
        raise ValueError("Only first-party NIST SARD HTTPS URLs are permitted")
    return url


class SourceLock(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1.0.0"]
    dataset_id: Literal["nist-sard-juliet-java-1.3"]
    version: Literal["1.3"]
    source_page: str
    archive_url: str
    filename: Literal["juliet-java-1.3.zip"]
    archive_bytes: int = Field(gt=0, le=MAX_ARCHIVE_BYTES)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    checksum_origin: str = Field(min_length=1)
    reviewed_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    license: Literal["CC0-1.0"]
    license_scope: str = Field(min_length=1)
    license_statements: list[str] = Field(min_length=2, max_length=2)
    source_prefix: Literal["Java/src/testcases/CWE89_SQL_Injection/"]
    metadata_members: list[str]

    @field_validator("source_page", "archive_url")
    @classmethod
    def official_urls(cls, value: str) -> str:
        return validate_official_url(value)

    @model_validator(mode="after")
    def recognized_license(self) -> "SourceLock":
        statement = " ".join(self.license_statements)
        if "17 USC 105" not in statement or "CC0 1.0 Public Domain License" not in statement:
            raise ValueError("Pinned Juliet public-domain licensing evidence is required")
        for member in self.metadata_members:
            safe_path(member)
            if not (member == "Java/manifest.xml" or member.startswith("Java/doc/")):
                raise ValueError("Only documentation and manifest metadata may be selected")
        return self


def load_source_lock() -> SourceLock:
    return SourceLock.model_validate_json(
        files("traceward_ml").joinpath("sources/juliet-java-1.3.json").read_bytes()
    )


class OfficialRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_official_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_official(url: str):
    validate_official_url(url)
    response = build_opener(OfficialRedirects()).open(
        Request(url, headers={"User-Agent": "TraceWard-dataset-acquisition/0.1"}), timeout=30
    )
    validate_official_url(response.geturl())
    return response


def verify_source_page(lock: SourceLock) -> dict[str, str]:
    with open_official(lock.source_page) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("Official source page exceeds metadata limit")
    page = data.decode("utf-8")
    text = " ".join(html.unescape(re.sub(r"<[^>]+>", " ", page)).split())
    if "Juliet Java 1.3" not in text or urlsplit(lock.archive_url).path not in page:
        raise ValueError("Source page does not identify the pinned Juliet archive")
    if lock.sha256 not in text:
        raise ValueError("Official source page does not publish the pinned SHA-256")
    if any(" ".join(statement.split()) not in text for statement in lock.license_statements):
        raise ValueError("Official licensing statements changed or are absent")
    return {
        "source_page_sha256": hashlib.sha256(data).hexdigest(),
        "license_evidence_sha256": hashlib.sha256(
            "\n".join(lock.license_statements).encode()
        ).hexdigest(),
    }


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def verify_archive(archive: Path, lock: SourceLock) -> None:
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("Archive must be a regular file without symlink indirection")
    if archive.stat().st_size != lock.archive_bytes or file_digest(archive) != lock.sha256:
        raise ValueError("Juliet archive size or SHA-256 differs from the pinned source")


def fetch_archive(output: Path, source_lock: SourceLock | None = None) -> Path:
    lock = source_lock or load_source_lock()
    proof = verify_source_page(lock)
    if output.is_symlink():
        raise ValueError("Acquisition output cannot be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    archive = output / lock.filename
    if archive.exists() or archive.is_symlink():
        verify_archive(archive, lock)
    else:
        fd, name = tempfile.mkstemp(prefix=lock.filename + ".", dir=output)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream, open_official(lock.archive_url) as response:
                started = time.monotonic()
                size = 0
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > lock.archive_bytes or time.monotonic() - started > TIMEOUT_SECONDS:
                        raise ValueError("Archive download exceeded its byte or time budget")
                    stream.write(block)
            verify_archive(temporary, lock)
            temporary.replace(archive)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    receipt = {
        "dataset_id": lock.dataset_id,
        "source_page": lock.source_page,
        "archive_url": lock.archive_url,
        "archive_sha256": lock.sha256,
        "archive_bytes": lock.archive_bytes,
        "license": lock.license,
        "verified_at": datetime.now(UTC).isoformat(),
        **proof,
    }
    (output / "acquisition.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return archive


def safe_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
        or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
    ):
        raise ValueError("Unsafe archive path")
    return path


def validate_members(archive: ZipFile) -> list[ZipInfo]:
    members = archive.infolist()
    if len(members) > MAX_ENTRIES:
        raise ValueError("Archive entry limit exceeded")
    seen: set[str] = set()
    total = 0
    for info in members:
        path = safe_path(info.filename)
        identity = path.as_posix().casefold()
        if identity in seen:
            raise ValueError("Duplicate or case-colliding archive path")
        seen.add(identity)
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind not in {0, stat.S_IFDIR, stat.S_IFREG} or info.flag_bits & 1:
            raise ValueError("Symlink, special file or encrypted archive entry rejected")
        if info.is_dir() and kind == stat.S_IFREG:
            raise ValueError("Archive file/directory metadata conflicts")
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError("Archive member exceeds its byte limit")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Archive expanded byte limit exceeded")
        if info.file_size > max(info.compress_size, 1) * MAX_RATIO:
            raise ValueError("Archive compression ratio limit exceeded")
    # File-as-parent collisions are invalid even if their own paths are unique.
    regular = {PurePosixPath(i.filename).as_posix().casefold() for i in members if not i.is_dir()}
    for info in members:
        if any(p.as_posix().casefold() in regular for p in PurePosixPath(info.filename).parents):
            raise ValueError("Archive file is also used as a parent directory")
    return members


def extract_java_cwe89(archive: Path, target: Path, source_lock: SourceLock | None = None) -> dict:
    lock = source_lock or load_source_lock()
    verify_archive(archive, lock)
    if target.exists() or target.is_symlink():
        raise FileExistsError("Extraction destination must be new")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".juliet-extract-", dir=target.parent))
    try:
        extracted = {}
        with ZipFile(archive) as source:
            members = validate_members(source)
            selected = [
                i
                for i in members
                if not i.is_dir()
                and (
                    (i.filename.startswith(lock.source_prefix) and i.filename.endswith(".java"))
                    or i.filename in lock.metadata_members
                )
            ]
            if not any(i.filename.startswith(lock.source_prefix) for i in selected):
                raise ValueError("Archive contains no Java CWE-89 source")
            if not set(lock.metadata_members).issubset({i.filename for i in selected}):
                raise ValueError("Required Juliet documentation or manifest is absent")
            if sum(i.file_size for i in selected) > MAX_SELECTED_BYTES:
                raise ValueError("Selected source exceeds extraction byte limit")
            for info in selected:
                destination = stage.joinpath(*PurePosixPath(info.filename).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                # Reading to EOF verifies CRC; all individual sizes were bounded above.
                with source.open(info) as stream:
                    data = stream.read(MAX_MEMBER_BYTES + 1)
                if len(data) != info.file_size:
                    raise ValueError("Archive member size is inconsistent")
                destination.write_bytes(data)
                extracted[info.filename] = hashlib.sha256(data).hexdigest()
        receipt = {
            "dataset_id": lock.dataset_id,
            "archive_sha256": lock.sha256,
            "source_page": lock.source_page,
            "license": lock.license,
            "selected_files": extracted,
            "source_prefix": lock.source_prefix,
        }
        (stage / "extraction.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        stage.replace(target)
        return receipt
    finally:
        if stage.exists():
            shutil.rmtree(stage)
