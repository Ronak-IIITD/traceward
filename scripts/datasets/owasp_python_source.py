"""Read the published CWE-89 labels and source text from a pinned OWASP archive."""

import csv
import hashlib
import io
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile, ZipInfo

REVISION = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
ARCHIVE_SHA256 = "97761539307e95911be4b56d4227bc20b7b9ed479456a7a7a83a334c8f597ec4"
ARCHIVE_URL = f"https://codeload.github.com/OWASP-Benchmark/BenchmarkPython/zip/{REVISION}"
ARCHIVE_ROOT = f"BenchmarkPython-{REVISION}"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_LABEL_BYTES = 128 * 1024
MAX_CASE_BYTES = 64 * 1024
CASE_ID = re.compile(r"BenchmarkTest[0-9]{5}")


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    expected_finding: bool
    source: str = field(repr=False)


def _read_archive(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Expected a regular OWASP BenchmarkPython ZIP file")
        if metadata.st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("OWASP BenchmarkPython ZIP exceeds the archive size limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(MAX_ARCHIVE_BYTES + 1)
    finally:
        os.close(fd)
    if len(content) > MAX_ARCHIVE_BYTES:
        raise ValueError("OWASP BenchmarkPython ZIP exceeds the archive size limit")
    if hashlib.sha256(content).hexdigest() != ARCHIVE_SHA256:
        raise ValueError("OWASP BenchmarkPython ZIP checksum does not match the pinned archive")
    return content


def _index_members(archive: ZipFile) -> dict[str, ZipInfo]:
    members = archive.infolist()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("OWASP BenchmarkPython ZIP exceeds the member limit")
    indexed: dict[str, ZipInfo] = {}
    for info in members:
        name = info.filename.removesuffix("/")
        parts = name.split("/")
        if (
            parts[0] != ARCHIVE_ROOT
            or info.orig_filename != info.filename
            or "\\" in name
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise ValueError("Unexpected member path in OWASP BenchmarkPython ZIP")
        if name in indexed:
            raise ValueError("Duplicate member path in OWASP BenchmarkPython ZIP")
        indexed[name] = info
    return indexed


def _read_text(archive: ZipFile, info: ZipInfo, limit: int) -> str:
    mode = stat.S_IFMT(info.external_attr >> 16)
    if (
        info.is_dir()
        or mode not in {0, stat.S_IFREG}
        or info.compress_type not in {ZIP_STORED, ZIP_DEFLATED}
        or info.flag_bits & 1
    ):
        raise ValueError("Expected an unencrypted regular file in the OWASP BenchmarkPython ZIP")
    if info.file_size > limit:
        raise ValueError("OWASP BenchmarkPython member exceeds its size limit")
    with archive.open(info) as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("OWASP BenchmarkPython member exceeds its size limit")
    return content.decode("utf-8")


def _read_labels(labels: str) -> dict[str, bool]:
    selected: dict[str, bool] = {}
    identifiers: set[str] = set()
    for row in csv.reader(io.StringIO(labels.removeprefix("\ufeff")), strict=True):
        if not row or row[0].startswith("#"):
            continue
        if len(row) != 4:
            raise ValueError("Invalid row in OWASP BenchmarkPython expected results")
        case_id, category, expected, cwe = row
        if not CASE_ID.fullmatch(case_id) or expected not in {"true", "false"}:
            raise ValueError("Invalid case ID or label in OWASP BenchmarkPython expected results")
        if case_id in identifiers:
            raise ValueError("Duplicate case ID in OWASP BenchmarkPython expected results")
        identifiers.add(case_id)
        if (category == "sqli") != (cwe == "89"):
            raise ValueError("Conflicting category and CWE in OWASP expected results")
        if cwe == "89":
            selected[case_id] = expected == "true"
    if len(selected) != 16 or sum(selected.values()) != 5:
        raise ValueError("Expected 16 CWE-89 labels with five positives in the pinned benchmark")
    return selected


def load_cases(path: Path) -> list[BenchmarkCase]:
    """Verify the exact archive and load only its labeled CWE-89 cases, without extraction."""
    content = _read_archive(path)
    try:
        with ZipFile(io.BytesIO(content)) as archive:
            members = _index_members(archive)
            labels = _read_text(
                archive, members[f"{ARCHIVE_ROOT}/expectedresults-0.1.csv"], MAX_LABEL_BYTES
            )
            result = []
            for case_id, expected in sorted(_read_labels(labels).items()):
                member = members[f"{ARCHIVE_ROOT}/testcode/{case_id}.py"]
                source = _read_text(archive, member, MAX_CASE_BYTES)
                result.append(BenchmarkCase(case_id, expected, source))
            return result
    except (BadZipFile, KeyError, UnicodeError, csv.Error):
        raise ValueError("Invalid OWASP BenchmarkPython archive or expected results") from None
