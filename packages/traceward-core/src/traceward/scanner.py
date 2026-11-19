"""Local discovery with bounded reads, no symlink following and explicit diagnostics."""

import os
import stat
import time
import uuid
from fnmatch import fnmatch
from pathlib import Path

from traceward.java import JavaAnalysis
from traceward.models import Diagnostic, ScanResult, Source

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_FILES = 2000
MAX_ENTRIES = 20_000
EXCLUDED = {".git", ".venv", "node_modules", "vendor", "dist", "build", "target"}
LANGUAGES = {
    ".java": "java",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
}


def new_result(kind: str) -> ScanResult:
    return ScanResult(
        scan_id=f"scan_{uuid.uuid4().hex}", source=Source.model_validate({"kind": kind})
    )


def analyze_bytes(result: ScanResult, data: bytes, path: str) -> None:
    if "java" not in result.coverage.languages_detected:
        result.coverage.languages_detected.append("java")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        result.diagnostics.append(
            Diagnostic(
                code="INVALID_ENCODING",
                message=f"{path}: expected UTF-8 Java source.",
                level="error",
            )
        )
        return
    if b"\0" in data:
        result.diagnostics.append(
            Diagnostic(
                code="BINARY_INPUT",
                message=f"{path}: binary content rejected.",
                level="error",
            )
        )
        return
    analysis = JavaAnalysis(data, path)
    analysis.analyze()
    result.findings.extend(analysis.findings)
    result.diagnostics.extend(analysis.diagnostics)
    if not any(d.level == "error" for d in analysis.diagnostics):
        result.summary.files_analyzed += 1


def finish(result: ScanResult, start: float) -> ScanResult:
    result.summary.findings = len(result.findings)
    result.summary.errors = sum(d.level == "error" for d in result.diagnostics)
    result.coverage.languages_detected.sort()
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


def scan_snippet(code: str, language: str = "java") -> ScanResult:
    start = time.monotonic()
    result = new_result("snippet")
    result.summary.files_discovered = 1
    if language != "java":
        result.diagnostics.append(
            Diagnostic(
                code="UNSUPPORTED_LANGUAGE",
                message="Only the experimental Java adapter is enabled.",
                level="error",
            )
        )
    elif len(code.encode("utf-8")) > MAX_FILE_BYTES:
        result.diagnostics.append(
            Diagnostic(
                code="INPUT_TOO_LARGE",
                message="Snippet exceeds the 2 MiB limit.",
                level="error",
            )
        )
    else:
        analyze_bytes(result, code.encode("utf-8"), "snippet.java")
    return finish(result, start)


def scan_path(path: Path, excludes: tuple[str, ...] = ()) -> ScanResult:
    start = time.monotonic()
    result = new_result("directory" if path.is_dir() else "file")
    if path.is_symlink() or not path.exists():
        result.diagnostics.append(
            Diagnostic(
                code="INVALID_PATH",
                message="Input must exist and must not be a symlink.",
                level="error",
            )
        )
        return finish(result, start)
    if not path.is_dir() and not path.is_file():
        result.diagnostics.append(
            Diagnostic(
                code="INVALID_PATH",
                message="Only regular files and directories are supported.",
                level="error",
            )
        )
        return finish(result, start)
    root = path.resolve() if path.is_dir() else path.resolve().parent
    pending = [path]
    entries = 0
    total = 0
    while pending:
        current = pending.pop()
        entries += 1
        if entries > MAX_ENTRIES or time.monotonic() - start > 120:
            result.diagnostics.append(
                Diagnostic(
                    code="SCAN_LIMIT",
                    message="Discovery or scan time budget exhausted.",
                )
            )
            break
        relative = current.relative_to(path).as_posix() if path.is_dir() else current.name
        if any(fnmatch(relative, pattern) for pattern in excludes):
            continue
        if current.is_symlink():
            result.diagnostics.append(
                Diagnostic(code="SYMLINK_SKIPPED", message="Symlink skipped.")
            )
            continue
        try:
            if current.is_dir():
                if current.name not in EXCLUDED or current == path:
                    # Bound each directory enumeration as well as the total traversal.
                    children = []
                    with os.scandir(current) as directory:
                        for entry in directory:
                            children.append(Path(entry.path))
                            if len(children) + entries + len(pending) > MAX_ENTRIES:
                                result.diagnostics.append(
                                    Diagnostic(
                                        code="SCAN_LIMIT",
                                        message="Directory entry budget exhausted.",
                                    )
                                )
                                break
                    pending.extend(sorted(children, reverse=True))
                continue
            language = LANGUAGES.get(current.suffix.lower())
            if language is None:
                if current == path:
                    result.diagnostics.append(
                        Diagnostic(
                            code="UNSUPPORTED_LANGUAGE",
                            message="Unsupported input file type.",
                            level="error",
                        )
                    )
                continue
            result.summary.files_discovered += 1
            if result.summary.files_discovered > MAX_FILES:
                result.diagnostics.append(
                    Diagnostic(code="FILE_LIMIT", message="File cap reached.")
                )
                break
            if language not in result.coverage.languages_detected:
                result.coverage.languages_detected.append(language)
            if language != "java":
                result.diagnostics.append(
                    Diagnostic(
                        code="UNSUPPORTED_LANGUAGE",
                        message=f"{language} detection is not implemented.",
                        level="error" if current == path else "warning",
                    )
                )
                continue
            # O_NOFOLLOW closes the final-component symlink race; reject devices/FIFOs.
            descriptor = os.open(current, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    result.diagnostics.append(
                        Diagnostic(
                            code="SPECIAL_FILE_SKIPPED",
                            message="Non-regular source file skipped.",
                        )
                    )
                    continue
                data = stream.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                result.diagnostics.append(
                    Diagnostic(
                        code="INPUT_TOO_LARGE",
                        message="Java file exceeds 2 MiB; skipped.",
                    )
                )
                continue
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                result.diagnostics.append(
                    Diagnostic(
                        code="BYTE_LIMIT",
                        message="Total 20 MiB scan budget exhausted.",
                    )
                )
                break
            analyze_bytes(result, data, current.resolve().relative_to(root).as_posix())
        except OSError:
            result.diagnostics.append(
                Diagnostic(
                    code="READ_ERROR",
                    message="Cannot read an input entry.",
                    level="error",
                )
            )
    if result.summary.files_discovered == 0:
        result.diagnostics.append(
            Diagnostic(
                code="NO_SUPPORTED_FILES",
                message="No supported source files discovered.",
            )
        )
    return finish(result, start)
