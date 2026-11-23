import hashlib
import stat
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

from scripts.datasets import owasp_python_source as source

LABELS = f"{source.ARCHIVE_ROOT}/expectedresults-0.1.csv"
FIRST_CASE = f"{source.ARCHIVE_ROOT}/testcode/BenchmarkTest00000.py"
OTHER_CASE = f"{source.ARCHIVE_ROOT}/testcode/BenchmarkTest00016.py"
CASE_TEXT = "# inert benchmark fixture\npass\n"


def expected_rows() -> list[str]:
    rows = ["# test name, category, real vulnerability, cwe"]
    rows.extend(f"BenchmarkTest{i:05d},sqli,{'true' if i < 5 else 'false'},89" for i in range(16))
    rows.append("BenchmarkTest00016,xss,true,79")
    return rows


def make_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    rows: list[str] | None = None,
    omit: str | None = None,
    extra: tuple[str | ZipInfo, bytes] | None = None,
) -> Path:
    path = tmp_path / "archive.zip"
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        if omit != LABELS:
            archive.writestr(LABELS, "\n".join(expected_rows() if rows is None else rows))
        for index in reversed(range(16)):
            name = f"{source.ARCHIVE_ROOT}/testcode/BenchmarkTest{index:05d}.py"
            if omit != name:
                archive.writestr(name, CASE_TEXT)
        # The loader must never read the non-CWE-89 case.
        archive.writestr(OTHER_CASE, b"\xff")
        if extra:
            archive.writestr(*extra)
    monkeypatch.setattr(source, "ARCHIVE_SHA256", hashlib.sha256(path.read_bytes()).hexdigest())
    return path


def test_loads_only_labeled_cwe89_cases_without_extracting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = make_archive(tmp_path, monkeypatch)
    cases = source.load_cases(path)
    assert [case.case_id for case in cases] == [f"BenchmarkTest{i:05d}" for i in range(16)]
    assert sum(case.expected_finding for case in cases) == 5
    assert all(case.source == CASE_TEXT for case in cases)
    assert CASE_TEXT.strip() not in repr(cases)
    assert list(tmp_path.iterdir()) == [path]
    assert capsys.readouterr() == ("", "")


def test_rejects_tampering_before_parsing_zip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_archive(tmp_path, monkeypatch)
    path.write_bytes(b"not a ZIP file")
    with pytest.raises(ValueError, match="checksum does not match"):
        source.load_cases(path)


def test_rejects_a_directory_without_reading_it(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Expected a regular"):
        source.load_cases(tmp_path)


def test_rejects_oversized_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = make_archive(tmp_path, monkeypatch)
    monkeypatch.setattr(source, "MAX_ARCHIVE_BYTES", 32)
    with pytest.raises(ValueError, match="archive size limit"):
        source.load_cases(path)


def test_rejects_too_many_members(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = make_archive(tmp_path, monkeypatch)
    monkeypatch.setattr(source, "MAX_ARCHIVE_MEMBERS", 16)
    with pytest.raises(ValueError, match="member limit"):
        source.load_cases(path)


@pytest.mark.parametrize("relative", ["other/place.py", "/absolute.py", "./not-canonical.py"])
def test_rejects_noncanonical_or_unexpected_member_path(
    relative: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = relative if not relative.startswith("./") else f"{source.ARCHIVE_ROOT}/{relative}"
    path = make_archive(tmp_path, monkeypatch, extra=(name, b"pass"))
    with pytest.raises(ValueError, match="Unexpected member path"):
        source.load_cases(path)


def test_rejects_duplicate_members(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        path = make_archive(tmp_path, monkeypatch, extra=(FIRST_CASE, b"pass"))
    with pytest.raises(ValueError, match="Duplicate member path"):
        source.load_cases(path)


@pytest.mark.parametrize("entry", [LABELS, FIRST_CASE])
def test_rejects_missing_required_members(
    entry: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_archive(tmp_path, monkeypatch, omit=entry)
    with pytest.raises(ValueError, match="Invalid OWASP BenchmarkPython archive"):
        source.load_cases(path)


def test_rejects_symlink_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    info = ZipInfo(FIRST_CASE)
    info.create_system = 3
    info.external_attr = stat.S_IFLNK << 16
    path = make_archive(tmp_path, monkeypatch, omit=FIRST_CASE, extra=(info, b"elsewhere"))
    with pytest.raises(ValueError, match="Expected an unencrypted regular file"):
        source.load_cases(path)


@pytest.mark.parametrize("size_limit", ["MAX_LABEL_BYTES", "MAX_CASE_BYTES"])
def test_rejects_oversized_members(
    size_limit: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_archive(tmp_path, monkeypatch)
    monkeypatch.setattr(source, size_limit, 4)
    with pytest.raises(ValueError, match="member exceeds its size limit"):
        source.load_cases(path)


def test_decode_error_does_not_include_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = make_archive(tmp_path, monkeypatch, omit=FIRST_CASE, extra=(FIRST_CASE, b"secret\xff"))
    with pytest.raises(ValueError, match="Invalid OWASP BenchmarkPython archive") as error:
        source.load_cases(path)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ("BenchmarkTest00000,sqli,true", "Invalid row"),
        ("wrong-id,sqli,true,89", "Invalid case ID or label"),
        ("BenchmarkTest00000,sqli,maybe,89", "Invalid case ID or label"),
        ("BenchmarkTest00000,sqli,false,79", "Conflicting category and CWE"),
        ("BenchmarkTest00000,xss,false,89", "Conflicting category and CWE"),
        ("BenchmarkTest00001,sqli,true,89", "Duplicate case ID"),
        ("BenchmarkTest00000,sqli,false,89", "Expected 16 CWE-89 labels"),
    ],
)
def test_rejects_malformed_or_unexpected_labels(
    row: str, message: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = expected_rows()
    rows[1] = row
    path = make_archive(tmp_path, monkeypatch, rows=rows)
    with pytest.raises(ValueError, match=message):
        source.load_cases(path)
