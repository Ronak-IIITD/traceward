"""Test ingestion mechanics with small, inert Java sources."""

import json
from pathlib import Path
from zipfile import ZipFile

import pytest
from traceward_ml.acquisition import load_source_lock, safe_path, validate_members, verify_archive
from traceward_ml.dataset import load_dataset, sha256
from traceward_ml.features import normalize_java
from traceward_ml.juliet import SOURCE_FAMILIES
from traceward_ml.preparation import deduplicate, partition, prepare_juliet, similar_pairs


@pytest.mark.parametrize("member", ["../case", "/case", "C:/case", "case\\child", "a/../b"])
def test_unsafe_archive_paths(member: str) -> None:
    with pytest.raises(ValueError, match="Unsafe archive path"):
        safe_path(member)


def test_zip_rejects_collisions_and_wrong_digest(tmp_path: Path) -> None:
    archive = tmp_path / "cases.zip"
    with ZipFile(archive, "w") as zipped:
        zipped.writestr("A.java", "test")
        zipped.writestr("a.java", "test")
    with ZipFile(archive) as zipped, pytest.raises(ValueError, match="case-colliding"):
        validate_members(zipped)
    with pytest.raises(ValueError, match="SHA-256"):
        verify_archive(archive, load_source_lock())


def test_normalization_removes_label_markers_and_local_names() -> None:
    assert normalize_java("void bad() { /* FLAW */ int value = 1; consume(value); }") == (
        normalize_java("void goodB2G(){ int index=1; consume(index); }")
    )
    assert "consume" in normalize_java("void goodB2G() { consume(1); }")


def test_near_duplicates_and_conflicts_are_handled_before_splitting() -> None:
    base = " ".join(f"token{n}" for n in range(150))
    assert list(similar_pairs([base, base + " extra"])) == [(1, 0)]
    same = {"code": "void bad() { consume(1); }", "input_source_family": "File"}
    kept, audit = deduplicate([{**same, "id": "a", "label": 0}, {**same, "id": "b", "label": 1}])
    assert not kept
    assert len(audit) == 1 and audit[0]["kept_id"] is None
    rows = [
        {"input_source_family": family, "label": label}
        for family in SOURCE_FAMILIES
        for label in (0, 1)
    ]
    assert partition(rows, 38) == partition(rows[::-1], 38)
    assert set(partition(rows, 38).values()) == {"train", "validation", "test"}


def test_preparation_integration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from traceward_ml import preparation

    archive = tmp_path / "cases.zip"
    lock = load_source_lock()
    manifest = []
    with ZipFile(archive, "w") as zipped:
        for index, family in enumerate(sorted(SOURCE_FAMILIES)):
            stem = f"CWE89_SQL_Injection__{family}_executeQuery_01"
            source = (
                f"/* TEMPLATE GENERATED TESTCASE FILE\nFilename: {stem}.java\n"
                f"CWE: 89 SQL Injection\nBadSource: {family}\n*/\n"
                f"class {stem} {{\n"
                f'void bad() {{ example{index}.executeQuery("A{index}"); }}\n'
                f'void goodB2G() {{ example{index}.executeQuery("B{index}"); }}\n'
                "}\n"
            )
            zipped.writestr(lock.source_prefix + stem + ".java", source)
            manifest.append(
                f'<file path="{stem}.java"><flaw line="7" name="CWE-089: fixture label"/></file>'
            )
        zipped.writestr("Java/manifest.xml", "<suite>" + "".join(manifest) + "</suite>")
        for member in lock.metadata_members:
            if member != "Java/manifest.xml":
                zipped.writestr(member, "Fixture metadata")
    fake_lock = lock.model_copy(
        update={"archive_bytes": archive.stat().st_size, "sha256": sha256(archive.read_bytes())}
    )
    monkeypatch.setattr(preparation, "load_source_lock", lambda: fake_lock)
    first = tmp_path / "first"
    second = tmp_path / "second"
    summary = prepare_juliet(archive, first, 38)
    assert summary == prepare_juliet(archive, second, 38)
    assert summary["kept"] == len(SOURCE_FAMILIES) * 2
    assert (first / "records.jsonl").read_bytes() == (second / "records.jsonl").read_bytes()
    _, rows = load_dataset(first / "manifest.json", first / "records.jsonl")
    assert all(
        row.provenance and row.provenance.flaw_lines == ([7] if row.label else []) for row in rows
    )
    records = [json.loads(line) for line in (first / "records.jsonl").read_text().splitlines()]
    next(row for row in records if row["split"] == "test")["group_id"] = "unexpected"
    data = "".join(json.dumps(row) + "\n" for row in records).encode()
    (first / "records.jsonl").write_bytes(data)
    metadata = json.loads((first / "manifest.json").read_text())
    metadata["dataset_sha256"] = sha256(data)
    (first / "manifest.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="family and split group"):
        load_dataset(first / "manifest.json", first / "records.jsonl")
