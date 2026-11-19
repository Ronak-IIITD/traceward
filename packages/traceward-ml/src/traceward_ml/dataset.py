"""Explicit provenance, split isolation, and bounded JSONL corpus loading."""

import hashlib
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_DATASET_BYTES = 50 * 1024 * 1024
MAX_RECORDS = 50_000
Split = Literal["train", "validation", "test"]


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal["1.0.0"]
    dataset_id: str = Field(min_length=1)
    source_url: str = Field(pattern=r"^https://\S+$")
    upstream_revision: str = Field(min_length=1)
    acquired_at: date
    license: str = Field(min_length=1)
    attribution: str = Field(min_length=1)
    label_provenance: str = Field(min_length=1)
    corpus_kind: Literal["synthetic", "real_world"]
    language: Literal["java"]
    cwe: Literal["CWE-89"]
    dataset_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    record_count: int = Field(ge=6, le=MAX_RECORDS)
    preprocessing: Literal["identity", "juliet-java-v1"] = "identity"
    preparation_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class JulietProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source_path: str = Field(min_length=1)
    source_file_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    label_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    flaw_lines: list[int]
    method_name: str
    start_column: int = Field(ge=1)
    end_column: int = Field(ge=1)
    sink_family: str
    flow_variant: str
    case_id: str
    label_scope: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_byte: int = Field(ge=0)
    end_byte: int = Field(ge=0)
    cwe: Literal["CWE-89"]
    input_source_family: str = Field(min_length=1)
    label_confidence: Literal["high", "medium", "low"]
    label_basis: str = Field(min_length=1)

    @field_validator("source_path")
    @classmethod
    def relative_path(cls, value: str) -> str:
        from pathlib import PurePosixPath

        if (
            "\\" in value
            or ":" in value
            or value.startswith("/")
            or ".." in PurePosixPath(value).parts
        ):
            raise ValueError("Source path must be relative")
        return value


class Example(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1)
    code: str = Field(min_length=1, max_length=65536)
    label: Literal[0, 1]
    split: Split
    group_id: str = Field(min_length=1)
    repository_id: str = Field(min_length=1)
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    provenance: JulietProvenance | None = None
    duplicate_cluster: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @field_validator("label", mode="before")
    @classmethod
    def integer_labels_only(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Labels must be integer 0 or 1")
        return value


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Input exceeds {limit} bytes")
    return data


def load_dataset(manifest_path: Path, dataset_path: Path) -> tuple[Manifest, list[Example]]:
    manifest = Manifest.model_validate_json(read_bounded(manifest_path, 64 * 1024))
    data = read_bounded(dataset_path, MAX_DATASET_BYTES)
    if sha256(data) != manifest.dataset_sha256:
        raise ValueError("Dataset content does not match its manifest hash")
    rows = data.splitlines()
    if len(rows) != manifest.record_count:
        raise ValueError("Dataset record count differs from its manifest")
    examples = [Example.model_validate_json(row) for row in rows]
    ids: set[str] = set()
    canonical_codes: set[str] = set()
    normalized_codes: set[str] = set()
    group_splits: dict[str, Split] = {}
    repository_splits: dict[str, Split] = {}
    for example in examples:
        if example.id in ids:
            raise ValueError("Duplicate example ID")
        ids.add(example.id)
        if len(example.code.encode("utf-8")) > 65536:
            raise ValueError("Example exceeds 64 KiB UTF-8 bytes")
        if sha256(example.code.encode("utf-8")) != example.content_sha256:
            raise ValueError("Example content does not match its recorded hash")
        if manifest.preprocessing == "juliet-java-v1":
            from traceward_ml.features import normalize_java

            if example.provenance is None:
                raise ValueError("Juliet examples require provenance")
            if example.provenance.input_source_family != example.group_id:
                raise ValueError("Input-source family and split group differ")
            canonical = sha256(normalize_java(example.code).encode())
            if canonical in canonical_codes:
                raise ValueError("Near-duplicate normalized Java examples detected")
            canonical_codes.add(canonical)
        normalized = sha256(" ".join(example.code.split()).encode("utf-8"))
        if normalized in normalized_codes:
            raise ValueError("Duplicate or whitespace-equivalent code detected")
        normalized_codes.add(normalized)
        if group_splits.setdefault(example.group_id, example.split) != example.split:
            raise ValueError("A group occurs in multiple splits")
        if manifest.corpus_kind == "real_world":
            if repository_splits.setdefault(example.repository_id, example.split) != example.split:
                raise ValueError("A real-world repository occurs in multiple splits")
    for split in ("train", "validation", "test"):
        if not any(row.split == split for row in examples):
            raise ValueError(f"Missing {split} split")
    if {row.label for row in examples if row.split == "train"} != {0, 1}:
        raise ValueError("Training split must contain both safe and vulnerable labels")
    return manifest, examples
