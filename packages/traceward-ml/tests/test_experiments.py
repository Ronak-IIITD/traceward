"""Synthetic unit tests validate the harness mechanics, not detection accuracy."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from traceward_ml.dataset import load_dataset, sha256
from traceward_ml.experiment import run_experiment
from traceward_ml.inference import load_artifact, score_code


def corpus(tmp_path: Path) -> tuple[Path, Path, list[dict]]:
    rows = []
    for index, split in enumerate(("train", "validation", "test")):
        for label in (0, 1):
            code = f"class Case{index}{label} {{ void f() {{ "
            code += (
                'String sql = "unsafe" + request.getParameter("q");' if label else 'bind("safe");'
            )
            code += f" int unique{index} = {index}; }} }}"
            rows.append(
                {
                    "id": f"{split}-{label}",
                    "code": code,
                    "label": label,
                    "split": split,
                    "group_id": split,
                    "repository_id": split,
                    "content_sha256": sha256(code.encode()),
                }
            )
    dataset = tmp_path / "data.jsonl"
    dataset.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "dataset_id": "synthetic-unit-tests-only",
                "source_url": "https://example.org/unit-tests",
                "upstream_revision": "unit-test",
                "acquired_at": "2026-11-19",
                "license": "test fixture",
                "attribution": "TraceWard tests",
                "label_provenance": "Unit-test labels for pipeline mechanics",
                "corpus_kind": "synthetic",
                "language": "java",
                "cwe": "CWE-89",
                "dataset_sha256": sha256(dataset.read_bytes()),
                "record_count": len(rows),
            }
        )
    )
    return manifest, dataset, rows


def rewrite(manifest: Path, dataset: Path, rows: list[dict]) -> None:
    dataset.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    metadata = json.loads(manifest.read_text())
    metadata["dataset_sha256"] = sha256(dataset.read_bytes())
    manifest.write_text(json.dumps(metadata))


def test_train_only_fit_and_safe_artifact(tmp_path: Path) -> None:
    manifest_path, dataset_path, _ = corpus(tmp_path)
    manifest, examples = load_dataset(manifest_path, dataset_path)
    output = tmp_path / "output"
    report = run_experiment(
        manifest, examples, output, ["svm", "rf", "xgboost"], 38, "a" * 40, "b" * 64
    )
    assert report["production_enabled"] is False
    assert report["corpus_kind"] == "synthetic"
    record = report["models"]["svm"]
    artifact = load_artifact(output / "svm.json", record["artifact"]["sha256"])
    assert "unique0" in artifact.vocabulary
    assert "unique1" not in artifact.vocabulary and "unique2" not in artifact.vocabulary
    assert score_code(artifact, examples[0].code)["label"] in (0, 1)
    assert record["metrics"]["test"]["count"] == 2
    assert record["latency"]["samples"] == 2
    assert record["artifact"]["bytes"] == (output / "svm.json").stat().st_size
    assert (
        json.loads((output / "report.json").read_text())["dataset"]["dataset_id"]
        == manifest.dataset_id
    )
    with pytest.raises(ValueError, match="digest"):
        load_artifact(output / "svm.json", "0" * 64)
    with pytest.raises(FileExistsError):
        run_experiment(manifest, examples, output, ["svm"], 38, "a" * 40, "b" * 64)


def test_changed_dataset_hash_rejected(tmp_path: Path) -> None:
    manifest, dataset, _ = corpus(tmp_path)
    dataset.write_bytes(dataset.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="manifest hash"):
        load_dataset(manifest, dataset)


@pytest.mark.parametrize(
    "change", ["group", "repository", "duplicate", "content_hash", "label", "boolean_label"]
)
def test_split_and_label_validation(tmp_path: Path, change: str) -> None:
    manifest, dataset, rows = corpus(tmp_path)
    if change == "group":
        rows[2]["group_id"] = rows[0]["group_id"]
    elif change == "repository":
        metadata = json.loads(manifest.read_text())
        metadata["corpus_kind"] = "real_world"
        manifest.write_text(json.dumps(metadata))
        rows[2]["repository_id"] = rows[0]["repository_id"]
    elif change == "duplicate":
        rows[2]["code"] = rows[0]["code"]
        rows[2]["content_sha256"] = rows[0]["content_sha256"]
    elif change == "content_hash":
        rows[2]["content_sha256"] = "0" * 64
    elif change == "boolean_label":
        rows[2]["label"] = True
    else:
        rows[2]["label"] = "1"
    rewrite(manifest, dataset, rows)
    with pytest.raises((ValueError, ValidationError)):
        load_dataset(manifest, dataset)


def test_bad_artifact_feature_contract(tmp_path: Path) -> None:
    manifest_path, dataset_path, _ = corpus(tmp_path)
    manifest, examples = load_dataset(manifest_path, dataset_path)
    output = tmp_path / "output"
    run_experiment(manifest, examples, output, ["svm"], 38, "a" * 40, "b" * 64)
    artifact_path = output / "svm.json"
    data = json.loads(artifact_path.read_text())
    data["feature_contract"]["version"] = "incompatible"
    artifact_path.write_text(json.dumps(data))
    with pytest.raises(ValidationError, match="incompatible"):
        load_artifact(artifact_path, sha256(artifact_path.read_bytes()))


def test_existing_invalid_output_not_modified(tmp_path: Path) -> None:
    manifest_path, dataset_path, _ = corpus(tmp_path)
    manifest, examples = load_dataset(manifest_path, dataset_path)
    with pytest.raises(ValueError, match="Unknown model"):
        run_experiment(manifest, examples, tmp_path / "output", ["unknown"], 38, "a" * 40, "b" * 64)
    assert not (tmp_path / "output").exists()


def test_known_json_linear_scores(tmp_path: Path) -> None:
    from traceward_ml.experiment import FEATURE_CONTRACT

    artifact_path = tmp_path / "model.json"
    artifact_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "usage": "offline_research_only",
                "feature_contract": FEATURE_CONTRACT,
                "vocabulary": {"unsafe": 0},
                "idf": [1.0],
                "coefficients": [2.0],
                "intercept": -1.0,
                "classes": [0, 1],
                "decision_value": "test margin",
            }
        )
    )
    artifact = load_artifact(artifact_path, sha256(artifact_path.read_bytes()))
    signal = score_code(artifact, "unsafe unsafe")
    assert signal["label"] == 1 and signal["decision_value"] == pytest.approx(1.0)
    assert signal["evidence_level"] == "ml_suspected"
    unseen = score_code(artifact, "new vocabulary")
    assert unseen["label"] == 0 and unseen["decision_value"] == pytest.approx(-1.0)
