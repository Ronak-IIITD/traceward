"""Build family-disjoint Juliet datasets from the pinned official archive."""

import json
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterator
from importlib.metadata import version
from pathlib import Path
from typing import Any

from traceward_ml.acquisition import extract_java_cwe89, load_source_lock
from traceward_ml.dataset import Example, Manifest, Split, load_dataset, sha256
from traceward_ml.features import NORMALIZATION, normalize_java
from traceward_ml.juliet import extract_examples

SHINGLE_WIDTH = 5
NEAR_PERCENT = 95
MAX_CANONICAL = 5000


def similar_pairs(texts: list[str]) -> Iterator[tuple[int, int]]:
    """Find near-identical normalized templates with exact shingle Jaccard checks."""
    if len(texts) > MAX_CANONICAL:
        raise ValueError("Normalized Juliet examples exceed the deduplication budget")
    shingles = []
    for text in texts:
        tokens = text.split()
        shingles.append(
            {tuple(tokens[i : i + SHINGLE_WIDTH]) for i in range(len(tokens) - SHINGLE_WIDTH + 1)}
        )
    frequency = Counter(shingle for document in shingles for shingle in document)
    index: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for i, left in enumerate(shingles):
        # A high-overlap pair must share a prefix token under a global token order.
        prefix_size = len(left) - (NEAR_PERCENT * len(left) + 99) // 100 + 1
        prefix = sorted(left, key=lambda token: (frequency[token], token))[:prefix_size]
        candidates = {j for token in prefix for j in index[token]}
        for token in prefix:
            index[token].append(i)
        for j in sorted(candidates):
            right = shingles[j]
            if min(len(left), len(right)) * 100 < NEAR_PERCENT * max(len(left), len(right)):
                continue
            intersection = len(left & right)
            union = len(left) + len(right) - intersection
            if union and intersection * 100 >= NEAR_PERCENT * union:
                yield i, j


def deduplicate(
    candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_text: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sorted(candidates, key=lambda row: row["id"]):
        by_text[normalize_java(row["code"])].append(row)
    texts = sorted(by_text)
    parent = list(range(len(texts)))

    def root(i: int) -> int:
        while i != parent[i]:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i, j in similar_pairs(texts):
        parent[root(i)] = root(j)
    clusters: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for i, normalized in enumerate(texts):
        clusters[root(i)].extend(by_text[normalized])

    kept, audit = [], []
    for cluster in clusters.values():
        cluster.sort(key=lambda row: row["id"])
        cluster_id = sha256("\n".join(row["id"] for row in cluster).encode())
        winner = cluster[0] if len({row["label"] for row in cluster}) == 1 else None
        if winner is not None:
            kept.append({**winner, "duplicate_cluster": cluster_id})
        audit.append(
            {
                "cluster_id": cluster_id,
                "kept_id": winner["id"] if winner else None,
                "members": [{k: v for k, v in row.items() if k != "code"} for row in cluster],
            }
        )
    return kept, audit


def partition(rows: list[dict[str, Any]], seed: int) -> dict[str, Split]:
    families = sorted(
        {row["input_source_family"] for row in rows},
        key=lambda family: (sha256(f"{seed}:{family}".encode()), family),
    )
    if len(families) < 5:
        raise ValueError("Too few distinct families remain after deduplication")
    tail = max(1, len(families) // 6)
    groups: dict[str, Split] = {}
    assignments: tuple[tuple[Split, list[str]], ...] = (
        ("train", families[: -2 * tail]),
        ("validation", families[-2 * tail : -tail]),
        ("test", families[-tail:]),
    )
    for split, names in assignments:
        if {row["label"] for row in rows if row["input_source_family"] in names} != {0, 1}:
            raise ValueError(f"{split} lacks one label after family partitioning")
        for name in names:
            groups[name] = split
    return groups


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()


def prepare_juliet(archive: Path, output: Path, seed: int) -> dict[str, Any]:
    lock = load_source_lock()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output directory must be new")
    with tempfile.TemporaryDirectory(prefix=".juliet-prepare-", dir=output.parent) as temporary:
        work = Path(temporary)
        extract_java_cwe89(archive, work / "extracted", lock)
        candidates, diagnostics = extract_examples(work / "extracted")
        kept, audit = deduplicate(candidates)
        groups = partition(kept, seed)
        rows = []
        for row in sorted(kept, key=lambda row: row["id"]):
            basic = {"id", "code", "label", "repository_id", "content_sha256", "duplicate_cluster"}
            provenance = {key: value for key, value in row.items() if key not in basic}
            family = provenance["input_source_family"]
            rows.append(
                Example.model_validate(
                    {
                        **{key: row[key] for key in basic},
                        "group_id": family,
                        "split": groups[family],
                        "provenance": provenance,
                    }
                )
            )
        prepared = work / "dataset"
        prepared.mkdir()
        dataset = b"".join(json_bytes(row.model_dump(mode="json")) for row in rows)
        counts = Counter((row.split, str(row.label)) for row in rows)
        summary = {
            "archive_sha256": lock.sha256,
            "source_lock": lock.model_dump(mode="json"),
            "tree_sitter_java": version("tree-sitter-java"),
            "tree_sitter": version("tree-sitter"),
            "normalization": NORMALIZATION,
            "near_duplicate_policy": {
                "shingle_width": SHINGLE_WIDTH,
                "jaccard_percent": NEAR_PERCENT,
            },
            "partition_seed": seed,
            "families": groups,
            "counts": {
                p: {label: counts[p, label] for label in ("0", "1")}
                for p in ("train", "validation", "test")
            },
            "candidates": len(candidates),
            "kept": len(rows),
            "skipped": dict(Counter(item["code"] for item in diagnostics)),
            "deduplication_sha256": sha256(json_bytes(audit)),
            "diagnostics_sha256": sha256(json_bytes(diagnostics)),
            "preparation_code_sha256": {
                name: sha256(Path(__file__).with_name(name).read_bytes())
                for name in ("acquisition.py", "juliet.py", "features.py", "preparation.py")
            },
        }
        manifest = Manifest.model_validate_json(
            json_bytes(
                {
                    "schema_version": "1.0.0",
                    "dataset_id": lock.dataset_id,
                    "source_url": lock.archive_url,
                    "upstream_revision": lock.version,
                    "acquired_at": lock.reviewed_at,
                    "license": lock.license,
                    "attribution": "NIST SARD Juliet Java 1.3",
                    "label_provenance": "Case conventions checked against NIST flaw lines.",
                    "corpus_kind": "synthetic",
                    "language": "java",
                    "cwe": "CWE-89",
                    "dataset_sha256": sha256(dataset),
                    "record_count": len(rows),
                    "preprocessing": NORMALIZATION,
                    "preparation_sha256": sha256(json_bytes(summary)),
                }
            )
        )
        (prepared / "records.jsonl").write_bytes(dataset)
        (prepared / "manifest.json").write_bytes(json_bytes(manifest.model_dump(mode="json")))
        (prepared / "preparation.json").write_bytes(json_bytes(summary))
        (prepared / "deduplication.json").write_bytes(json_bytes(audit))
        (prepared / "diagnostics.json").write_bytes(json_bytes(diagnostics))
        load_dataset(prepared / "manifest.json", prepared / "records.jsonl")
        prepared.rename(output)
    return summary
