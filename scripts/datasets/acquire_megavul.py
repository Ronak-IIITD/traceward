"""Acquire a pinned, local research subset of CVE-linked Java functions.

Run with uv run --no-project --with pyarrow==26.0.1 python scripts/datasets/acquire_megavul.py.
No dataset source code is executed. Labels remain the upstream mined labels.
"""

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from urllib.request import urlopen

REVISION = "38ccb0e531503c682b7e0eab7e8e73897e3ce899"
MIRROR = "https://huggingface.co/datasets/athrv/megavul-vulnerability-detection-java"
EXPECTED_DIGESTS = {
    "train": "3ca0dc6da75ea7569ccdaef8b37504a1b6175389f648c083afe562bba4d03194",
    "validation": "4a7651e4f5643280406f3539e0e0b5162d05bba1d8c640fe8b3676ddf2fdffeb",
    "test": "ad84e6b2cab3dfccbba966ee188a8ad23c320e5ebd5ba3f22fefdd53d0172c0e",
}
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024
MAX_FUNCTION_BYTES = 64 * 1024


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def acquire(cache: Path, split: str) -> Path:
    target = cache / f"{split}.parquet"
    if target.exists():
        if target.stat().st_size > MAX_DOWNLOAD_BYTES:
            raise ValueError("Cached source exceeds the download cap")
        data = target.read_bytes()
    else:
        url = f"{MIRROR}/resolve/{REVISION}/data/{split}-00000-of-00001.parquet"
        with urlopen(url, timeout=60) as response:
            data = response.read(MAX_DOWNLOAD_BYTES + 1)
        if len(data) > MAX_DOWNLOAD_BYTES:
            raise ValueError("Source exceeds the download cap")
    if digest(data) != EXPECTED_DIGESTS[split]:
        raise ValueError(f"Source integrity check failed for {split}")
    target.write_bytes(data)
    return target


def records_from_rows(rows: list[dict], sources: dict) -> tuple[list[dict], list[dict], Counter]:
    records = []
    provenance = []
    excluded = Counter()
    fingerprints = set()
    labels_by_content = defaultdict(set)
    for row in rows:
        normalized = re.sub(r"\s+", "", row["input"])
        labels_by_content[digest(normalized.encode())].add(row["is_vulnerable"])
    for row in rows:
        if "CWE-89" not in row["cwe_ids"]:
            continue
        repo = sources["repositories"].get(row["repo_name"])
        if repo is None:
            excluded["repository_license_or_identity_unresolved"] += 1
            continue
        code = row["input"]
        path = row["file_path"].lower()
        if re.search(r"(^|/)(tests?|testing)(/|$)", path) or re.search(r"@(Test|Ignore)\b", code):
            excluded["test_code"] += 1
            continue
        if (
            not path.endswith(".java")
            or not code.strip()
            or len(code.encode()) > MAX_FUNCTION_BYTES
        ):
            excluded["unsupported_or_oversized_function"] += 1
            continue
        normalized = re.sub(r"\s+", "", code)
        normalized_digest = digest(normalized.encode())
        if len(labels_by_content[normalized_digest]) > 1:
            excluded["conflicting_duplicate_labels"] += 1
            continue
        if normalized_digest in fingerprints:
            excluded["whitespace_equivalent_duplicate"] += 1
            continue
        fingerprints.add(normalized_digest)
        repository = repo["repository"]
        commit = sources["commits"].get(f"{repository}@{row['commit_hash']}")
        if not commit or "sha" not in commit:
            excluded["unverified_commit"] += 1
            continue
        group = "xm-online-family" if repository.startswith("xm-online/") else repository
        identifier = digest(
            (
                "megavul-java-cwe89\0"
                + repository
                + "\0"
                + row["commit_hash"]
                + "\0"
                + row["file_path"]
                + "\0"
                + normalized_digest
            ).encode()
        )
        record = {
            "id": identifier,
            "code": code,
            "label": row["is_vulnerable"],
            "group_id": group,
            "repository_id": repository,
            "content_sha256": digest(code.encode()),
        }
        records.append(record)
        provenance.append(
            {
                "id": identifier,
                "cve": row["cve_id"],
                "cwes": row["cwe_ids"],
                "repository": repository,
                "dataset_repository_name": row["repo_name"],
                "commit": commit["sha"],
                "parent_commits": commit["parents"],
                "dataset_commit": row["commit_hash"],
                "commit_url": f"https://github.com/{repository}/commit/{commit['sha']}",
                "file_path": row["file_path"],
                "function_name": row["func_name"],
                "repository_license_at_acquisition": repo["spdx_id"],
                "label": row["is_vulnerable"],
                "label_confidence": "upstream_automated_mining_not_independently_reviewed",
            }
        )
    repositories = sorted(
        {record["group_id"] for record in records},
        key=lambda repository: digest(("traceward-split-v1\0" + repository).encode()),
    )
    if len(repositories) < 6:
        raise ValueError("At least six repositories are required for this research split")
    train_end = int(len(repositories) * 0.6)
    validation_end = int(len(repositories) * 0.8)
    splits = {
        repo: "train" if index < train_end else "validation" if index < validation_end else "test"
        for index, repo in enumerate(repositories)
    }
    for record in records:
        record["split"] = splits[record["group_id"]]
    records.sort(key=lambda record: record["id"])
    provenance.sort(key=lambda item: item["id"])
    for split in ("train", "validation", "test"):
        if {record["label"] for record in records if record["split"] == split} != {0, 1}:
            raise ValueError(f"Both labels are required in {split}")
    return records, provenance, excluded


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/research/megavul-java-cwe89"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cache = args.output / "source-cache"
    cache.mkdir(exist_ok=True)
    sources = json.loads(Path(__file__).with_name("megavul-java-sources.json").read_text())
    import pyarrow.parquet as parquet

    rows = []
    for split in EXPECTED_DIGESTS:
        rows.extend(parquet.read_table(acquire(cache, split)).to_pylist())
    records, provenance, excluded = records_from_rows(rows, sources)
    content = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records
    ).encode("utf-8")
    manifest = {
        "schema_version": "1.0.0",
        "dataset_id": "megavul-java-cwe89-research-v1",
        "source_url": MIRROR,
        "upstream_revision": REVISION,
        "acquired_at": date.today().isoformat(),
        "license": "MegaVul GPL-3.0; original project licenses recorded in provenance.jsonl",
        "attribution": "Ni et al., MegaVul, MSR 2024; Hugging Face mirror by athrv",
        "label_provenance": "MegaVul CVE-linked automated changed-function mining. "
        "Positive and negative labels are inherited, not independently verified. "
        "Negative means dataset-labeled non-vulnerable, not certified safe.",
        "corpus_kind": "real_world",
        "language": "java",
        "cwe": "CWE-89",
        "dataset_sha256": digest(content),
        "record_count": len(records),
    }
    (args.output / "records.jsonl").write_bytes(content)
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output / "provenance.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in provenance)
    )
    summary = {
        "dataset_sha256": digest(content),
        "records": len(records),
        "repositories": len({record["repository_id"] for record in records}),
        "cves": len({item["cve"] for item in provenance}),
        "split_label_counts": dict(
            sorted(
                Counter(f"{record['split']}_label_{record['label']}" for record in records).items()
            )
        ),
        "excluded": dict(excluded),
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
